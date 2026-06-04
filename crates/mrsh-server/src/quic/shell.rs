//! Interactive shell channel: PTY (Linux) and ConPTY (Windows) implementations.

use anyhow::{Context, Result};
use mrsh_core::wire;
use tokio::io::BufReader;
use tracing::{debug, info};

use crate::shell;

use super::streams::parse_shell_target;

/// Interactive shell over QUIC stream (Linux PTY).
/// Channel header: `shell[\0{COLSxROWS}[\0env=KEY=VAL]*]\n`
/// Protocol:
///   Server → Client: `OK\n` (or `ERROR: ...\n`)
///   Bidirectional: wire-framed chunks (same as TLS shell)
///   Resize: 0x01 + cols(2BE) + rows(2BE) from client
///   EOF: empty frame from either side
/// Env forwarding: each `env=KEY=VAL` token after size adds one env var.
/// Unknown tokens are ignored for forward compat.
#[cfg(not(target_os = "windows"))]
pub(super) async fn handle_quic_shell(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    let (parsed_size, env_vars) = parse_shell_target(target);
    let size_str = if parsed_size.is_empty() {
        "80x24"
    } else {
        parsed_size.as_str()
    };
    let (cols, rows) = shell::parse_size(size_str);
    info!(
        "[QUIC] shell: {}x{} env_vars={}",
        cols,
        rows,
        env_vars.len()
    );

    // Create PTY pair
    let mut master_fd: libc::c_int = 0;
    let mut slave_fd: libc::c_int = 0;
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    } != 0
    {
        let msg = format!("ERROR: openpty: {}\n", std::io::Error::last_os_error());
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    // Use the same shell selection logic as the TLS handler for consistency.
    // Previously this was hardcoded to /bin/bash > /bin/sh, missing MRSH_SHELL support.
    let shell_bin = shell::choose_shell_unix(&env_vars);

    let saved_master = master_fd;
    let saved_slave = slave_fd;

    let mut cmd = tokio::process::Command::new(shell_bin);
    cmd.env("TERM", "xterm-256color");
    cmd.kill_on_drop(true);
    // Forward env vars from client (each in "KEY=VAL" form); matches TLS handler behavior.
    for e in &env_vars {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    // Match TLS handler + SSH: launch shell in $HOME, not daemon cwd. See rsh-lyi4.
    let home = env_vars
        .iter()
        .find_map(|e| e.strip_prefix("HOME=").map(str::to_string))
        .or_else(|| std::env::var("HOME").ok());
    if let Some(h) = &home {
        if !h.is_empty() && std::path::Path::new(h).exists() {
            cmd.current_dir(h);
        }
    }
    unsafe {
        cmd.pre_exec(move || {
            libc::close(saved_master);
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // TIOCSCTTY ioctl request type differs between C library impls:
            // glibc/macOS = c_ulong, musl = c_int. Same gate as TLS handler.
            #[cfg(target_env = "musl")]
            let tiocsctty = libc::TIOCSCTTY as libc::c_int;
            #[cfg(not(target_env = "musl"))]
            let tiocsctty = libc::TIOCSCTTY as libc::c_ulong;
            if libc::ioctl(saved_slave, tiocsctty, 0 as libc::c_int) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::dup2(saved_slave, 0);
            libc::dup2(saved_slave, 1);
            libc::dup2(saved_slave, 2);
            if saved_slave > 2 {
                libc::close(saved_slave);
            }
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(master_fd);
                libc::close(slave_fd);
            }
            let msg = format!("ERROR: spawn: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };
    let child_pid = child.id().unwrap_or(0) as libc::pid_t;
    let _child = child;

    // Close slave in parent (child holds its copy)
    unsafe {
        libc::close(slave_fd);
    }

    // Dup master for separate read and write ownership
    let master_write_fd = unsafe { libc::dup(master_fd) };
    if master_write_fd < 0 {
        unsafe {
            libc::close(master_fd);
        }
        anyhow::bail!("dup(master): {}", std::io::Error::last_os_error());
    }

    // Signal OK to client before entering relay loop
    send.write_all(b"OK\n").await.context("send OK")?;

    // Spawn blocking reader thread: PTY master → mpsc channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EIO) {
                        break; // slave closed (child exited) — normal
                    }
                    debug!("[QUIC] shell: PTY read: {}", e);
                    break;
                }
            }
        }
    });

    let mut master_write = unsafe { std::fs::File::from_raw_fd(master_write_fd) };

    // Bidirectional relay loop
    loop {
        tokio::select! {
            // Client → PTY
            result = wire::recv_message(reader) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        debug!("[QUIC] shell: client EOF");
                        break;
                    }
                    Ok(data) => {
                        if let Some((c, r)) = shell::parse_resize(&data) {
                            let new_ws = libc::winsize {
                                ws_row: r,
                                ws_col: c,
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            unsafe {
                                libc::ioctl(master_write_fd, libc::TIOCSWINSZ, &new_ws);
                                if child_pid > 0 {
                                    libc::kill(-child_pid, libc::SIGWINCH);
                                }
                            }
                            continue;
                        }
                        use std::io::Write;
                        if master_write.write_all(&data).is_err()
                            || master_write.flush().is_err()
                        {
                            debug!("[QUIC] shell: PTY write failed");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("[QUIC] shell: client disconnected");
                        break;
                    }
                }
            }
            // PTY → Client
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(send, &data).await.is_err() {
                            debug!("[QUIC] shell: send failed");
                            break;
                        }
                    }
                    None => {
                        debug!("[QUIC] shell: process exited");
                        break;
                    }
                }
            }
        }
    }

    drop(master_write);
    reader_task.abort();
    wire::send_message(send, &[]).await.ok();
    info!("[QUIC] shell: session ended");
    Ok(())
}

/// Interactive shell over QUIC stream (Windows ConPTY).
///
/// Channel header: `shell[\0{COLSxROWS}[\0env=KEY=VAL]*]\n`
/// Env forwarding: each `env=KEY=VAL` token after size adds one env var.
/// Windows env block is built via `shell::build_windows_env_block`, matching
/// the TLS Windows handler (inherited env merged with `env_vars`).
#[cfg(target_os = "windows")]
pub(super) async fn handle_quic_shell(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use windows::core::BOOL;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
        STARTF_USESTDHANDLES,
    };

    let (parsed_size, env_vars) = parse_shell_target(target);
    let size_str = if parsed_size.is_empty() {
        "80x24"
    } else {
        parsed_size.as_str()
    };
    let (cols, rows) = shell::parse_size(size_str);
    info!(
        "[QUIC] shell (ConPTY): {}x{} env_vars={}",
        cols,
        rows,
        env_vars.len()
    );

    let (pty_in_write, pty_out_read, hpc, shell_pid, proc_raw, thread_raw) = unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: BOOL::from(true),
        };
        let mut pty_in_read = HANDLE::default();
        let mut pty_in_write = HANDLE::default();
        let mut pty_out_read = HANDLE::default();
        let mut pty_out_write = HANDLE::default();

        CreatePipe(&mut pty_in_read, &mut pty_in_write, Some(&sa as *const _), 0)
            .context("CreatePipe input")?;
        CreatePipe(&mut pty_out_read, &mut pty_out_write, Some(&sa as *const _), 0)
            .context("CreatePipe output")?;

        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        let hpc = CreatePseudoConsole(size, pty_in_read, pty_out_write, 0)
            .context("CreatePseudoConsole")?;

        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_size);
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_size)
            .context("InitializeProcThreadAttributeList")?;

        const PSEUDOCONSOLE_ATTR: usize = 0x00020016;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PSEUDOCONSOLE_ATTR,
            // Pass handle value as pointer (matches TLS path, Windows API convention)
            Some(hpc.0 as *const std::ffi::c_void),
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )
        .context("UpdateProcThreadAttribute")?;

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = pty_in_read;
        si.StartupInfo.hStdOutput = pty_out_write;
        si.StartupInfo.hStdError = pty_out_write;
        si.lpAttributeList = attr_list;
        let mut pi = PROCESS_INFORMATION::default();
        // Use the same shell selection as TLS handler (pwsh > powershell > cmd).
        // Previously hardcoded to "powershell.exe", missing pwsh.exe preference.
        let shell_exe = shell::choose_shell_windows(&env_vars);
        let mut cmd: Vec<u16> = format!("{}\0", shell_exe).encode_utf16().collect();

        // Build UTF-16 env block merging inherited env + extras (matches TLS handler).
        // Empty env_vars → None → child inherits server's env unmodified.
        let env_block = shell::build_windows_env_block(&env_vars);
        let env_ptr = env_block
            .as_ref()
            .map(|b| b.as_ptr() as *const std::ffi::c_void);
        let create_flags = EXTENDED_STARTUPINFO_PRESENT
            | CREATE_NO_WINDOW
            | if env_ptr.is_some() {
                windows::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT
            } else {
                windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0)
            };

        CreateProcessW(
            windows::core::PCWSTR::null(),
            Some(windows::core::PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            true,
            create_flags,
            env_ptr,
            windows::core::PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )
        .context("CreateProcessW")?;

        let _ = CloseHandle(pty_in_read);
        let _ = CloseHandle(pty_out_write);
        DeleteProcThreadAttributeList(attr_list);
        let shell_pid = pi.dwProcessId;
        let proc_raw = pi.hProcess.0 as usize;
        let thread_raw = pi.hThread.0 as usize;
        (pty_in_write, pty_out_read, hpc, shell_pid, proc_raw, thread_raw)
    };

    use std::os::windows::io::FromRawHandle;
    let out_file = unsafe { std::fs::File::from_raw_handle(pty_out_read.0) };
    let mut in_file = Some(unsafe { std::fs::File::from_raw_handle(pty_in_write.0) });

    send.write_all(b"OK\n").await.context("send OK")?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = out_file;
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let (proc_exit_tx, mut proc_exit_rx) = tokio::sync::mpsc::channel::<()>(1);
    let proc_wait_task = tokio::task::spawn_blocking(move || {
        let proc_handle = HANDLE(proc_raw as *mut std::ffi::c_void);
        let _ = unsafe { WaitForSingleObject(proc_handle, u32::MAX) };
        let _ = proc_exit_tx.blocking_send(());
    });

    let mut conpty_closed = false;

    loop {
        tokio::select! {
            result = wire::recv_message(reader) => {
                match result {
                    Ok(data) if data.is_empty() => break,
                    Ok(data) => {
                        if let Some((c, r)) = shell::parse_resize(&data) {
                            unsafe {
                                let sz = COORD { X: c as i16, Y: r as i16 };
                                let _ = ResizePseudoConsole(hpc, sz);
                            }
                            continue;
                        }
                        let Some(in_file) = in_file.as_mut() else {
                            break;
                        };
                        if let Err(err) = shell::write_windows_shell_input(in_file, shell_pid, &data) {
                            debug!("[QUIC] shell: input pipe broken: {:#}", err);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            proc_exit = proc_exit_rx.recv(), if !conpty_closed => {
                if proc_exit.is_some() {
                    unsafe {
                        ClosePseudoConsole(hpc);
                    }
                    conpty_closed = true;
                    let _ = in_file.take();
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(send, &data).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    if !conpty_closed {
        unsafe {
            ClosePseudoConsole(hpc);
        }
    }
    let _ = in_file.take();
    reader_task.abort();
    proc_wait_task.abort();
    unsafe {
        let _ = CloseHandle(HANDLE(proc_raw as *mut std::ffi::c_void));
        let _ = CloseHandle(HANDLE(thread_raw as *mut std::ffi::c_void));
    }
    wire::send_message(send, &[]).await.ok();
    info!("[QUIC] shell: ConPTY session ended");
    Ok(())
}
