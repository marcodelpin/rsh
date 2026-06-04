//! ConPTY regression test for rsh-bqw: verifies child process starts successfully.
//! The original bug: child crashed with STATUS_DLL_INIT_FAILED (0xC0000142)
//! because HPCON was passed by pointer instead of by value to UpdateProcThreadAttribute.
#![cfg(windows)]

use std::io::Read;
use std::os::windows::io::FromRawHandle;
use std::time::Duration;

#[test]
fn conpty_child_starts_successfully() {
    unsafe {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Console::*;
        use windows::Win32::System::Pipes::CreatePipe;
        use windows::Win32::System::Threading::*;

        let mut pty_in_read = HANDLE::default();
        let mut pty_in_write = HANDLE::default();
        let mut pty_out_read = HANDLE::default();
        let mut pty_out_write = HANDLE::default();

        CreatePipe(&mut pty_in_read, &mut pty_in_write, None, 0).unwrap();
        CreatePipe(&mut pty_out_read, &mut pty_out_write, None, 0).unwrap();

        let size = COORD { X: 80, Y: 24 };
        let hpc = CreatePseudoConsole(size, pty_in_read, pty_out_write, 0).unwrap();
        CloseHandle(pty_in_read).ok();
        CloseHandle(pty_out_write).ok();

        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_size);
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_size).unwrap();

        const PSEUDOCONSOLE_ATTR: usize = 0x00020016;
        // FIX (rsh-bqw): pass HPCON handle VALUE via .0, not pointer to struct
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PSEUDOCONSOLE_ATTR,
            Some(hpc.0 as *const std::ffi::c_void),
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )
        .unwrap();

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;
        let mut pi = PROCESS_INFORMATION::default();

        let mut cmd: Vec<u16> = "cmd.exe /c echo hello\0".encode_utf16().collect();
        CreateProcessW(
            windows::core::PCWSTR::null(),
            Some(windows::core::PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            windows::core::PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )
        .unwrap();

        DeleteProcThreadAttributeList(attr_list);

        // Wait for child to finish (max 5s)
        WaitForSingleObject(pi.hProcess, 5000);
        let mut ec: u32 = 0;
        GetExitCodeProcess(pi.hProcess, &mut ec).ok();

        // Child must NOT crash with STATUS_DLL_INIT_FAILED
        assert_ne!(
            ec, 0xC0000142,
            "child crashed with STATUS_DLL_INIT_FAILED — HPCON passed incorrectly"
        );
        assert_eq!(ec, 0, "child exited with unexpected code: 0x{:08x}", ec);

        // Verify pipe produces data (ConPTY output)
        let out_file = std::fs::File::from_raw_handle(pty_out_read.0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut f = out_file;
            let mut buf = [0u8; 4096];
            match f.read(&mut buf) {
                Ok(n) if n > 0 => tx.send(n).ok(),
                _ => tx.send(0).ok(),
            };
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(n) => assert!(n > 0, "ConPTY pipe produced no data"),
            Err(_) => {
                // Close ConPTY to unblock reader
                ClosePseudoConsole(hpc);
                panic!("pipe read still blocked after child exited");
            }
        }

        ClosePseudoConsole(hpc);
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();
    }
}
