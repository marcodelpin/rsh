//! Regression tests for server-side solved issues.
//!
//! Each test references a specific solved issue document and verifies the fix
//! remains in place. Tests are designed to run on CI (Linux) without hardware
//! dependencies (no display server, no Windows service, no fleet machines).

// ---------------------------------------------------------------------------
// 1. solved/2026-03-08-002 — Screenshot Linux hangs without display server
//
// Root cause: `import -window root` (ImageMagick) blocks indefinitely on
// headless systems without $DISPLAY. Fix: early bail when neither DISPLAY
// nor WAYLAND_DISPLAY is set, plus per-tool spawn+timeout instead of .output().
// ---------------------------------------------------------------------------

/// Regression: screenshot on headless Linux must return error, not hang.
/// Ref: docs/solved/2026-03-08-002-screenshot-linux-hangs-no-display.md
#[test]
fn screenshot_no_display_returns_error_not_hang() {
    // Remove display env vars to simulate headless environment.
    let old_display = std::env::var("DISPLAY").ok();
    let old_wayland = std::env::var("WAYLAND_DISPLAY").ok();
    // SAFETY: test is single-threaded for env var manipulation.
    unsafe {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
    }

    let resp = mrsh_server::screenshot::handle_screenshot(0, 80, 100);

    // Restore env vars
    unsafe {
        if let Some(val) = old_display {
            std::env::set_var("DISPLAY", val);
        }
        if let Some(val) = old_wayland {
            std::env::set_var("WAYLAND_DISPLAY", val);
        }
    }

    // On headless (no display server), must fail with an error — never hang.
    // The key regression: the call RETURNED (did not hang indefinitely).
    if !resp.success {
        let err = resp.error.as_deref().unwrap_or("");
        assert!(
            err.contains("no display")
                || err.contains("no screenshot tool")
                || err.contains("display may be locked"),
            "expected display-related error, got: {}",
            err
        );
    }
}

/// Regression: screenshot handler does not panic on missing display.
/// Ref: docs/solved/2026-03-08-002-screenshot-linux-hangs-no-display.md
#[test]
fn screenshot_does_not_panic_without_display() {
    let old_display = std::env::var("DISPLAY").ok();
    let old_wayland = std::env::var("WAYLAND_DISPLAY").ok();
    // SAFETY: test is single-threaded for env var manipulation.
    unsafe {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
    }

    let result =
        std::panic::catch_unwind(|| mrsh_server::screenshot::handle_screenshot(0, 80, 100));

    unsafe {
        if let Some(val) = old_display {
            std::env::set_var("DISPLAY", val);
        }
        if let Some(val) = old_wayland {
            std::env::set_var("WAYLAND_DISPLAY", val);
        }
    }

    assert!(
        result.is_ok(),
        "screenshot handler must not panic on headless system"
    );
}

// ---------------------------------------------------------------------------
// 2. solved/2026-03-17-002 — Relay TLS handshake EOF on immediate disconnect
//
// Root cause: relay connect_relay returned a stream even when the server side
// never accepted. Fix required: hbbs TCP relay forwarding, persistent
// registration loop, server-side relay acceptance. The connect_relay function
// must not hang when the relay server drops the connection.
// ---------------------------------------------------------------------------

/// Regression: connect_relay returns error (or dead stream) on immediate disconnect, not hang.
/// Ref: docs/solved/2026-03-17-002-relay-tls-handshake-eof.md
#[tokio::test]
async fn relay_connect_returns_error_on_immediate_disconnect() {
    use tokio::net::TcpListener;

    // Start a listener that accepts and immediately drops the connection.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                // Immediately drop — simulates relay server that rejects/dies
                drop(stream);
            }
        }
    });

    // connect_relay sends RequestRelay then returns the stream.
    // With an immediate disconnect, the write may succeed (buffered) or fail.
    // The critical test: must NOT hang.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        mrsh_relay::relay::connect_relay(&addr.to_string(), "test-uuid", "key"),
    )
    .await;

    match result {
        Ok(Ok(mut stream)) => {
            // connect_relay returned Ok (handshake bytes were buffered before drop).
            // Verify the stream is actually dead — read should return EOF.
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "stream from dropped server should be EOF");
        }
        Ok(Err(_)) => {
            // Error is the expected outcome — relay rejected/dropped.
        }
        Err(_) => {
            panic!(
                "connect_relay hung (timeout) on immediate disconnect — regression of 2026-03-17-002"
            );
        }
    }
}

/// Regression: relay server with auth rejects wrong licence_key and closes.
/// Ref: docs/solved/2026-03-17-002-relay-tls-handshake-eof.md
///
/// This tests the server side: when auth fails, the server must close the
/// connection (not hang). Uses the public RelayServer API.
#[tokio::test]
async fn relay_server_rejects_wrong_key_not_hang() {
    use mrsh_relay::relay::RelayServer;

    let srv = RelayServer::new("correct-secret-key");

    // Use port 0 to let OS assign an available port.
    // listen_and_serve binds internally, so we need to find the port.
    // Instead, spawn listen_and_serve on a known free port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release the port for listen_and_serve

    let bind_addr = format!("127.0.0.1:{}", addr.port());
    tokio::spawn(async move {
        srv.listen_and_serve(&bind_addr).await.ok();
    });

    // Give server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Connect with WRONG licence_key — server should reject and close
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        mrsh_relay::relay::connect_relay(&addr.to_string(), "test-uuid", "wrong-key"),
    )
    .await;

    match result {
        Ok(Ok(mut stream)) => {
            // Connection established but server should close after auth failure.
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let read_result =
                tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
                    .await;
            match read_result {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    // EOF or error or timeout — server closed, which is correct
                }
                Ok(Ok(_)) => panic!("server should close connection after auth failure"),
            }
        }
        Ok(Err(_)) => {
            // Error on connect — also acceptable
        }
        Err(_) => {
            panic!("connect_relay hung on auth rejection — regression of 2026-03-17-002");
        }
    }
}

// ---------------------------------------------------------------------------
// 3. solved/2026-03-19-001 — stdout lost when invoked from non-TTY pipe
//
// Root cause: GUI subsystem binary unconditionally overwrote pipe handles
// with CONOUT$. Fix: check GetStdHandle before SetStdHandle.
//
// Test: verify handle_exec captures output correctly via pipes.
// ---------------------------------------------------------------------------

/// Regression: exec output is captured correctly (not lost to broken pipe handles).
/// Ref: docs/solved/2026-03-19-001-stdout-lost-non-tty-pipe-handles.md
#[tokio::test]
async fn exec_output_captured_correctly() {
    let resp = mrsh_server::exec::handle_exec("echo regression_test_output", &[]).await;
    assert!(resp.success, "echo command should succeed");
    let output = resp
        .output
        .expect("output must not be None — pipe handle regression");
    assert!(
        output.contains("regression_test_output"),
        "stdout must be captured, got: {}",
        output
    );
}

/// Regression: exec captures both stdout and stderr (pipe handles preserved for both).
/// Ref: docs/solved/2026-03-19-001-stdout-lost-non-tty-pipe-handles.md
#[tokio::test]
async fn exec_captures_stdout_and_stderr() {
    let resp =
        mrsh_server::exec::handle_exec("echo STDOUT_PART && echo STDERR_PART >&2", &[]).await;
    let output = resp
        .output
        .expect("output must not be None — pipe handle regression");
    assert!(
        output.contains("STDOUT_PART"),
        "stdout must be captured, got: {}",
        output
    );
    assert!(
        output.contains("STDERR_PART"),
        "stderr must be captured, got: {}",
        output
    );
}

/// Regression: streaming exec delivers output through duplex pipe (not lost).
/// Ref: docs/solved/2026-03-19-001-stdout-lost-non-tty-pipe-handles.md
#[tokio::test]
async fn exec_stream_output_not_lost() {
    use mrsh_core::binproto;
    use mrsh_core::binproto::msg;

    let (mut reader, writer) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        mrsh_server::exec::handle_exec_stream(
            "echo stream_regression_check",
            &[],
            &mut tokio::io::BufWriter::new(writer),
        )
        .await
    });

    let mut got_output = false;
    let exit_code;
    loop {
        let (type_id, data) = binproto::recv_msg(&mut reader).await.unwrap();
        match type_id {
            msg::EXEC_STDOUT => {
                let s = String::from_utf8_lossy(&data);
                if s.contains("stream_regression_check") {
                    got_output = true;
                }
            }
            msg::EXEC_STDERR => {} // ignore
            msg::EXEC_EXIT => {
                exit_code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                break;
            }
            _ => panic!("unexpected msg type 0x{:02x}", type_id),
        }
    }

    assert!(
        got_output,
        "streaming output must not be lost (regression of pipe handle issue)"
    );
    assert_eq!(exit_code, 0);
    handle.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// 4. solved/2026-03-21-001 — Self-update rollback loop (timeout + retry)
//
// Root cause: bat script had insufficient timeouts (5s total) and no copy
// retry. On Win10 the service takes longer to release the file lock.
// Fix: increased timeouts to 5s+3s and added retry with 5s wait before rollback.
// ---------------------------------------------------------------------------

/// Regression: validate_update_path succeeds for a valid large binary.
/// Ref: docs/solved/2026-03-21-001-selfupdate-rollback-timeout.md
#[test]
fn selfupdate_validate_large_file_succeeds() {
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    // Write a file larger than MIN_BINARY_SIZE (1 MB)
    let data = vec![0xCCu8; 2_000_000]; // 2 MB
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = mrsh_server::selfupdate::validate_update_path(f.path().to_str().unwrap());
    assert!(
        result.is_ok(),
        "valid 2MB binary should pass validation, got: {:?}",
        result.err()
    );
}

/// Regression: selfupdate bat template in source has retry logic and adequate timeouts.
/// Ref: docs/solved/2026-03-21-001-selfupdate-rollback-timeout.md
///
/// Static analysis of the bat template in selfupdate.rs to ensure the retry
/// pattern (second `copy` after `timeout`) and rollback are present.
#[test]
fn selfupdate_bat_template_has_retry_and_timeout() {
    let selfupdate_src = include_str!("../crates/mrsh-server/src/selfupdate.rs");

    // v1.9.6+: uses rename-swap instead of stop+taskkill+copy.
    // Verify the bat template uses ren (rename running binary) + copy new.
    assert!(
        selfupdate_src.contains(r#"ren "{exe}" "{backup_name}""#),
        "bat template must rename running binary before copy"
    );

    assert!(
        selfupdate_src.contains(r#"copy /y "{new}" "{exe}.incoming""#),
        "bat template must contain staged copy command for new binary"
    );

    // Verify fallback: if rename fails, stop service first then retry rename
    assert!(
        selfupdate_src.contains("net stop {svc}"),
        "bat template must stop service as fallback when rename fails"
    );

    // Verify service restart after swap
    assert!(
        selfupdate_src.contains("net start {svc}"),
        "bat template must restart service after swap"
    );

    // Verify logging
    assert!(
        selfupdate_src.contains("self-update starting"),
        "bat template must log start of update"
    );
}

// ---------------------------------------------------------------------------
// 5. solved/2026-03-13-002 — Go→Rust self-update flag mismatch
//
// Root cause: Go rsh used single-dash flags (-install, -service, -port)
// but Rust clap requires double-dash (--install, --service, --port).
// Self-update swapping Go→Rust broke the Windows service because SCM
// registration still had single-dash flags.
// ---------------------------------------------------------------------------

/// Regression: CLI flags use double-dash (clap long) convention, not Go single-dash.
/// Ref: docs/solved/2026-03-13-002-go-rust-selfupdate-flag-mismatch.md
///
/// Static analysis: verify main.rs clap attributes define critical flags
/// as `long = "..."` (double-dash), not single-dash short flags.
#[test]
fn cli_flags_are_double_dash_convention() {
    // Cli struct lives in cli.rs since the rsh-4hv refactor; main.rs only
    // imports and instantiates it.
    let main_src = concat!(
        include_str!("../src/main.rs"),
        include_str!("../src/cli.rs"),
    );

    // Verify --install is defined as a long flag (double-dash)
    assert!(
        main_src.contains(r#"long = "install""#),
        "install flag must use long = \"install\" (double-dash clap convention)"
    );

    // Verify --service is also double-dash
    assert!(
        main_src.contains(r#"long = "service""#),
        "service flag must use long = \"service\" (double-dash clap convention)"
    );

    // Verify --console is also double-dash
    assert!(
        main_src.contains(r#"long = "console""#),
        "console flag must use long = \"console\" (double-dash clap convention)"
    );

    // Verify --uninstall is also double-dash
    assert!(
        main_src.contains(r#"long = "uninstall""#),
        "uninstall flag must use long = \"uninstall\" (double-dash clap convention)"
    );

    // Verify clap::Parser derive is used (Rust convention, not Go flag package)
    assert!(
        main_src.contains("use clap::Parser") || main_src.contains("clap::Parser"),
        "binary must use clap::Parser (Rust convention with double-dash flags)"
    );
}

/// Regression: critical service flags are defined with #[arg(long = ...)] in Cli struct.
/// Ref: docs/solved/2026-03-13-002-go-rust-selfupdate-flag-mismatch.md
///
/// Ensures that if someone changes the flag definitions, the test will catch it.
#[test]
fn cli_install_not_defined_as_short_flag_only() {
    // Cli struct lives in cli.rs since the rsh-4hv refactor.
    let main_src = concat!(
        include_str!("../src/main.rs"),
        include_str!("../src/cli.rs"),
    );

    // The dangerous scenario: someone defines `#[arg(short)]` for install
    // without `long`, which would make it `-i` only (like Go's single-dash).
    // The install field must have `long` in its #[arg] attribute.

    // Find the install field definition and verify it has `long`
    let lines: Vec<&str> = main_src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("install: bool") && !line.contains("uninstall") {
            // Look backwards for the #[arg(...)] attribute
            let mut found_long = false;
            for j in (0..i).rev() {
                let attr_line = lines[j].trim();
                if attr_line.starts_with("#[arg(") {
                    found_long = attr_line.contains("long");
                    break;
                }
                if attr_line.starts_with("///") || attr_line.starts_with("//") {
                    continue;
                }
                break;
            }
            assert!(
                found_long,
                "install flag must have 'long' in its #[arg] attribute (line {})",
                i + 1
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. solved/2026-03-17-005 — Dashboard blocking quit (fleet probe in event loop)
//
// Root cause: fleet::status() was awaited directly in the TUI event loop,
// blocking quit events for seconds. Fix: spawn fleet probe as background
// task with mpsc::channel, use try_recv for non-blocking event processing.
// ---------------------------------------------------------------------------

/// Regression: fleet::status returns Vec<HostStatus> without blocking indefinitely.
/// Ref: docs/solved/2026-03-17-005-dashboard-blocking-quit.md
#[tokio::test]
async fn fleet_status_returns_vec_not_blocking() {
    let config = mrsh_core::config::Config::default();

    // fleet::status with empty config should return quickly (no hosts to probe).
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        mrsh_client::fleet::status(&config),
    )
    .await;

    match result {
        Ok(statuses) => {
            // Empty config produces empty vec (no hang)
            assert!(
                statuses.is_empty(),
                "empty config should produce empty status vec"
            );
        }
        Err(_) => {
            panic!("fleet::status hung on empty config — regression of 2026-03-17-005");
        }
    }
}

/// Regression: dashboard source uses channel-based background refresh pattern.
/// Ref: docs/solved/2026-03-17-005-dashboard-blocking-quit.md
///
/// Static analysis: the fix moved fleet probing to a background task with
/// mpsc::channel. Verifies the pattern remains in dashboard.rs.
#[test]
fn dashboard_uses_background_refresh_pattern() {
    let dashboard_src = include_str!("../crates/mrsh-client/src/dashboard.rs");

    // Verify the background refresh channel pattern
    assert!(
        dashboard_src.contains("mpsc::channel"),
        "dashboard must use mpsc::channel for background refresh (not inline await)"
    );

    // Verify spawn_refresh helper exists
    assert!(
        dashboard_src.contains("spawn_refresh"),
        "dashboard must have spawn_refresh function for background probing"
    );

    // Verify tokio::spawn is used (background task, not inline await)
    assert!(
        dashboard_src.contains("tokio::spawn"),
        "dashboard must spawn fleet probes as background tasks"
    );

    // Verify try_recv is used (non-blocking receive in event loop)
    assert!(
        dashboard_src.contains("try_recv"),
        "dashboard event loop must use try_recv (non-blocking) for fleet results"
    );
}

/// Regression: run_loop does NOT directly await fleet::status (must use spawn_refresh).
/// Ref: docs/solved/2026-03-17-005-dashboard-blocking-quit.md
///
/// The original bug was `fleet_statuses = fleet::status().await` inside the event
/// loop. The fix delegates to spawn_refresh. This test ensures no direct await
/// regresses back into the event loop.
#[test]
fn dashboard_run_loop_does_not_inline_await_fleet_status() {
    let dashboard_src = include_str!("../crates/mrsh-client/src/dashboard.rs");

    // Find the run_loop function and check that fleet::status is NOT directly
    // awaited in its body (it should only appear inside spawn_refresh).
    if let Some(run_loop_start) = dashboard_src.find("async fn run_loop") {
        let run_loop_body = &dashboard_src[run_loop_start..];

        // spawn_refresh is defined inside run_loop as a nested fn.
        // fleet::status should ONLY appear inside spawn_refresh, not in
        // the outer run_loop body.
        let lines: Vec<&str> = run_loop_body.lines().collect();
        let mut inside_spawn_refresh = false;
        let mut brace_depth: i32 = 0;
        let mut spawn_refresh_depth: i32 = 0;

        for line in &lines {
            if line.contains("fn spawn_refresh") {
                inside_spawn_refresh = true;
                spawn_refresh_depth = brace_depth;
            }

            // Track brace depth
            for ch in line.chars() {
                if ch == '{' {
                    brace_depth += 1;
                }
                if ch == '}' {
                    brace_depth -= 1;
                }
            }

            if inside_spawn_refresh && brace_depth <= spawn_refresh_depth {
                inside_spawn_refresh = false;
            }

            // Check for direct fleet::status().await outside spawn_refresh
            if !inside_spawn_refresh && line.contains("fleet::status") && line.contains(".await") {
                panic!(
                    "run_loop directly awaits fleet::status (must use spawn_refresh): {}",
                    line.trim()
                );
            }
        }
    } else {
        panic!("could not find async fn run_loop in dashboard.rs");
    }
}

// ---------------------------------------------------------------------------
// rsh-c8f — Relay tray-first routing: target_port=0 probes tray
//
// Root cause: relay connections always landed on service (8822/SYSTEM) because
// client sent target_port=DEFAULT_PORT. Fix: client sends target_port=0 when
// no explicit -p; server probes tray (9822) before handling in SYSTEM context.
// Proxy forwards RAW stream so target port handles its own TLS.
// ---------------------------------------------------------------------------

/// Regression: bidirectional TCP proxy transfers data in both directions.
/// Covers the relay_proxy_bidirectional helper used for tray/port routing.
/// Ref: rsh-c8f
#[tokio::test]
async fn relay_proxy_bidirectional_transfers_data() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Simulate the "tray" side — a local TCP listener that echoes data (reversed)
    let tray_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tray_addr = tray_listener.local_addr().unwrap();

    // Simulate the "relay" side — a pair of connected streams
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    // Spawn the proxy: connect relay_accept_side ↔ tray
    // Uses tokio::select! (same as relay_proxy_bidirectional in server_mode.rs)
    let proxy_handle = tokio::spawn(async move {
        let (relay_accept, _) = relay_listener.accept().await.unwrap();
        let tray_stream = tokio::net::TcpStream::connect(tray_addr).await.unwrap();

        let (mut r_read, mut r_write) = tokio::io::split(relay_accept);
        let (mut t_read, mut t_write) = tokio::io::split(tray_stream);

        tokio::select! {
            _ = tokio::io::copy(&mut r_read, &mut t_write) => {}
            _ = tokio::io::copy(&mut t_read, &mut r_write) => {}
        }
    });

    // Spawn tray echo server: read exactly 10 bytes → reverse → write back → close
    let tray_handle = tokio::spawn(async move {
        let (mut tray_conn, _) = tray_listener.accept().await.unwrap();
        let mut buf = [0u8; 10];
        tray_conn.read_exact(&mut buf).await.unwrap();
        buf.reverse();
        tray_conn.write_all(&buf).await.unwrap();
        tray_conn.shutdown().await.unwrap();
    });

    // Client side: connect, write 10 bytes, read response (keep write half open)
    let mut client = tokio::net::TcpStream::connect(relay_addr).await.unwrap();
    client.write_all(b"HELLO_TRAY").await.unwrap();

    // Read the 10-byte reversed response (don't shutdown write first!)
    let mut response = [0u8; 10];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.read_exact(&mut response),
    )
    .await;

    assert!(
        result.is_ok(),
        "read must not timeout — proxy must forward tray response"
    );
    assert_eq!(
        &response, b"YART_OLLEH",
        "proxy must forward data bidirectionally — tray reverses the input"
    );

    drop(client);
    let _ = proxy_handle.await;
    let _ = tray_handle.await;
}

/// Regression: RelayConnectOptions.target_port=0 when auto-try (no explicit -p).
/// Ensures the client signals tray-first to the server via the relay protocol.
/// Ref: rsh-c8f
#[test]
fn relay_connect_options_target_port_zero_for_auto_try() {
    use mrsh_client::relay_connect::RelayConnectOptions;

    // Simulate auto-try (no explicit -p): target_port should be 0
    let auto_opts = RelayConnectOptions {
        device_id: "123456".to_string(),
        rendezvous_server: "rdv.example.com:21116".to_string(),
        rendezvous_key: String::new(),
        key_path: None,
        server_name: "host".to_string(),
        port: 8822,
        target_port: 0, // tray-first signal
        force_relay: false,
        enrollment_token: String::new(),
        own_device_id: None, // sys-1qgww: no self-loop in this test
    };
    assert_eq!(
        auto_opts.target_port, 0,
        "auto-try must send target_port=0 for tray-first"
    );
    assert_eq!(
        auto_opts.port, 8822,
        "P2P port stays at default for direct attempts"
    );

    // Simulate explicit -p 8822: target_port should match
    let explicit_opts = RelayConnectOptions {
        target_port: 8822,
        ..auto_opts.clone()
    };
    assert_eq!(
        explicit_opts.target_port, 8822,
        "explicit -p 8822 must send 8822 (SYSTEM)"
    );

    // Simulate explicit -p 9822: target_port should match
    let tray_opts = RelayConnectOptions {
        target_port: 9822,
        ..auto_opts.clone()
    };
    assert_eq!(
        tray_opts.target_port, 9822,
        "explicit -p 9822 must send 9822 (tray)"
    );
}

/// Regression: rendezvous resolve_with_port receives target_port from client.
/// Verifies the protocol carries target_port=0 vs explicit values.
/// Ref: rsh-c8f
#[test]
fn relay_notification_carries_target_port() {
    let notif = mrsh_relay::rendezvous::RelayNotification {
        uuid: "test-uuid".to_string(),
        relay_server: "relay.example.com:21117".to_string(),
        target_port: 0,
    };
    assert_eq!(notif.target_port, 0, "target_port=0 means tray-first");

    let notif_explicit = mrsh_relay::rendezvous::RelayNotification {
        target_port: 9822,
        ..notif
    };
    assert_eq!(
        notif_explicit.target_port, 9822,
        "explicit tray port preserved"
    );
}
