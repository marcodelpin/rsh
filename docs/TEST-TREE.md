# Test Tree — mrsh

Generated: 2026-03-24 | Version: v1.5.1

## Summary

- Total source files: 61 (.rs)
- Total LOC: ~39,900
- Test functions: 720 (on default features)
- Feature-gated tests: quic (~20), ssh (~9) — require `--features quic,ssh`
- Crates tested: 5/5 + root binary (all have tests)
- All tests passing: YES
- Modules with HIGH coverage: 38 | PARTIAL: 15 | NONE: 0
- Regression coverage: 17/26 solved issues (65%)
- Critical gaps: 0 (all P0 core logic fully covered)

## Coverage Matrix

### mrsh-core (109 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| auth.rs | 987 | 21 | HIGH | Key loading, signatures, TOTP, revocation |
| binproto.rs | 625 | 21 | HIGH | Encode/decode, streaming exec protocol |
| config.rs | 614 | 17 | HIGH | Config load/parse, host entries |
| protocol.rs | 417 | 18 | HIGH | Serde roundtrips, all request/response types |
| tls.rs | 628 | 12 | HIGH | Cert generation, client/server configs |
| wire.rs | 266 | 8 | HIGH | Compressed JSON, big-endian format |
| path.rs | 133 | 12 | HIGH | Normalization, exec command passthrough |

### mrsh-transfer (25 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| blockcache.rs | 537 | 11 | HIGH | Cache ops, cleanup, file info |
| chunking.rs | 256 | 7 | HIGH | Rabin chunking, hash, boundaries |
| delta.rs | 267 | 7 | HIGH | Signatures, delta compute/apply |

### mrsh-relay (67 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| rendezvous.rs | 2,274 | 39 | HIGH | Server, client, AddrMangle, groups |
| relay.rs | 613 | 10 | HIGH | Relay server, connect, limits |
| codec.rs | 193 | 10 | HIGH | Frame encode/decode |
| stun.rs | 266 | 4 | HIGH | NAT detection |
| discovery.rs | 250 | 4 | HIGH | LAN discovery |

### mrsh-client (259 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| sync.rs | 1,745 | 39 | HIGH | Push/pull file/dir, delta, chunked |
| commands.rs | 962 | 35 | HIGH | All remote commands |
| session_log.rs | 633 | 26 | HIGH | Logging, tracking |
| client.rs | 943 | 21 | HIGH | Connect, IPv6 parsing, TLS wrap |
| config_tui.rs | 1,230 | 20 | HIGH | Config editor TUI |
| fleet.rs | 966 | 18 | HIGH | Status, update, group token |
| shell.rs | 536 | 13 | HIGH | Shell, attach, WoL |
| tunnel.rs | 908 | 12 | HIGH | Parse spec, run tunnel |
| install_pack.rs | 949 | 11 | HIGH | NSIS generator |
| browse.rs | 409 | 10 | HIGH | Browser integration |
| host_picker.rs | 461 | 10 | HIGH | Host selection TUI |
| sftp.rs | 451 | 9 | HIGH | SFTP protocol |
| dashboard.rs | 694 | 8 | HIGH | Dashboard TUI |
| mux.rs | 514 | 8 | HIGH | Connection multiplexing |
| socks.rs | 593 | 6 | PARTIAL | SOCKS5 proxy |
| recording.rs | 221 | 4 | PARTIAL | Asciicast export |
| relay_connect.rs | 207 | 4 | PARTIAL | Relay connection |
| log_viewer.rs | 501 | 3 | PARTIAL | Log viewer TUI |
| ssh_client.rs | 244 | 1 | PARTIAL | Feature-gated |
| quic.rs | 347 | 1 | PARTIAL | Feature-gated |

### mrsh-server (244 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| dispatch.rs | 605 | 23 | HIGH | Request routing |
| sync.rs | 1,910 | 23 | HIGH | Delta, chunked, path sanitize |
| quic.rs | 1,939 | 19 | PARTIAL | Feature-gated |
| listener.rs | 1,081 | 19 | HIGH | Dual-stack bind, ACL, TLS detect |
| tunnel.rs | 351 | 18 | HIGH | Server tunnel |
| handler.rs | 1,225 | 16 | HIGH | Binary protocol dispatch |
| mux.rs | 899 | 14 | HIGH | Server mux |
| fileops.rs | 330 | 12 | HIGH | File operations |
| ssh.rs | 889 | 9 | HIGH | Feature-gated |
| safety.rs | 146 | 8 | HIGH | Exec safety checks |
| notify.rs | 153 | 8 | HIGH | Broadcast notifications |
| shell.rs | 565 | 8 | HIGH | Server shell (ConPTY) |
| exec.rs | 351 | 8 | HIGH | Buffered + streaming exec |
| tray.rs | 456 | 8 | PARTIAL | Windows-only |
| service.rs | 514 | 7 | HIGH | Install, detect, tray task |
| session.rs | 331 | 7 | HIGH | Session management |
| gui.rs | 418 | 6 | PARTIAL | Windows-only |
| plugin.rs | 323 | 6 | PARTIAL | Plugin loading |
| scp.rs | 542 | 6 | PARTIAL | SCP protocol |
| screenshot.rs | 355 | 6 | PARTIAL | Screen capture |
| ratelimit.rs | 174 | 5 | HIGH | Rate limiter |
| selfupdate.rs | 289 | 4 | PARTIAL | Validate, no rollback test |
| exec_user.rs | 300 | 4 | PARTIAL | User-context exec |

### Root binary — main.rs (16 tests)

| Area | Tests | Notes |
|------|-------|-------|
| compute_timeout_secs | 3 | All command categories |
| CLI arg parsing | 3 | Port, timeout, flags |
| build_server_caps | 4 | Common + platform caps |
| resolve_device_id | 4 | Config, legacy, generate |
| timeout wrapper | 2 | Fast/slow future |

## Cost Classification

| Cost | Count | % |
|------|-------|---|
| FREE | ~450 | 63% |
| CHEAP | ~120 | 17% |
| MODERATE | ~150 | 20% |
| EXPENSIVE | 0 | 0% |

## Regression Gap Table

| # | Solved Issue | Regression Test | Status |
|---|-------------|-----------------|--------|
| 003 | rendezvous wrong IPs | `regression_tailscale_ip_roundtrip` +4 | OK |
| 004 | screenshot RDP failure | None (RDP env required) | SKIP |
| 007 | wire protocol interop | `protocol.rs` serde tests (18) | OK |
| 010 | clap flag parsing | `service_flag_uses_double_dash` | OK |
| 013 | rdv deploy wrong path | None | **MISSING** |
| 016 | relay TLS handshake EOF | None | **MISSING** |
| 019 | dashboard blocking quit | None | **MISSING** |
| 022 | tracing-appender panic | None | **MISSING** |
| 024 | selfupdate rollback | None | **MISSING** |
| 025 | enrollment config path | `enrollment_token_round_trip` | OK |
| 026 | pull-delta protocol | `pull_delta_multi_block_file` +2 | OK |

## Highest-Value Test Additions

| Priority | Module/Issue | Tests Needed | Cost |
|----------|-------------|-------------|------|
| P1 | solved/022 tracing panic | 1-2 (PermissionDenied log) | CHEAP |
| P1 | solved/024 selfupdate rollback | 2-3 (timeout + retry) | CHEAP |
| P1 | log_viewer.rs (3/501 lines) | 5-8 (parsing, filtering) | FREE |
| P1 | scp.rs (6/542 lines) | 3-5 (wire protocol edges) | CHEAP |
| P2 | solved/016 relay TLS EOF | 1-2 (inbound acceptance) | MODERATE |
| P2 | solved/019 dashboard quit | 1-2 (non-blocking quit) | MODERATE |
| P2 | plugin.rs (6/323 lines) | 2-3 (dir scanning, errors) | CHEAP |
