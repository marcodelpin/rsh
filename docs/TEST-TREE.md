# TEST-TREE.md — mrsh Test Coverage Analysis

Generated: 2026-03-25 | Version: v1.7.1 | Tests: 552

## Summary

| Metric | Value |
|--------|-------|
| Source files | 74 |
| Files with tests | 61 |
| Total #[test] | 552 |
| Coverage (files) | 82% (61/74) |
| NONE coverage | 9 files |
| LOW coverage (<5 tests) | 11 files |
| Solved issues | 28 |
| Regression tests | 2/28 (7%) |

## Coverage Matrix — NONE (0 tests)

| Module | Lines | Priority | Notes |
|--------|-------|----------|-------|
| src/keygen.rs | 429 | P1 | keys list/add/remove testable |
| src/local_cmds.rs | 285 | P2 | log_query, install_pack CLI parsing |
| src/fleet_cmd.rs | 250 | P2 | fleet/relay/rdv arg parsing |
| src/server_mode.rs | 508 | P2 | server startup (integration) |
| src/help.rs | 280 | — | pure text |
| mrsh-server/dispatch.rs | 595 | P1 | request routing + permission |
| mrsh-server/exec_user.rs | 300 | P2 | exec-as-user |
| mrsh-server/log_query.rs | 273 | — | 9 tests in module (separate) |

## Coverage Matrix — LOW (1-4 tests)

| Module | Lines | Tests | Priority |
|--------|-------|-------|----------|
| mrsh-client/commands.rs | 1007 | 4 | P1 |
| mrsh-relay/relay.rs | 613 | 4 | P1 |
| mrsh-client/tunnel.rs | 908 | 3 | P1 |
| mrsh-server/exec.rs | 351 | 2 | P0 |
| mrsh-server/shell.rs | 515 | 2 | P1 |
| mrsh-server/session.rs | 331 | 1 | P2 |
| mrsh-client/socks.rs | 593 | 1 | P2 |

## Regression Gap Table

28 solved issues, 2 with regression tests (7%).

| Status | Issue | Bug |
|--------|-------|-----|
| OK | 2026-03-19-003 | tracing-appender panic |
| OK | 2026-03-21-001 | selfupdate rollback |
| MISSING | 2026-03-05-003 | Rust-Go wire interop |
| MISSING | 2026-03-10-001 | clap flag parsing |
| MISSING | 2026-03-11-001 | tray crash Win10 IoT |
| MISSING | 2026-03-17-002 | relay TLS handshake EOF |
| MISSING | 2026-03-17-004 | service flag routing 1053 |
| MISSING | 2026-03-19-001 | stdout lost pipe handles |
| MISSING | 2026-03-22-001 | enrollment config path |
| MISSING | 2026-03-23-001 | pull-delta protocol bug |
| MISSING | 2026-03-24-002 | installer missing key |
| + 17 more | — | see docs/solved/ |

## Priority Gaps

### P0
- **exec.rs** (2 tests / 351 lines) — core command execution
- **dispatch.rs** (0 tests / 595 lines) — request routing

### P1
- **commands.rs** (4 / 1007) — client commands
- **keygen.rs** (0 / 429) — key management
- **relay.rs** (4 / 613) — relay core
- **tunnel.rs** (3 / 908) — TCP tunnels
- **shell.rs** (2 / 515) — ConPTY/shell
- **26 regression tests** missing from solved issues

### P2
- socks.rs, session.rs, exec_user.rs, local_cmds.rs, fleet_cmd.rs

## Cost

| Cost | ~Count | Notes |
|------|--------|-------|
| FREE | 500 | pure logic, parsing |
| CHEAP | 40 | tempdir, duplex streams |
| MODERATE | 10 | network, relay pairing |
| EXPENSIVE | 2 | real screenshot, GPU |
