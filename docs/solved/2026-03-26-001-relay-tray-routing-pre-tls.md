# SOLVED: Relay connections always land on SYSTEM — tray unreachable via relay

| Metadata | Value |
| :--- | :--- |
| **Date** | 2026-03-26 |
| **ID** | 2026-03-26-001 |
| **Area** | mrsh relay / server_mode / tray routing |
| **Status** | Resolved |
| **Impact** | High |

## 1. Problem Description

When connecting to a machine via relay (DeviceID), all connections landed on the service port (8822, SYSTEM context). The tray port (9822, user session) was unreachable via relay, even though direct connections had auto-try-ports logic that found the tray.

This meant relay connections couldn't access user-session features: mapped drives, GUI, screenshots, network shares.

## 2. Root Cause Analysis (RCA)

Three independent root causes:

**RC1 — Client: mutually exclusive branches.** In `main.rs`, the relay path and auto-try-ports path were separate `if/else if` branches. Relay connections always used `resolved_port = DEFAULT_PORT = 8822`, bypassing auto-try.

**RC2 — Server: default port = no proxy.** The server's relay routing logic (`server_mode.rs:389`) only proxied to tray when `target_port != 0 && target_port != DEFAULT_PORT`. Since client sent 8822, the condition was always false.

**RC3 — Server: proxy at wrong layer.** The existing explicit-port proxy happened AFTER TLS accept — it sent decrypted application data to the tray port. But tray's listener expects TLS ClientHello as the first byte. The proxy would have silently broken the tray's TLS handshake.

## 3. Abstract Solution

**Protocol signal:** Use `target_port = 0` in the relay protocol to mean "server decides" (tray-first). Non-zero = explicit port request.

**Client:** Send `target_port=0` when no `-p` flag specified. Send exact port when explicit.

**Server:** Route BEFORE TLS accept (critical — must forward raw TCP):
- `target_port == 0`: probe tray (127.0.0.1:9822, 500ms timeout), proxy raw stream if available, fall back to SYSTEM
- `target_port != DEFAULT_PORT`: proxy raw stream to that port
- `target_port == DEFAULT_PORT`: TLS accept and handle in SYSTEM context

The raw stream proxy is essential — the target port (tray) does its own TLS handshake with the client through the transparent relay tunnel.

## 4. Prevention Rules

- Relay proxy must operate on raw TCP stream, before TLS accept — never proxy decrypted data to a TLS listener
- Use sentinel value (0) for "server decides" instead of overloading the default port
- When adding new transport-layer features, verify they work across all connection methods (direct, relay, P2P)

## 5. Case Study Reference

Commit: 8603e57
Files: relay_connect.rs, main.rs, server_mode.rs, fleet.rs
Tests: 3 regression tests in regression_server.rs
