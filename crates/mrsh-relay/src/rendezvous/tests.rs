//! Tests for the rendezvous module.
//!
//! Pulls in `super::*` plus internal items (`PeerEntry`, `encode_socket_addr_with_tm`,
//! `make_uuid`) that are only `pub(super)`-visible from sibling submodules.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use prost::Message;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, timeout};

use crate::proto;

use super::protocol::{
    Client, decode_socket_addr, encode_socket_addr, encode_socket_addr_with_tm, is_device_id,
    make_uuid,
};
use super::server::{PeerEntry, RendezvousServer};

#[test]
fn device_id_valid() {
    assert!(is_device_id("123456789"));
    assert!(is_device_id("abc123"));
    assert!(is_device_id("ABC123456"));
    assert!(is_device_id("a1"));
    assert!(is_device_id("1"));
    assert!(is_device_id("0"));
}

#[test]
fn device_id_invalid() {
    assert!(!is_device_id(""));
    assert!(!is_device_id("192.168.1.1"));
    assert!(!is_device_id("10.0.0.1"));
    assert!(!is_device_id("example.com"));
    assert!(!is_device_id("abcdef")); // no digits
    assert!(!is_device_id("123abc")); // letter after digit
    assert!(!is_device_id("a-1")); // dash
    assert!(!is_device_id("::1")); // IPv6
}

#[test]
fn addr_decode_lan() {
    // Encode 192.168.1.100:8822 with tm=0 for testing.
    let ip = Ipv4Addr::new(192, 168, 1, 100);
    let port: u16 = 8822;
    let ip32 = u32::from_le_bytes(ip.octets());
    let lo = (ip32 as u64) << 49 | port as u64;
    let hi = (ip32 as u64) >> 15;
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&lo.to_le_bytes());
    data[8..].copy_from_slice(&hi.to_le_bytes());
    let end = data
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);

    let addr = decode_socket_addr(&data[..end]).unwrap();
    assert_eq!(addr, SocketAddr::V4(SocketAddrV4::new(ip, port)));
}

#[test]
fn addr_decode_tailscale() {
    let ip = Ipv4Addr::new(100, 124, 180, 114);
    let port: u16 = 8822;
    let ip32 = u32::from_le_bytes(ip.octets());
    let lo = (ip32 as u64) << 49 | port as u64;
    let hi = (ip32 as u64) >> 15;
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&lo.to_le_bytes());
    data[8..].copy_from_slice(&hi.to_le_bytes());
    let end = data
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);

    let addr = decode_socket_addr(&data[..end]).unwrap();
    assert_eq!(addr, SocketAddr::V4(SocketAddrV4::new(ip, port)));
}

#[test]
fn addr_decode_invalid_len() {
    assert!(decode_socket_addr(&[]).is_err());
    assert!(decode_socket_addr(&[1, 2, 3]).is_err());
    assert!(decode_socket_addr(&[0; 20]).is_err());
}

#[test]
fn resolve_no_servers() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = Client {
            servers: vec![],
            licence_key: String::new(),
            local_id: String::new(),
            group_hash: String::new(),
            hostname: String::new(),
            platform: String::new(),
            service_port: 0,
            encrypted_net_info: Vec::new(),
            enrollment_token: String::new(),
            tray_port: 0,
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        };
        assert!(c.resolve("123456789").await.is_err());
    });
}

#[test]
fn uuid_format() {
    let u = make_uuid();
    assert_eq!(u.len(), 36);
    assert_eq!(u.as_bytes()[8], b'-');
    assert_eq!(u.as_bytes()[13], b'-');
    assert_eq!(u.as_bytes()[18], b'-');
    assert_eq!(u.as_bytes()[23], b'-');
}

// --- encode_socket_addr tests ---

#[test]
fn addr_encode_decode_roundtrip_zero_tm() {
    let addr: SocketAddr = "192.168.1.100:8822".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn addr_encode_decode_roundtrip_nonzero_tm() {
    let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 1710000000);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn addr_encode_decode_roundtrip_tailscale() {
    let addr: SocketAddr = "100.64.0.1:8822".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0xDEADBEEF);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn addr_encode_decode_roundtrip_live() {
    // Uses real timestamp (encode_socket_addr without explicit tm).
    let addr: SocketAddr = "192.168.1.220:80".parse().unwrap();
    let encoded = encode_socket_addr(&addr);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn addr_encode_minimum_4_bytes() {
    let addr: SocketAddr = "0.0.0.1:1".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0);
    assert!(encoded.len() >= 4);
}

// --- RendezvousServer tests ---

#[tokio::test]
async fn rdv_server_register_and_resolve() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = sock.local_addr().unwrap();
    let sock = Arc::new(sock);

    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Server recv loop (single iteration per request).
    let srv_sock = sock.clone();
    let peers_clone = peers.clone();
    let srv_clone_key = srv.key.clone();
    let srv_clone_relay = srv.relay_server.clone();
    let handle = tokio::spawn(async move {
        let srv_inner = RendezvousServer::new(&srv_clone_key, &srv_clone_relay);
        let mut buf = vec![0u8; 65535];
        // Handle 2 messages: register + punch hole
        for _ in 0..2 {
            let (n, src) = srv_sock.recv_from(&mut buf).await.unwrap();
            let msg = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
            if let Some(resp) = srv_inner.handle_message(msg, src, &peers_clone) {
                srv_sock.send_to(&resp.encode_to_vec(), src).await.unwrap();
            }
        }
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(srv_addr).await.unwrap();

    // Register as "dev123".
    let reg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(
            proto::RegisterPeer {
                id: "dev123".to_string(),
                ..Default::default()
            },
        )),
    };
    client.send(&reg.encode_to_vec()).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    assert!(matches!(
        resp.union,
        Some(proto::rendezvous_message::Union::RegisterPeerResponse(_))
    ));

    // Punch hole request for "dev123" (same IP → FetchLocalAddr).
    let punch = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(
            proto::PunchHoleRequest {
                id: "dev123".to_string(),
                ..Default::default()
            },
        )),
    };
    client.send(&punch.encode_to_vec()).await.unwrap();
    let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    // Same IP → FetchLocalAddr.
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchLocalAddr(fla)) => {
            assert!(!fla.socket_addr.is_empty());
            assert_eq!(fla.relay_server, "relay.test:21117");
        }
        other => panic!("expected FetchLocalAddr, got {:?}", other),
    }

    handle.await.unwrap();
}

#[tokio::test]
async fn rdv_server_unknown_device() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    let punch = proto::PunchHoleRequest {
        id: "nonexistent".to_string(),
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
    };
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
            assert_eq!(
                phr.failure,
                proto::punch_hole_response::Failure::IdNotExist as i32
            );
        }
        other => panic!("expected PunchHoleResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_server_key_mismatch() {
    let srv = RendezvousServer::new("secret", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    let punch = proto::PunchHoleRequest {
        id: "dev1".to_string(),
        licence_key: "wrong".to_string(),
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
    };
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
            assert_eq!(
                phr.failure,
                proto::punch_hole_response::Failure::LicenseMismatch as i32
            );
        }
        other => panic!("expected LicenseMismatch, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_server_register_pk() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    let rpk = proto::RegisterPk {
        id: "dev1".to_string(),
        uuid: vec![1; 16],
        pk: vec![0; 32],
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPk(rpk)),
    };
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::RegisterPkResponse(r)) => {
            assert_eq!(r.result, proto::register_pk_response::Result::Ok as i32);
            assert_eq!(r.keep_alive, 300);
        }
        other => panic!("expected RegisterPkResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_server_health_check() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Add a peer.
    peers.lock().unwrap().insert(
        "dev1".to_string(),
        PeerEntry {
            addr: "10.0.0.1:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: String::new(),
            platform: String::new(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::HealthCheck(
            proto::HealthCheck {
                token: String::new(),
            },
        )),
    };
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::HealthResponse(hr)) => {
            assert_eq!(hr.peers_online, 1);
            assert!(!hr.version.is_empty());
        }
        other => panic!("expected HealthResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_server_cross_network_returns_punch_hole_response() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Register peer from a different IP.
    peers.lock().unwrap().insert(
        "remote1".to_string(),
        PeerEntry {
            addr: "203.0.113.50:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: String::new(),
            platform: String::new(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    let punch = proto::PunchHoleRequest {
        id: "remote1".to_string(),
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
    };
    // Requester comes from a different IP.
    let src: SocketAddr = "198.51.100.10:54321".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
            assert!(!phr.socket_addr.is_empty());
            assert_eq!(phr.relay_server, "relay.test:21117");
            // Decode the address to verify it matches the registered peer.
            let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
            assert_eq!(decoded, "203.0.113.50:8822".parse::<SocketAddr>().unwrap());
        }
        other => panic!("expected PunchHoleResponse, got {:?}", other),
    }
}

// --- Protobuf zero-value / edge case tests (orin-0td) ---

/// PunchHoleResponse with failure=0 (IdNotExist, protobuf default) but valid
/// socket_addr should return the address, not an error.  Failure=0 is the
/// protobuf default so a "success" response has failure==0 implicitly.
#[tokio::test]
async fn rdv_server_success_response_has_failure_zero() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    peers.lock().unwrap().insert(
        "peer1".to_string(),
        PeerEntry {
            addr: "10.0.0.5:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: String::new(),
            platform: String::new(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    let punch = proto::PunchHoleRequest {
        id: "peer1".to_string(),
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
    };
    // Different IP so we get PunchHoleResponse (not FetchLocalAddr).
    let src: SocketAddr = "203.0.113.1:9999".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
            // failure field is 0 (IdNotExist/default) — but socket_addr is populated,
            // so the client should treat this as success.
            assert_eq!(
                phr.failure,
                proto::punch_hole_response::Failure::IdNotExist as i32
            );
            assert!(!phr.socket_addr.is_empty(), "socket_addr must be populated");
            let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
            assert_eq!(decoded, "10.0.0.5:8822".parse::<SocketAddr>().unwrap());
        }
        other => panic!("expected PunchHoleResponse, got {:?}", other),
    }
}

/// AddrMangle roundtrip with port 0 (edge case: port=0 after wrapping).
#[test]
fn addr_encode_decode_roundtrip_port_zero() {
    let addr: SocketAddr = "192.168.1.1:0".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

/// AddrMangle roundtrip with port 65535 (max u16).
#[test]
fn addr_encode_decode_roundtrip_port_max() {
    let addr: SocketAddr = "10.0.0.1:65535".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0xFFFFFFFF);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

/// AddrMangle with 0.0.0.0 (all-zeros IP).
#[test]
fn addr_encode_decode_roundtrip_zero_ip() {
    let addr: SocketAddr = "0.0.0.0:8822".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 42);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

/// AddrMangle with 255.255.255.255 (broadcast).
#[test]
fn addr_encode_decode_roundtrip_broadcast() {
    let addr: SocketAddr = "255.255.255.255:65535".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0xDEADCAFE);
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

/// Port preservation: resolve result must carry the exact port registered.
#[tokio::test]
async fn rdv_server_preserves_registered_port() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Register on non-default port.
    peers.lock().unwrap().insert(
        "custom-port".to_string(),
        PeerEntry {
            addr: "172.16.0.1:9822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: String::new(),
            platform: String::new(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    let punch = proto::PunchHoleRequest {
        id: "custom-port".to_string(),
        ..Default::default()
    };
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
    };
    let src: SocketAddr = "198.51.100.1:12345".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
            let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
            assert_eq!(
                decoded.port(),
                9822,
                "port must be preserved through encode/decode"
            );
        }
        other => panic!("expected PunchHoleResponse, got {:?}", other),
    }
}

// --- Network partition / unreachable server tests (rsh-a3o) ---

fn make_client(servers: Vec<String>, local_id: &str) -> Client {
    Client {
        servers,
        licence_key: String::new(),
        local_id: local_id.to_string(),
        group_hash: String::new(),
        hostname: "test-host".to_string(),
        platform: "linux".to_string(),
        service_port: 8822,
        encrypted_net_info: Vec::new(),
        enrollment_token: String::new(),
        tray_port: 0,
        ports: Vec::new(),
        current_version: String::new(),
        last_update_status: String::new(),
        last_update_at_unix: 0,
        track: String::new(),
        auto_upgrade: false,
    }
}

/// register_once returns error when no servers are configured (fast path).
#[test]
fn register_once_no_servers_configured() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = make_client(vec![], "test-device");
        let err = c.register_once().await.unwrap_err();
        assert!(err.to_string().contains("no rendezvous server"));
    });
}

/// register_once returns error immediately when local_id is empty.
#[test]
fn register_once_no_local_id() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = make_client(vec!["127.0.0.1:19999".to_string()], "");
        let err = c.register_once().await.unwrap_err();
        assert!(err.to_string().contains("no local_id"));
    });
}

/// register_once fails gracefully when all servers are unreachable.
/// On Linux, UDP send to a closed local port gets ECONNREFUSED on recv.
/// The 5-second timeout in do_register fires as fallback.
/// Either way: must return an error, must not hang indefinitely.
#[tokio::test(flavor = "current_thread")]
async fn register_once_server_unreachable_returns_error() {
    // Bind then immediately drop to get a "closed" port (ICMP port-unreachable).
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = sock.local_addr().unwrap().to_string();
    drop(sock);

    let c = make_client(vec![closed_addr], "partition-test-device");

    // Must return error — either ECONNREFUSED (fast) or timeout (≤5s).
    let result = tokio::time::timeout(Duration::from_secs(7), c.register_once()).await;

    match result {
        Ok(inner) => assert!(
            inner.is_err(),
            "register_once must fail when server unreachable"
        ),
        Err(_) => panic!("register_once hung beyond 7 seconds (deadline: 5s per server)"),
    }
}

// --- Relay forwarding tests (beads-u8d) ---

/// hbbs TCP RequestRelay forwarding: registered device receives RelayResponse via UDP.
#[tokio::test]
async fn rdv_tcp_relay_forwarding_to_registered_device() {
    // Start hbbs (UDP + TCP) on random port.
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = udp_sock.local_addr().unwrap();
    drop(udp_sock);

    let srv = RendezvousServer::new("testkey", &format!("127.0.0.1:{}", srv_addr.port() + 1));

    let srv_handle = tokio::spawn(async move {
        // Will run until cancelled; we just let it run in background.
        let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
    });

    // Give server time to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // "Server" device: register with hbbs and listen for messages on same socket.
    let device_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Register device "999888777" by sending RegisterPeer.
    let reg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(
            proto::RegisterPeer {
                id: "999888777".to_string(),
                hostname: "test-device".to_string(),
                platform: "linux".to_string(),
                service_port: 8822,
                ..Default::default()
            },
        )),
    };
    device_sock
        .send_to(&reg.encode_to_vec(), srv_addr)
        .await
        .unwrap();

    // Read RegisterPeerResponse.
    let mut buf = vec![0u8; 65535];
    let (n, _) = timeout(Duration::from_secs(3), device_sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    assert!(
        matches!(
            resp.union,
            Some(proto::rendezvous_message::Union::RegisterPeerResponse(_))
        ),
        "should get RegisterPeerResponse"
    );

    // "Client": send RequestRelay via TCP to hbbs for device 999888777.
    let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
    let relay_req = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RequestRelay(
            proto::RequestRelay {
                id: "999888777".to_string(),
                uuid: "test-uuid-1234".to_string(),
                relay_server: "relay.test:21117".to_string(),
                licence_key: "testkey".to_string(),
                ..Default::default()
            },
        )),
    };
    let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
    use tokio::io::AsyncWriteExt;
    tcp.write_all(&frame).await.unwrap();

    // The "device" should receive RelayResponse via UDP.
    let (n, _) = timeout(Duration::from_secs(3), device_sock.recv_from(&mut buf))
        .await
        .expect("device should receive RelayResponse within 3s")
        .unwrap();
    let notification = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    match notification.union {
        Some(proto::rendezvous_message::Union::RelayResponse(rr)) => {
            assert_eq!(rr.uuid, "test-uuid-1234");
            assert_eq!(rr.relay_server, "relay.test:21117");
        }
        other => panic!("expected RelayResponse, got {:?}", other),
    }

    srv_handle.abort();
}

/// hbbs TCP RequestRelay for unregistered device: no crash, no notification.
#[tokio::test]
async fn rdv_tcp_relay_unregistered_device_no_crash() {
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = udp_sock.local_addr().unwrap();
    drop(udp_sock);

    let srv = RendezvousServer::new("", "relay.test:21117");
    let srv_handle = tokio::spawn(async move {
        let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send RequestRelay for non-existent device — should not crash.
    let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
    let relay_req = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RequestRelay(
            proto::RequestRelay {
                id: "nonexistent".to_string(),
                uuid: "test-uuid".to_string(),
                ..Default::default()
            },
        )),
    };
    let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
    use tokio::io::AsyncWriteExt;
    tcp.write_all(&frame).await.unwrap();

    // Give hbbs time to process.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Server should still be alive (try another TCP connection).
    let tcp2 = tokio::net::TcpStream::connect(srv_addr).await;
    assert!(tcp2.is_ok(), "hbbs should still accept connections");

    srv_handle.abort();
}

/// hbbs TCP RequestRelay with key mismatch: silently rejected.
#[tokio::test]
async fn rdv_tcp_relay_key_mismatch_rejected() {
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = udp_sock.local_addr().unwrap();
    drop(udp_sock);

    let srv = RendezvousServer::new("correctkey", "relay.test:21117");
    let srv_handle = tokio::spawn(async move {
        let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Register a device.
    let device_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(
            proto::RegisterPeer {
                id: "keytestdev".to_string(),
                ..Default::default()
            },
        )),
    };
    device_sock
        .send_to(&reg.encode_to_vec(), srv_addr)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let _ = timeout(Duration::from_secs(2), device_sock.recv_from(&mut buf))
        .await
        .unwrap();

    // Send RequestRelay with wrong key.
    let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
    let relay_req = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RequestRelay(
            proto::RequestRelay {
                id: "keytestdev".to_string(),
                uuid: "uuid-xyz".to_string(),
                licence_key: "wrongkey".to_string(),
                ..Default::default()
            },
        )),
    };
    let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
    use tokio::io::AsyncWriteExt;
    tcp.write_all(&frame).await.unwrap();

    // Device should NOT receive anything (key mismatch → silently rejected).
    let result = timeout(Duration::from_millis(500), device_sock.recv_from(&mut buf)).await;
    assert!(
        result.is_err(),
        "device should not receive notification on key mismatch"
    );

    srv_handle.abort();
}

/// run_registration_loop receives RelayResponse and forwards to channel.
#[tokio::test]
async fn registration_loop_receives_relay_notification() {
    // Start a minimal hbbs.
    let hbbs_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let hbbs_addr = hbbs_sock.local_addr().unwrap();

    let hbbs_sock_clone = hbbs_sock.clone();
    let hbbs_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        // Read RegisterPeer, respond, then send a fake RelayResponse.
        let (n, src) = hbbs_sock_clone.recv_from(&mut buf).await.unwrap();
        let msg = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
        assert!(matches!(
            msg.union,
            Some(proto::rendezvous_message::Union::RegisterPeer(_))
        ));

        // Send RegisterPeerResponse.
        let resp = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeerResponse(
                proto::RegisterPeerResponse { request_pk: false },
            )),
        };
        hbbs_sock_clone
            .send_to(&resp.encode_to_vec(), src)
            .await
            .unwrap();

        // Now send a RelayResponse (simulating a client requesting relay).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let relay_resp = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RelayResponse(
                proto::RelayResponse {
                    uuid: "relay-uuid-abc".to_string(),
                    relay_server: "hbbr.test:21117".to_string(),
                    ..Default::default()
                },
            )),
        };
        hbbs_sock_clone
            .send_to(&relay_resp.encode_to_vec(), src)
            .await
            .unwrap();
    });

    let cancel = tokio_util::sync::CancellationToken::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let client = Client {
        servers: vec![hbbs_addr.to_string()],
        licence_key: String::new(),
        local_id: "testdev123".to_string(),
        group_hash: String::new(),
        hostname: "test".to_string(),
        platform: "linux".to_string(),
        service_port: 8822,
        encrypted_net_info: Vec::new(),
        enrollment_token: String::new(),
        tray_port: 0,
        ports: Vec::new(),
        current_version: String::new(),
        last_update_status: String::new(),
        last_update_at_unix: 0,
        track: String::new(),
        auto_upgrade: false,
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        client.run_registration_loop(cancel_clone, tx).await;
    });

    // Wait for the relay notification.
    let notif = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("should receive relay notification within 5s")
        .expect("channel should not be closed");

    assert_eq!(notif.uuid, "relay-uuid-abc");
    assert_eq!(notif.relay_server, "hbbr.test:21117");

    cancel.cancel();
    hbbs_handle.await.unwrap();
}

#[tokio::test]
async fn rdv_list_peers_returns_all_registered() {
    let srv = RendezvousServer::new("test-key", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Register two peers
    peers.lock().unwrap().insert(
        "111".to_string(),
        PeerEntry {
            addr: "10.0.0.1:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: "host-a".to_string(),
            platform: "windows".to_string(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );
    peers.lock().unwrap().insert(
        "222".to_string(),
        PeerEntry {
            addr: "10.0.0.2:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: "host-b".to_string(),
            platform: "linux".to_string(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    // Valid key → should get both peers
    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::ListPeers(
            proto::ListPeers {
                licence_key: "test-key".to_string(),
            },
        )),
    };
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::ListPeersResponse(lpr)) => {
            assert_eq!(lpr.peers.len(), 2);
            let ids: Vec<&str> = lpr.peers.iter().map(|p| p.device_id.as_str()).collect();
            assert!(ids.contains(&"111"));
            assert!(ids.contains(&"222"));
        }
        other => panic!("expected ListPeersResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_list_peers_rejects_bad_key() {
    let srv = RendezvousServer::new("correct-key", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    peers.lock().unwrap().insert(
        "111".to_string(),
        PeerEntry {
            addr: "10.0.0.1:8822".parse().unwrap(),
            last_seen: Instant::now(),
            group_hash: String::new(),
            hostname: "host-a".to_string(),
            platform: "windows".to_string(),
            service_port: 0,
            tcp_notify: None,
            encrypted_net_info: Vec::new(),
            ports: Vec::new(),
            current_version: String::new(),
            last_update_status: String::new(),
            last_update_at_unix: 0,
            track: String::new(),
            auto_upgrade: false,
        },
    );

    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::ListPeers(
            proto::ListPeers {
                licence_key: "wrong-key".to_string(),
            },
        )),
    };
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let resp = srv.handle_message(msg, src, &peers);
    assert!(resp.is_none(), "bad key should be rejected");
}

#[tokio::test]
async fn rdv_service_port_round_trip() {
    let srv = RendezvousServer::new("key", "relay.test:21117");
    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Register peer with non-default service_port
    let reg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(
            proto::RegisterPeer {
                id: "test-9822".to_string(),
                serial: 0,
                group_hash: String::new(),
                hostname: "CUSTOM-PORT".to_string(),
                platform: "windows".to_string(),
                service_port: 9822,
                encrypted_net_info: Vec::new(),
                ports: Vec::new(),
                current_version: String::new(),
                last_update_status: String::new(),
                last_update_at_unix: 0,
                track: String::new(),
                auto_upgrade: false,
            },
        )),
    };
    let src: SocketAddr = "10.0.0.5:12345".parse().unwrap();
    let _resp = srv.handle_message(reg, src, &peers);

    // Also register one with default port (0)
    let reg2 = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(
            proto::RegisterPeer {
                id: "test-default".to_string(),
                serial: 0,
                group_hash: String::new(),
                hostname: "DEFAULT-PORT".to_string(),
                platform: "linux".to_string(),
                service_port: 0,
                encrypted_net_info: Vec::new(),
                ports: Vec::new(),
                current_version: String::new(),
                last_update_status: String::new(),
                last_update_at_unix: 0,
                track: String::new(),
                auto_upgrade: false,
            },
        )),
    };
    let _resp2 = srv.handle_message(reg2, "10.0.0.6:12345".parse().unwrap(), &peers);

    // Query via ListPeers
    let lp = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::ListPeers(
            proto::ListPeers {
                licence_key: "key".to_string(),
            },
        )),
    };
    let resp = srv
        .handle_message(lp, "127.0.0.1:9999".parse().unwrap(), &peers)
        .unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::ListPeersResponse(lpr)) => {
            let custom = lpr
                .peers
                .iter()
                .find(|p| p.device_id == "test-9822")
                .unwrap();
            assert_eq!(
                custom.service_port, 9822,
                "custom port must survive round-trip"
            );
            assert_eq!(custom.hostname, "CUSTOM-PORT");

            let default = lpr
                .peers
                .iter()
                .find(|p| p.device_id == "test-default")
                .unwrap();
            assert_eq!(
                default.service_port, 0,
                "default port=0 must survive round-trip"
            );
        }
        other => panic!("expected ListPeersResponse, got {:?}", other),
    }
}

// ── Regression: solved 2026-02-27-001 ────────────────────────
// Bug: 6-byte encoded addresses were decoded incorrectly.
// Tailscale IPs (100.x.x.x) must roundtrip correctly.
// Short encoded data must not corrupt the address.

#[test]
fn regression_tailscale_ip_roundtrip() {
    // Tailscale IPs caused wrong resolution in production
    let addr: SocketAddr = "100.64.0.1:8822".parse().unwrap();
    for tm in [0u32, 1, 1000, 0xDEAD_BEEF, u32::MAX] {
        let encoded = encode_socket_addr_with_tm(&addr, tm);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr, "failed with tm={}", tm);
    }
}

#[test]
fn regression_lan_ip_roundtrip() {
    // LAN IPs that were misresolved due to AddrMangle bug
    for ip in [
        "192.0.2.50:8822",
        "192.168.0.42:9822",
        "10.0.0.99:8822",
    ] {
        let addr: SocketAddr = ip.parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0xCAFE_BABE);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr, "failed for {}", ip);
    }
}

#[test]
fn regression_short_encoded_data() {
    // The bug: 6-byte data was handled by a legacy branch that corrupted output.
    // After fix: all lengths go through the same AddrMangle decode.
    let addr: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let encoded = encode_socket_addr_with_tm(&addr, 0); // tm=0 produces short encoding
    assert!(encoded.len() >= 4, "encoded must be at least 4 bytes");
    let decoded = decode_socket_addr(&encoded).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn regression_various_encoded_lengths() {
    // Verify all possible encoded lengths decode correctly
    let addrs = [
        "0.0.0.1:1",             // minimal values → short encoding
        "1.1.1.1:443",           // common
        "192.168.1.1:8822",      // typical LAN
        "100.64.0.1:22",         // CGNAT range
        "255.255.255.255:65535", // max values → longest encoding
    ];
    for ip in addrs {
        let addr: SocketAddr = ip.parse().unwrap();
        let encoded = encode_socket_addr(&addr);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr, "roundtrip failed for {}", ip);
    }
}

#[test]
fn regression_decode_rejects_too_short() {
    assert!(decode_socket_addr(&[0, 0, 0]).is_err()); // < 4 bytes
    assert!(decode_socket_addr(&[]).is_err());
}

#[test]
fn regression_decode_rejects_too_long() {
    assert!(decode_socket_addr(&[0u8; 17]).is_err()); // > 16 bytes
}

// --- rsh-5264.3 VersionAdvert tests ---

#[test]
fn version_advert_proto_roundtrip() {
    use super::protocol::VersionAdvert;
    let a = VersionAdvert {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        latest_version: "1.10.30".into(),
        download_url: "https://rdv.example/mrsh-1.10.30.exe".into(),
        signature: vec![1, 2, 3, 4, 5],
        published_at_unix: 1_700_000_000,
    };
    let p = a.to_proto();
    let b = VersionAdvert::from_proto(&p);
    assert_eq!(a, b, "VersionAdvert proto roundtrip must be lossless");
}

#[test]
fn version_advert_operator_signing_payload_is_canonical() {
    use super::protocol::VersionAdvert;
    let a = VersionAdvert {
        platform: "linux-musl".into(),
        track: "canary".into(),
        latest_version: "2.0.0".into(),
        ..Default::default()
    };
    assert_eq!(
        a.operator_signing_payload(),
        b"linux-musl|canary|2.0.0".to_vec(),
        "operator signing payload format must be stable for cross-tool agreement"
    );
}

#[tokio::test]
async fn rdv_publish_then_query_roundtrip() {
    let srv = RendezvousServer::new("", "relay.test:21117");

    // Publish 1.10.30 stable for windows-msvc.
    let advert = proto::VersionAdvert {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        latest_version: "1.10.30".into(),
        download_url: "https://example/bin".into(),
        signature: vec![0xAA; 64],
        published_at_unix: 0, // server stamps this
    };
    let pub_resp = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(advert.clone()),
        binary_blob: vec![0xCC; 1024],
        operator_signature: vec![0xDD; 64],
    });
    match pub_resp.union {
        Some(proto::rendezvous_message::Union::PublishVersionResponse(r)) => {
            assert!(r.accepted, "publish must be accepted (got: {})", r.error_message);
        }
        other => panic!("expected PublishVersionResponse, got {:?}", other),
    }

    // Query: server has 1.10.29, should get the 1.10.30 advert.
    let qresp = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        current_version: "1.10.29".into(),
    });
    match qresp.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(r.update_available, "1.10.30 > 1.10.29 must trigger update");
            let a = r.advert.expect("advert must be present");
            assert_eq!(a.latest_version, "1.10.30");
            assert_eq!(a.platform, "windows-msvc");
            assert_eq!(a.track, "stable");
            assert!(a.published_at_unix > 0, "server must stamp published_at");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    // Query: server already at 1.10.30, no update.
    let qresp_eq = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        current_version: "1.10.30".into(),
    });
    match qresp_eq.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(!r.update_available);
            assert!(r.advert.is_none(), "no advert returned when up-to-date");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    // Query: different track has no advert.
    let qresp_other = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "canary".into(),
        current_version: "0".into(),
    });
    match qresp_other.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(!r.update_available);
            assert!(r.advert.is_none());
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_publish_rejects_empty_fields() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let bad = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "".into(),
            track: "stable".into(),
            latest_version: "1.0.0".into(),
            ..Default::default()
        }),
        binary_blob: Vec::new(),
        operator_signature: Vec::new(),
    });
    match bad.union {
        Some(proto::rendezvous_message::Union::PublishVersionResponse(r)) => {
            assert!(!r.accepted);
            assert!(
                r.error_message.contains("platform")
                    || r.error_message.contains("track")
                    || r.error_message.contains("latest_version"),
                "error must mention which field is missing: {}",
                r.error_message
            );
        }
        other => panic!("expected PublishVersionResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_publish_overwrites_existing_advert() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let make = |v: &str| proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "linux-glibc".into(),
            track: "stable".into(),
            latest_version: v.into(),
            ..Default::default()
        }),
        binary_blob: Vec::new(),
        operator_signature: Vec::new(),
    };
    let _ = srv.handle_publish_version(make("1.0.0"));
    let _ = srv.handle_publish_version(make("1.5.0")); // overwrite

    let q = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "linux-glibc".into(),
        track: "stable".into(),
        current_version: "1.0.0".into(),
    });
    match q.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(r.update_available);
            assert_eq!(r.advert.unwrap().latest_version, "1.5.0");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rdv_publish_query_via_udp_endtoend() {
    // Spawn a tiny server task that handles exactly two messages (publish + query)
    // and exits. Mirrors the existing rdv_server_register_and_resolve pattern.
    let srv = RendezvousServer::new("", "relay.test:21117");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = sock.local_addr().unwrap();
    let sock = Arc::new(sock);

    let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    let srv_sock = sock.clone();
    let peers_clone = peers.clone();
    let srv_key = srv.key.clone();
    let srv_relay = srv.relay_server.clone();
    let advert_arc = srv.version_adverts.clone();
    let handle = tokio::spawn(async move {
        // Reuse the *same* RendezvousServer instance across the two requests so
        // version_adverts state is preserved (the UDP loop owns the server).
        let mut srv_inner = RendezvousServer::new(&srv_key, &srv_relay);
        srv_inner.version_adverts = advert_arc;
        let mut buf = vec![0u8; 65535];
        for _ in 0..2 {
            let (n, src) = srv_sock.recv_from(&mut buf).await.unwrap();
            let msg = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
            if let Some(resp) = srv_inner.handle_message(msg, src, &peers_clone) {
                srv_sock.send_to(&resp.encode_to_vec(), src).await.unwrap();
            }
        }
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(srv_addr).await.unwrap();

    // Publish.
    let pub_msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PublishVersionRequest(
            proto::PublishVersionRequest {
                advert: Some(proto::VersionAdvert {
                    platform: "macos".into(),
                    track: "stable".into(),
                    latest_version: "1.10.31".into(),
                    download_url: String::new(),
                    signature: vec![0u8; 64],
                    published_at_unix: 0,
                }),
                binary_blob: Vec::new(),
                operator_signature: vec![0u8; 64],
            },
        )),
    };
    client.send(&pub_msg.encode_to_vec()).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::PublishVersionResponse(r)) => {
            assert!(r.accepted, "publish accepted; err={}", r.error_message);
        }
        other => panic!("expected PublishVersionResponse, got {:?}", other),
    }

    // Query.
    let q_msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::QueryVersionRequest(
            proto::QueryVersionRequest {
                platform: "macos".into(),
                track: "stable".into(),
                current_version: "1.10.30".into(),
            },
        )),
    };
    client.send(&q_msg.encode_to_vec()).await.unwrap();
    let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
    match resp.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(r.update_available);
            let a = r.advert.expect("advert");
            assert_eq!(a.latest_version, "1.10.31");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    handle.await.unwrap();
}

// ---------- rsh-5264.5: canary track gating ----------

/// rsh-5264.5 acceptance: a canary host receives an advert for the canary
/// track while a stable host stays on stable. Two adverts published on the
/// same platform but different tracks must NOT cross-pollinate.
#[tokio::test]
async fn rsh_5264_5_canary_host_gets_canary_stable_host_stays_stable() {
    let srv = RendezvousServer::new("", "relay.test:21117");

    // Publish 1.11.0 to canary track for windows-msvc.
    let canary_advert = proto::VersionAdvert {
        platform: "windows-msvc".into(),
        track: "canary".into(),
        latest_version: "1.11.0".into(),
        download_url: "https://example/canary".into(),
        signature: vec![0xAB; 64],
        published_at_unix: 0,
    };
    let _ = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(canary_advert),
        binary_blob: vec![0xEE; 1024],
        operator_signature: vec![0xFF; 64],
    });

    // No stable advert published yet. A stable host MUST NOT see the canary.
    let stable_query = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        current_version: "1.10.29".into(),
    });
    match stable_query.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(
                !r.update_available,
                "stable host must NOT receive canary advert"
            );
            assert!(r.advert.is_none(), "stable track has no advert");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    // Canary host on the same fleet sees the canary advert.
    let canary_query = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "canary".into(),
        current_version: "1.10.29".into(),
    });
    match canary_query.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(
                r.update_available,
                "canary host must receive the canary advert"
            );
            let a = r.advert.expect("advert");
            assert_eq!(a.track, "canary");
            assert_eq!(a.latest_version, "1.11.0");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    // Now publish a slower stable release (1.10.30 < 1.11.0). The canary
    // host's request for canary still returns 1.11.0 (per-track isolation),
    // and the stable host now sees 1.10.30.
    let stable_advert = proto::VersionAdvert {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        latest_version: "1.10.30".into(),
        download_url: "https://example/stable".into(),
        signature: vec![0xAB; 64],
        published_at_unix: 0,
    };
    let _ = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(stable_advert),
        binary_blob: vec![0xEE; 1024],
        operator_signature: vec![0xFF; 64],
    });

    let stable_query2 = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        current_version: "1.10.29".into(),
    });
    match stable_query2.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(r.update_available);
            let a = r.advert.expect("advert");
            assert_eq!(a.track, "stable");
            assert_eq!(a.latest_version, "1.10.30");
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }

    let canary_query2 = srv.handle_query_version(proto::QueryVersionRequest {
        platform: "windows-msvc".into(),
        track: "canary".into(),
        current_version: "1.10.29".into(),
    });
    match canary_query2.union {
        Some(proto::rendezvous_message::Union::QueryVersionResponse(r)) => {
            assert!(r.update_available);
            let a = r.advert.expect("advert");
            assert_eq!(a.track, "canary");
            assert_eq!(
                a.latest_version, "1.11.0",
                "canary host must still see 1.11.0, not the slower stable 1.10.30"
            );
        }
        other => panic!("expected QueryVersionResponse, got {:?}", other),
    }
}

/// rsh-5264.5: register a peer with auto_upgrade=true on canary track and
/// verify the rdv server stores + forwards those fields in ListPeers.
#[tokio::test]
async fn rsh_5264_5_register_peer_track_and_auto_upgrade_round_trip() {
    use crate::proto;
    use std::collections::HashMap;
    use std::sync::Mutex;

    let srv = RendezvousServer::new("", "relay.test:21117");
    let peers: Mutex<HashMap<String, super::server::PeerEntry>> = Mutex::new(HashMap::new());
    let src: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();

    let rp = proto::RegisterPeer {
        id: "10000001".into(),
        serial: 0,
        group_hash: String::new(),
        hostname: "canary-1".into(),
        platform: "windows".into(),
        service_port: 8822,
        encrypted_net_info: vec![],
        ports: vec![],
        current_version: "1.10.29".into(),
        last_update_status: "success".into(),
        last_update_at_unix: 1700000000,
        track: "canary".into(),
        auto_upgrade: true,
    };

    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RegisterPeer(rp)),
    };
    let _ = srv.handle_message(msg, src, &peers);

    // Now ListPeers (with empty key, since srv was constructed with key="").
    let lp = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::ListPeers(
            proto::ListPeers {
                licence_key: "".into(),
            },
        )),
    };
    let resp = srv.handle_message(lp, src, &peers).expect("response");
    match resp.union {
        Some(proto::rendezvous_message::Union::ListPeersResponse(r)) => {
            assert_eq!(r.peers.len(), 1);
            let p = &r.peers[0];
            assert_eq!(p.device_id, "10000001");
            assert_eq!(p.track, "canary");
            assert!(p.auto_upgrade, "auto_upgrade must round-trip");
            assert_eq!(p.current_version, "1.10.29");
        }
        other => panic!("expected ListPeersResponse, got {:?}", other),
    }
}

// --- rsh-5264.6 FetchBinary tests ------------------------------------------

/// rsh-5264.6: build a minimal `Client` for tests — only `servers` is set,
/// other fields are empty/zero (publish/query/fetch only need `servers`).
#[allow(dead_code)]
fn build_test_client(servers: Vec<String>) -> super::protocol::Client {
    super::protocol::Client {
        servers,
        licence_key: String::new(),
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
        encrypted_net_info: Vec::new(),
        enrollment_token: String::new(),
        tray_port: 0,
        ports: Vec::new(),
        current_version: String::new(),
        last_update_status: String::new(),
        last_update_at_unix: 0,
        track: String::new(),
        auto_upgrade: false,
    }
}


/// rsh-5264.6: fetch_binary returns the inline blob stored at publish time.
#[tokio::test]
async fn rdv_fetch_binary_returns_published_blob() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let blob: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
    let sig = vec![0xAB; 64];

    // Publish with inline blob.
    let _ = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "windows-msvc".into(),
            track: "stable".into(),
            latest_version: "1.10.32".into(),
            download_url: String::new(),
            signature: sig.clone(),
            published_at_unix: 0,
        }),
        binary_blob: blob.clone(),
        operator_signature: vec![0xDD; 64],
    });

    // Fetch by exact version.
    let resp = srv.handle_fetch_binary(proto::FetchBinaryRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        version: "1.10.32".into(),
    });
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(r)) => {
            assert!(r.found, "blob must be found, error: {}", r.error_message);
            assert_eq!(r.binary_blob, blob, "blob bytes must round-trip exactly");
            assert_eq!(r.signature, sig, "signature must match advert");
            assert!(r.error_message.is_empty());
        }
        other => panic!("expected FetchBinaryResponse, got {:?}", other),
    }
}

/// rsh-5264.6: fetch_binary returns found=false when no advert is published
/// for (platform, track).
#[tokio::test]
async fn rdv_fetch_binary_no_advert() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let resp = srv.handle_fetch_binary(proto::FetchBinaryRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        version: "1.0.0".into(),
    });
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(r)) => {
            assert!(!r.found);
            assert!(r.binary_blob.is_empty());
            assert!(r.error_message.contains("no advert"));
        }
        other => panic!("expected FetchBinaryResponse, got {:?}", other),
    }
}

/// rsh-5264.6: fetch_binary returns found=false with version-mismatch error
/// when caller asks for a version other than the published one.
#[tokio::test]
async fn rdv_fetch_binary_version_mismatch() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let _ = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "windows-msvc".into(),
            track: "stable".into(),
            latest_version: "1.10.32".into(),
            download_url: String::new(),
            signature: vec![0xAB; 64],
            published_at_unix: 0,
        }),
        binary_blob: vec![0xCC; 1024],
        operator_signature: vec![],
    });

    let resp = srv.handle_fetch_binary(proto::FetchBinaryRequest {
        platform: "windows-msvc".into(),
        track: "stable".into(),
        version: "1.10.99".into(), // mismatched
    });
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(r)) => {
            assert!(!r.found);
            assert!(
                r.error_message.contains("version mismatch"),
                "got: {}",
                r.error_message
            );
        }
        other => panic!("expected FetchBinaryResponse, got {:?}", other),
    }
}

/// rsh-5264.6: fetch_binary returns found=false when advert was published
/// with --no-blob (binary_blob is empty).
#[tokio::test]
async fn rdv_fetch_binary_no_blob_published() {
    let srv = RendezvousServer::new("", "relay.test:21117");
    let _ = srv.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "linux-glibc".into(),
            track: "stable".into(),
            latest_version: "1.10.32".into(),
            download_url: "https://example/bin".into(),
            signature: vec![0xAB; 64],
            published_at_unix: 0,
        }),
        binary_blob: Vec::new(), // --no-blob equivalent
        operator_signature: vec![],
    });

    let resp = srv.handle_fetch_binary(proto::FetchBinaryRequest {
        platform: "linux-glibc".into(),
        track: "stable".into(),
        version: "1.10.32".into(),
    });
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(r)) => {
            assert!(!r.found);
            assert!(
                r.error_message.contains("no inline binary_blob"),
                "got: {}",
                r.error_message
            );
        }
        other => panic!("expected FetchBinaryResponse, got {:?}", other),
    }
}

/// rsh-5264.6: clone_for_tcp produces a server that shares the version_adverts
/// HashMap — publishes via the original are visible from the clone (and vice
/// versa). This is critical because the TCP listener task uses a clone to
/// dispatch FetchBinary requests.
#[tokio::test]
async fn rdv_clone_for_tcp_shares_version_adverts() {
    let original = RendezvousServer::new("", "relay.test:21117");
    let clone = original.clone_for_tcp();

    let _ = original.handle_publish_version(proto::PublishVersionRequest {
        advert: Some(proto::VersionAdvert {
            platform: "macos".into(),
            track: "stable".into(),
            latest_version: "1.10.32".into(),
            download_url: String::new(),
            signature: vec![0xEE; 64],
            published_at_unix: 0,
        }),
        binary_blob: vec![0xFF; 4096],
        operator_signature: vec![],
    });

    // The clone must see the publish via the shared Arc<Mutex<HashMap>>.
    let resp = clone.handle_fetch_binary(proto::FetchBinaryRequest {
        platform: "macos".into(),
        track: "stable".into(),
        version: "1.10.32".into(),
    });
    match resp.union {
        Some(proto::rendezvous_message::Union::FetchBinaryResponse(r)) => {
            assert!(
                r.found,
                "clone must see publishes from original via shared Arc"
            );
            assert_eq!(r.binary_blob.len(), 4096);
        }
        other => panic!("expected FetchBinaryResponse, got {:?}", other),
    }
}

// --- rsh-5264.6 TCP transport end-to-end test ------------------------------

/// rsh-5264.6: full TCP roundtrip — start a real RendezvousServer, publish
/// a small advert via the UDP path, then fetch the blob via the TCP path
/// using `Client::fetch_binary`.
#[tokio::test]
async fn rdv_fetch_binary_over_tcp_e2e() {
    use super::protocol::VersionAdvert;

    // Bind to ephemeral port for both UDP and TCP (server uses same port).
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp_sock.local_addr().unwrap().port();
    drop(udp_sock); // free for the server to rebind

    let addr = format!("127.0.0.1:{}", port);
    let addr_clone = addr.clone();
    tokio::spawn(async move {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let _ = srv.listen_and_serve(&addr_clone).await;
    });

    // Wait for the server to be ready.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sig = vec![0x42; 64];

    // Publish via TCP (blob > 32 KB threshold? No, 8 KB → UDP path. Force a
    // larger blob to exercise TCP publish path.)
    let big_blob: Vec<u8> = vec![0xAB; 64 * 1024]; // 64 KB > TCP threshold
    let advert = VersionAdvert {
        platform: "windows-msvc".to_string(),
        track: "stable".to_string(),
        latest_version: "1.10.32".to_string(),
        download_url: String::new(),
        signature: sig.clone(),
        published_at_unix: 0,
    };
    let publisher = build_test_client(vec![addr.clone()]);
    publisher
        .publish_version(advert.clone(), big_blob.clone(), vec![])
        .await
        .expect("publish over TCP must succeed");

    // Fetch via TCP.
    let fetcher = build_test_client(vec![addr.clone()]);
    let (got_blob, got_sig) = fetcher
        .fetch_binary("windows-msvc", "stable", "1.10.32")
        .await
        .expect("fetch over TCP must succeed");

    assert_eq!(got_blob, big_blob, "blob must round-trip via TCP exactly");
    assert_eq!(got_sig, sig, "signature must match");

    // Also verify a smaller blob via TCP-published path (UDP threshold edge).
    let small_blob = vec![0xCD; 1024];
    let advert_small = VersionAdvert {
        platform: "linux-glibc".to_string(),
        track: "canary".to_string(),
        latest_version: "1.10.32".to_string(),
        download_url: String::new(),
        signature: vec![0x99; 64],
        published_at_unix: 0,
    };
    publisher
        .publish_version(advert_small, small_blob.clone(), vec![])
        .await
        .expect("publish (UDP path, small blob) must succeed");

    let (got_small, _) = fetcher
        .fetch_binary("linux-glibc", "canary", "1.10.32")
        .await
        .expect("fetch small blob via TCP must succeed");
    assert_eq!(got_small, small_blob);
}
