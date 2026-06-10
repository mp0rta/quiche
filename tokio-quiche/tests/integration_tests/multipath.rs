// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use h3i::quiche;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::ConnectionIdGenerator as _;
use tokio_quiche::ServerH3Connection;

use crate::fixtures::*;

fn multipath_client_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_data(1_500_000);
    config.set_initial_max_stream_data_bidi_local(150_000);
    config.set_initial_max_stream_data_bidi_remote(150_000);
    config.set_initial_max_stream_data_uni(150_000);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(5);
    config.set_active_connection_id_limit(4);
    config.set_initial_max_path_id(4);
    config.set_disable_active_migration(false);
    config.verify_peer(false);
    config
}

fn multipath_server_settings() -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.max_send_udp_payload_size = 1400;
    settings.max_recv_udp_payload_size = 1400;
    settings.active_connection_id_limit = 4;
    settings.disable_active_migration = false;
    settings.multipath = tokio_quiche::MultipathSettings {
        enabled: true,
        scheduler: tokio_quiche::MultipathScheduler::MinRtt,
        max_active_paths: Some(4),
        reinjection_mode: tokio_quiche::ReinjectionMode::default(),
        auto_raise_max_path_id: None,
    };
    settings
}

/// Server settings with a small initial path-ID limit (2) and the given
/// auto-raise ceiling, for exercising the PATHS_BLOCKED → MAX_PATH_ID
/// extension loop.
fn small_limit_server_settings(
    auto_raise_max_path_id: Option<u64>,
) -> QuicSettings {
    let mut settings = multipath_server_settings();
    settings.multipath.max_active_paths = Some(2);
    settings.multipath.auto_raise_max_path_id = auto_raise_max_path_id;
    settings
}

/// Drives a bare-quiche client against a small-limit tokio-quiche server
/// until every path ID the server allows (1 and 2) is consumed and the
/// client is blocked, returning the sockets backing the consumed paths.
///
/// On return the client has a PATHS_BLOCKED(2) frame queued for the
/// server (draft-ietf-quic-multipath-21 §3.2.1).
async fn consume_all_path_ids(
    socket: &tokio::net::UdpSocket, client_addr: SocketAddr,
    server_addr: SocketAddr, conn: &mut quiche::Connection,
) -> Vec<(tokio::net::UdpSocket, SocketAddr)> {
    // Wait for the server's proactive per-path CID provisioning to fund
    // path IDs 1 and 2, then consume both.
    for _ in 0..20 {
        if conn.mp_available_dcids(1) > 0 && conn.mp_available_dcids(2) > 0 {
            break;
        }
        exchange(socket, client_addr, conn).await;
    }

    let mut extra_sockets = Vec::new();
    for expected_id in [1u64, 2] {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        assert_eq!(conn.create_path(addr, server_addr), Ok(expected_id));
        extra_sockets.push((sock, addr));
    }

    // Every path ID the server allows is consumed: the next attempt is
    // peer-limited and queues PATHS_BLOCKED carrying the limit (2).
    let blocked_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocked_sock.local_addr().unwrap();
    assert_eq!(
        conn.create_path(blocked_addr, server_addr),
        Err(quiche::Error::PathLimitExceeded)
    );

    extra_sockets
}

/// With `auto_raise_max_path_id` set on the server, a bare-quiche client
/// that consumes every allowed path ID and sends PATHS_BLOCKED gets a
/// MAX_PATH_ID raise from the server worker — with no server-application
/// intervention — and can open another path.
#[tokio::test]
async fn multipath_paths_blocked_auto_raise_unblocks_client() {
    let (url, _) = start_server_with_settings(
        small_limit_server_settings(Some(4)),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");
    assert_eq!(conn.peer_max_path_id(), 2);

    let extra =
        consume_all_path_ids(&socket, client_addr, server_addr, &mut conn)
            .await;
    let socks: Vec<_> = std::iter::once((&socket, client_addr))
        .chain(extra.iter().map(|(s, a)| (s, *a)))
        .collect();

    // The queued PATHS_BLOCKED reaches the server; its worker auto-raises
    // the limit and the MAX_PATH_ID raise comes back, without any
    // server-application involvement.
    for _ in 0..20 {
        if conn.peer_max_path_id() > 2 {
            break;
        }
        exchange_all(&socks, &mut conn).await;
    }
    assert_eq!(
        conn.peer_max_path_id(),
        4,
        "the server should auto-raise its limit to the ceiling"
    );

    // The worker's proactive CID provisioning self-heals for the newly
    // permitted path IDs; the client can then open path ID 3.
    for _ in 0..20 {
        if conn.mp_available_dcids(3) > 0 {
            break;
        }
        exchange_all(&socks, &mut conn).await;
    }
    let sock4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr4 = sock4.local_addr().unwrap();
    assert_eq!(
        conn.create_path(addr4, server_addr),
        Ok(3),
        "the client should be unblocked after the auto-raise"
    );
}

/// Without `auto_raise_max_path_id`, the server worker performs no
/// MAX_PATH_ID raise on PATHS_BLOCKED: the limit is application policy
/// and ignoring the report is spec-legal (§4.7).
#[tokio::test]
async fn multipath_paths_blocked_no_auto_raise_by_default() {
    let (url, _) = start_server_with_settings(
        small_limit_server_settings(None),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");
    assert_eq!(conn.peer_max_path_id(), 2);

    let extra =
        consume_all_path_ids(&socket, client_addr, server_addr, &mut conn)
            .await;
    let socks: Vec<_> = std::iter::once((&socket, client_addr))
        .chain(extra.iter().map(|(s, a)| (s, *a)))
        .collect();

    // The PATHS_BLOCKED reaches the server, but no raise must come back.
    for _ in 0..10 {
        exchange_all(&socks, &mut conn).await;
    }
    assert_eq!(
        conn.peer_max_path_id(),
        2,
        "the server must not raise its limit without the opt-in knob"
    );

    let sock4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr4 = sock4.local_addr().unwrap();
    assert_eq!(
        conn.create_path(addr4, server_addr),
        Err(quiche::Error::PathLimitExceeded),
        "the client must remain blocked"
    );
}

/// Emit all pending packets from a connection on a single socket (single-path).
async fn emit_flight(
    socket: &tokio::net::UdpSocket, conn: &mut quiche::Connection,
) {
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,
        Err(quiche::Error::Done) => return,
        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for (pkt, info) in flight {
        socket.send_to(&pkt, info.to).await.unwrap();
    }
}

/// Receive packets from a socket with a timeout to avoid hanging.
async fn process_flight(
    socket: &tokio::net::UdpSocket, local_addr: SocketAddr,
    conn: &mut quiche::Connection,
) {
    let mut buf = [0; 65535];

    match tokio::time::timeout(Duration::from_millis(200), socket.readable())
        .await
    {
        Ok(Ok(())) => {},
        _ => return,
    }

    loop {
        let (len, from) = match socket.try_recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("failed to receive packets: {e:?}"),
        };
        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from,
        };
        let _ = conn.recv(&mut buf[..len], recv_info);
    }
}

/// Emit + receive on a single socket (single-path exchange).
async fn exchange(
    socket: &tokio::net::UdpSocket, local_addr: SocketAddr,
    conn: &mut quiche::Connection,
) {
    emit_flight(socket, conn).await;
    process_flight(socket, local_addr, conn).await;
}

/// Emit all pending packets, routing each to the correct socket based on
/// `SendInfo.from`. Then receive on both sockets.
///
/// This is the key fix: `emit_flight()` drains ALL paths and each packet's
/// `SendInfo.from` tells us which local address (and therefore socket) to
/// use. Sending all packets through socket1 would break path validation
/// for path 1.
async fn exchange_both(
    sock1: &tokio::net::UdpSocket, addr1: SocketAddr,
    sock2: &tokio::net::UdpSocket, addr2: SocketAddr,
    conn: &mut quiche::Connection,
) {
    // Drain all paths at once — each packet carries its own SendInfo.
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,
        Err(quiche::Error::Done) => vec![],
        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for (pkt, info) in flight {
        // Route to the correct socket based on the source address.
        if info.from == addr2 {
            sock2.send_to(&pkt, info.to).await.unwrap();
        } else {
            sock1.send_to(&pkt, info.to).await.unwrap();
        }
    }

    // Receive on both sockets with timeout.
    process_flight(sock1, addr1, conn).await;
    process_flight(sock2, addr2, conn).await;
}

/// Emit all pending packets, routing each to the socket matching its
/// `SendInfo.from` address (defaulting to the first socket), then receive
/// on every socket.
async fn exchange_all(
    socks: &[(&tokio::net::UdpSocket, SocketAddr)], conn: &mut quiche::Connection,
) {
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,
        Err(quiche::Error::Done) => vec![],
        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for (pkt, info) in flight {
        let (sock, _) = socks
            .iter()
            .find(|(_, addr)| *addr == info.from)
            .unwrap_or(&socks[0]);
        sock.send_to(&pkt, info.to).await.unwrap();
    }

    for (sock, addr) in socks {
        process_flight(sock, *addr, conn).await;
    }
}

/// Waits for the tokio-quiche server's proactive per-path CID provisioning
/// (draft-ietf-quic-multipath-21 §3.2.1) to fund our DCID pool for
/// `path_id`, then issues one of our own CIDs for that path ID so the
/// server can send on it too.
///
/// No legacy (path ID 0) CIDs are exchanged: opening the path relies
/// entirely on the per-path pools.
async fn prepare_path(
    socket: &tokio::net::UdpSocket, local_addr: SocketAddr,
    conn: &mut quiche::Connection, path_id: u64,
) {
    for _ in 0..20 {
        if conn.mp_available_dcids(path_id) > 0 {
            break;
        }
        exchange(socket, local_addr, conn).await;
    }
    assert!(
        conn.mp_available_dcids(path_id) > 0,
        "server should proactively fund our path {path_id} DCID pool"
    );

    let scid = SimpleConnectionIdGenerator.new_connection_id();
    conn.new_scid_on_path(path_id, &scid, 0, false).unwrap();
    exchange(socket, local_addr, conn).await;
}

fn drain_h3_events(
    h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection,
) -> (bool, bool) {
    let mut buf = [0; 65535];
    let mut got_headers = false;

    loop {
        match h3_conn.poll(conn) {
            Ok((_, quiche::h3::Event::Headers { .. })) => got_headers = true,
            Ok((stream_id, quiche::h3::Event::Data)) => {
                while h3_conn.recv_body(conn, stream_id, &mut buf).is_ok() {}
            },
            Ok((_, quiche::h3::Event::Finished)) =>
                return (got_headers, true),
            _ => return (got_headers, false),
        }
    }
}

/// Tests multipath negotiation and an H3 request over the initial path with a
/// multipath-enabled tokio-quiche server.
#[tokio::test]
async fn multipath_negotiation_and_h3_request() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    exchange(&socket, client_addr, &mut conn).await;

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..5 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(got_headers, "should receive response headers");
    assert!(got_fin, "should receive FIN");
}

/// Tests that a second path can be created, validated, and used to
/// successfully transfer H3 data with a tokio-quiche server.
#[tokio::test]
async fn multipath_two_path_h3_transfer() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    // Handshake on path 0.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Wait for the server's proactive per-path CIDs and fund the reverse
    // direction of path 1 (needed for the second path).
    prepare_path(&socket, client_addr, &mut conn, 1).await;

    // Create second path from a new local address.
    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();

    let path_id = conn
        .create_path(client_addr2, server_addr)
        .expect("create_path should succeed");
    assert!(path_id > 0, "second path should have non-zero path_id");

    // Exchange PATH_CHALLENGE/RESPONSE to validate the new path.
    for _ in 0..6 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Verify we have multiple paths.
    let path_stats: Vec<_> = conn.path_stats().collect();
    assert!(
        path_stats.len() >= 2,
        "should have at least 2 paths, got {}",
        path_stats.len()
    );

    // Create H3 connection and exchange settings over both paths.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Send H3 request — the scheduler may route data over either path.
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..8 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(got_headers, "should receive H3 response headers via multipath");
    assert!(got_fin, "should receive FIN via multipath");
}

/// Tests that the server can dynamically add a socket and the client can
/// create a path to the server's new address for multipath H3 transfer.
#[tokio::test]
async fn multipath_server_dynamic_socket() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    // Channel for the server to communicate its new address to the client.
    let (addr_tx, mut addr_rx) =
        tokio::sync::mpsc::channel::<SocketAddr>(1);
    let ready = Arc::new(Notify::new());
    let ready_clone = ready.clone();

    let handler = move |mut connection: ServerH3Connection| {
        let addr_tx = addr_tx.clone();
        let ready = ready_clone.clone();
        async move {
            let mp = connection
                .quic_connection
                .multipath_handle()
                .expect("multipath handle should be available")
                .clone();

            let new_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .unwrap();
            let new_addr = new_socket.local_addr().unwrap();
            mp.add_socket(new_socket, new_addr).await.unwrap();

            // Tell the client about the new address.
            addr_tx.send(new_addr).await.unwrap();

            // Wait for the client to signal it has created the path and
            // exchanged enough packets.
            ready.notified().await;

            let _ = serve_connection_details(
                &mut connection.h3_controller,
                Default::default(),
            )
            .await;
        }
    };

    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handler,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    // Handshake on path 0.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Wait for the server's proactive per-path CIDs and fund the reverse
    // direction of path 1 (needed for the second path).
    prepare_path(&socket, client_addr, &mut conn, 1).await;

    // Wait for the server to report its new address.
    let server_addr2 = tokio::time::timeout(
        Duration::from_secs(2),
        addr_rx.recv(),
    )
    .await
    .expect("timeout waiting for server address")
    .expect("server address channel closed");

    // Client creates a path to the server's new address.
    let path_id = conn
        .create_path(client_addr, server_addr2)
        .expect("create_path to server's new address should succeed");
    assert!(path_id > 0, "second path should have non-zero path_id");

    // Signal the server that it can start serving H3.
    ready.notify_one();

    // Exchange packets to validate the new path. The server's recv task
    // on the new socket will feed incoming packets to the IoWorker.
    for _ in 0..8 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    // Verify we have multiple paths.
    let path_stats: Vec<_> = conn.path_stats().collect();
    assert!(
        path_stats.len() >= 2,
        "should have at least 2 paths, got {}",
        path_stats.len()
    );

    // Create H3 connection and exchange settings.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    // Send H3 request.
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..8 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(
        got_headers,
        "should receive response headers with server dynamic socket"
    );
    assert!(got_fin, "should receive FIN with server dynamic socket");
}

/// Tests that closing a path triggers automatic resource cleanup on the
/// server, and the connection continues to work on the remaining path.
#[tokio::test]
async fn multipath_path_close_failover() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    // Handshake on path 0.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Wait for the server's proactive per-path CIDs and fund the reverse
    // direction of path 1 (needed for the second path).
    prepare_path(&socket, client_addr, &mut conn, 1).await;

    // Create second path from a new local address.
    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();

    let path_id = conn
        .create_path(client_addr2, server_addr)
        .expect("create_path should succeed");

    // Validate the second path.
    for _ in 0..6 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    let path_stats: Vec<_> = conn.path_stats().collect();
    assert!(
        path_stats.len() >= 2,
        "should have at least 2 paths before close, got {}",
        path_stats.len()
    );

    // Create H3 connection before closing the path to ensure H3 settings
    // are exchanged while both paths are available.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Close the second path. Traffic should failover to path 0.
    conn.close_path(path_id, 0)
        .expect("close_path should succeed");

    // Exchange on both sockets to propagate the PATH_ABANDON frame and
    // drain any in-flight packets the server may still send on path 1.
    for _ in 0..6 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
        while let Some(_ev) = conn.path_event_next() {}
    }

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..12 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(
        got_headers,
        "should receive H3 response after path close failover"
    );
    assert!(got_fin, "should receive FIN after path close failover");
}

/// Tests runtime scheduler switching and path stats querying via the
/// MultipathHandle API on the server side.
#[tokio::test]
async fn multipath_runtime_scheduler_switch() {
    use std::sync::Arc;
    use tokio::sync::Barrier;

    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();

    let handler = move |mut connection: ServerH3Connection| {
        let barrier = barrier_clone.clone();
        async move {
            let mp = connection
                .quic_connection
                .multipath_handle()
                .expect("multipath handle should be available")
                .clone();

            // Query path stats before scheduler switch.
            let stats = mp.path_stats().await.expect("path_stats should succeed");
            assert!(!stats.is_empty(), "should have at least one path");

            // Switch from MinRtt (default) to RoundRobin.
            mp.set_scheduler(
                quiche::multipath::scheduler::MultipathSchedulerAlgorithm::RoundRobin,
            )
            .await
            .expect("set_scheduler to RoundRobin should succeed");

            // Switch back to MinRtt.
            mp.set_scheduler(
                quiche::multipath::scheduler::MultipathSchedulerAlgorithm::MinRtt,
            )
            .await
            .expect("set_scheduler back to MinRtt should succeed");

            // Signal the client that scheduler switching is done.
            barrier.wait().await;

            // Now serve the H3 request.
            let _ = serve_connection_details(
                &mut connection.h3_controller,
                Default::default(),
            )
            .await;
        }
    };

    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handler,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    // Handshake.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Wait for the server to finish scheduler switching.
    tokio::time::timeout(Duration::from_secs(2), barrier.wait())
        .await
        .expect("server should complete scheduler switching within timeout");

    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    exchange(&socket, client_addr, &mut conn).await;

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..8 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(
        got_headers,
        "should receive H3 response after scheduler switch"
    );
    assert!(got_fin, "should receive FIN after scheduler switch");
}

/// Verifies that a second path is properly validated and both paths carry
/// traffic. Uses per-path `sent` counters on the client side with RoundRobin
/// scheduler to confirm the client distributes traffic.
#[tokio::test]
async fn multipath_both_paths_carry_traffic() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();
    // RoundRobin ensures client distributes across both paths.
    client_config.set_multipath_scheduler(
        quiche::multipath::scheduler::MultipathSchedulerAlgorithm::RoundRobin,
    );

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }

    prepare_path(&socket, client_addr, &mut conn, 1).await;

    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();

    conn.create_path(client_addr2, server_addr)
        .expect("create_path should succeed");

    // Exchange until the second path is validated.
    let mut path1_validated = false;
    for _ in 0..15 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
        while let Some(ev) = conn.path_event_next() {
            if matches!(ev, quiche::PathEvent::Validated(..)) {
                path1_validated = true;
            }
        }
        if path1_validated {
            break;
        }
    }
    assert!(path1_validated, "path 1 should be validated");

    // Both paths should now be active.
    let stats: Vec<_> = conn.path_stats().collect();
    assert!(stats.len() >= 2, "should have 2+ paths");

    // Snapshot sent counts before H3 transfer.
    let sent_before: Vec<usize> = stats.iter().map(|s| s.sent).collect();

    // Create H3 connection and send request.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    for _ in 0..10 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(got_headers, "should receive H3 response headers");
    assert!(got_fin, "should receive FIN");

    // Check that both paths sent packets (RoundRobin distributes).
    let stats_after: Vec<_> = conn.path_stats().collect();
    for (i, (before, after)) in
        sent_before.iter().zip(stats_after.iter()).enumerate()
    {
        assert!(
            after.sent > *before,
            "path {} should have sent packets: before={}, after={}",
            i,
            before,
            after.sent
        );
    }
}

/// Verifies that H3 traffic continues without interruption when a path is
/// closed mid-transfer. Starts a large transfer over two paths, closes one
/// mid-way, and verifies the full response is received.
#[tokio::test]
async fn multipath_mid_transfer_path_close() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }

    prepare_path(&socket, client_addr, &mut conn, 1).await;

    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();

    let path_id = conn
        .create_path(client_addr2, server_addr)
        .expect("create_path should succeed");

    for _ in 0..6 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Create H3 and exchange settings on both paths.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Start the H3 request.
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"test.com"),
        quiche::h3::Header::new(b":path", b"/1"),
    ];
    h3_conn.send_request(&mut conn, &req, true).unwrap();

    // Exchange a few rounds on both paths (transfer starts).
    for _ in 0..3 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Close the second path mid-transfer.
    conn.close_path(path_id, 0)
        .expect("close_path should succeed");

    // Continue exchanging on the primary path only.
    for _ in 0..10 {
        exchange(&socket, client_addr, &mut conn).await;
    }

    let (got_headers, got_fin) = drain_h3_events(&mut h3_conn, &mut conn);
    assert!(
        got_headers,
        "should receive H3 response after mid-transfer path close"
    );
    assert!(
        got_fin,
        "should receive complete response after mid-transfer path close"
    );
}

/// Verifies the tokio-quiche worker proactively issues per-path CIDs for
/// every negotiated path ID (draft-ietf-quic-multipath-21 §3.2.1
/// RECOMMENDED): after the handshake the client can open path 1 AND path 2
/// without any manual CID provisioning, with each open consuming a CID
/// from its own per-path pool (the legacy pool stays untouched).
#[tokio::test]
async fn multipath_proactive_per_path_cid_provisioning() {
    let (url, _) = start_server_with_settings(
        multipath_server_settings(),
        Http3Settings::default(),
        TestConnectionHook::new(),
        handle_connection,
    );
    let server_addr = extract_host_ipv4(&url);
    let mut client_config = multipath_client_config();

    let client_scid = SimpleConnectionIdGenerator.new_connection_id();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = socket.local_addr().unwrap();

    let mut conn = quiche::connect(
        Some("test.com"),
        &client_scid,
        client_addr,
        server_addr,
        &mut client_config,
    )
    .unwrap();

    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // The server must fund our per-path DCID pools on its own: this test
    // performs NO manual CID provisioning before opening paths.
    for _ in 0..20 {
        if conn.mp_available_dcids(1) > 0 && conn.mp_available_dcids(2) > 0 {
            break;
        }
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(
        conn.mp_available_dcids(1) > 0,
        "server should proactively fund the path 1 DCID pool"
    );
    assert!(
        conn.mp_available_dcids(2) > 0,
        "server should proactively fund the path 2 DCID pool"
    );

    // Open paths 1 and 2 back-to-back. Both must consume per-path CIDs,
    // leaving the legacy (path ID 0) pool untouched.
    let legacy_dcids = conn.available_dcids();

    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();
    let path_id1 = conn
        .create_path(client_addr2, server_addr)
        .expect("opening path 1 should not need manual CID provisioning");
    assert_eq!(path_id1, 1, "lowest unused path ID is consumed first");

    let socket3 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr3 = socket3.local_addr().unwrap();
    let path_id2 = conn
        .create_path(client_addr3, server_addr)
        .expect("opening path 2 should not need manual CID provisioning");
    assert_eq!(path_id2, 2, "path IDs are consumed without holes");

    assert_eq!(
        conn.available_dcids(),
        legacy_dcids,
        "new paths must use per-path DCIDs, not legacy pool DCIDs"
    );

    // The reverse direction is the client application's responsibility
    // (the client here is a bare quiche connection): issue one CID per
    // path so the server can send on paths 1 and 2. A tokio-quiche client
    // endpoint does this automatically in its worker.
    for path_id in [1u64, 2] {
        let scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid_on_path(path_id, &scid, 0, false).unwrap();
    }

    // Both paths must reach Validated.
    let mut validated = std::collections::HashSet::new();
    for _ in 0..20 {
        exchange_all(
            &[
                (&socket, client_addr),
                (&socket2, client_addr2),
                (&socket3, client_addr3),
            ],
            &mut conn,
        )
        .await;
        while let Some(ev) = conn.path_event_next() {
            if let quiche::PathEvent::Validated(local, _) = ev {
                validated.insert(local);
            }
        }
        if validated.contains(&client_addr2) && validated.contains(&client_addr3)
        {
            break;
        }
    }
    assert!(validated.contains(&client_addr2), "path 1 should validate");
    assert!(validated.contains(&client_addr3), "path 2 should validate");
}
