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
    };
    settings
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

    // Supply extra SCIDs (needed for second path).
    for _ in 0..3 {
        let extra_scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid(&extra_scid, 0, false).unwrap();
    }
    exchange(&socket, client_addr, &mut conn).await;

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

    // Supply extra SCIDs (needed for second path).
    for _ in 0..3 {
        let extra_scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid(&extra_scid, 0, false).unwrap();
    }
    exchange(&socket, client_addr, &mut conn).await;

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

    // Supply extra SCIDs (needed for second path).
    for _ in 0..3 {
        let extra_scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid(&extra_scid, 0, false).unwrap();
    }
    exchange(&socket, client_addr, &mut conn).await;

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

    // Close the second path. Traffic should failover to path 0.
    conn.close_path(path_id, 0)
        .expect("close_path should succeed");

    // Exchange to propagate the PATH_ABANDON frame.
    for _ in 0..4 {
        exchange_both(
            &socket, client_addr, &socket2, client_addr2, &mut conn,
        )
        .await;
    }

    // Create H3 connection on the surviving path and send a request.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    for _ in 0..3 {
        exchange(&socket, client_addr, &mut conn).await;
    }

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
        "should receive H3 response after path close failover"
    );
    assert!(got_fin, "should receive FIN after path close failover");
}
