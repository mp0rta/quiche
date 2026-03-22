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
    };
    settings
}

async fn emit_flight(
    socket: &tokio::net::UdpSocket, conn: &mut quiche::Connection,
) {
    let flight = match quiche::test_utils::emit_flight(conn) {
        Ok(v) => v,
        Err(quiche::Error::Done) => return,
        Err(e) => panic!("failed to emit flight: {e:?}"),
    };

    for p in flight {
        socket.send_to(&p.0, p.1.to).await.unwrap();
    }
}

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

async fn exchange(
    socket: &tokio::net::UdpSocket, local_addr: SocketAddr,
    conn: &mut quiche::Connection,
) {
    emit_flight(socket, conn).await;
    process_flight(socket, local_addr, conn).await;
}

/// Emit and receive on both sockets, with timeouts to avoid hanging.
async fn exchange_both(
    sock1: &tokio::net::UdpSocket, addr1: SocketAddr,
    sock2: &tokio::net::UdpSocket, addr2: SocketAddr,
    server_addr: SocketAddr, conn: &mut quiche::Connection,
) {
    // Emit on default path.
    emit_flight(sock1, conn).await;

    // Emit on second path.
    let flight2 = quiche::test_utils::emit_flight_on_path(
        conn,
        Some(addr2),
        Some(server_addr),
    );
    if let Ok(pkts) = flight2 {
        for p in pkts {
            sock2.send_to(&p.0, p.1.to).await.unwrap();
        }
    }

    // Receive on both sockets with timeout.
    process_flight(sock1, addr1, conn).await;
    process_flight(sock2, addr2, conn).await;
}

fn process_h3_events(
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

/// Tests multipath negotiation and H3 request over the initial path with a
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

    // Complete the handshake.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }

    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Create H3 connection.
    let h3_config = quiche::h3::Config::new().unwrap();
    let mut h3_conn =
        quiche::h3::Connection::with_transport(&mut conn, &h3_config).unwrap();

    // Exchange H3 settings.
    exchange(&socket, client_addr, &mut conn).await;

    // Send request on initial path.
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

    let (got_headers, got_fin) = process_h3_events(&mut h3_conn, &mut conn);
    assert!(got_headers, "should receive response headers");
    assert!(got_fin, "should receive FIN");
}

/// Tests that a second path can be created and validated with the server.
#[tokio::test]
async fn multipath_create_second_path() {
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

    // Complete the handshake.
    while !conn.is_established() {
        exchange(&socket, client_addr, &mut conn).await;
    }
    assert!(conn.is_multipath(), "multipath should be negotiated");

    // Supply extra SCIDs after handshake.
    for _ in 0..3 {
        let extra_scid = SimpleConnectionIdGenerator.new_connection_id();
        conn.new_scid(&extra_scid, 0, false).unwrap();
    }
    exchange(&socket, client_addr, &mut conn).await;

    // Create second path from new local address.
    let socket2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr2 = socket2.local_addr().unwrap();

    let path_id = conn
        .create_path(client_addr2, server_addr)
        .expect("create_path should succeed");
    assert!(path_id > 0, "second path should have non-zero path_id");

    // Exchange PATH_CHALLENGE/RESPONSE to validate the new path.
    for _ in 0..6 {
        exchange_both(
            &socket,
            client_addr,
            &socket2,
            client_addr2,
            server_addr,
            &mut conn,
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
}
