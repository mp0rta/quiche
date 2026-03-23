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
//       documentation and/or other materials provided with the distribution.
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

use super::InboundFrame;
use crate::buf_factory::BufFactory;
use crate::buf_factory::PooledDgram;
use crate::quic::QuicheConnection;
use quiche::h3::NameValue;
use quiche::h3::{
    self,
};

/// The `capsule-protocol` structured field value indicating the Capsule
/// Protocol is in use on the stream (RFC 9297 Section 3.4).
pub const CAPSULE_PROTOCOL_HEADER_NAME: &[u8] = b"capsule-protocol";
pub const CAPSULE_PROTOCOL_HEADER_VALUE: &[u8] = b"?1";

/// Result of inspecting request headers for DATAGRAM/Capsule-Protocol usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowInfo {
    /// The Quarter Stream ID used as the DATAGRAM flow identifier.
    pub flow_id: u64,
    /// Whether the request uses the Capsule Protocol.
    pub capsule_protocol: bool,
    /// Whether this is a CONNECT-IP request (vs CONNECT-UDP).
    pub is_connect_ip: bool,
    /// Whether datagrams on this flow carry a Context ID varint after the
    /// Quarter Stream ID (RFC 9298 §5, RFC 9484 §6). False for legacy
    /// draft CONNECT-UDP which predates the Context ID mechanism.
    pub has_context_id: bool,
}

/// Returns `true` if the headers indicate Capsule Protocol usage but
/// also contain Content-Length, Content-Type, or Transfer-Encoding,
/// which is forbidden by RFC 9297 Section 3.2.
pub(crate) fn has_capsule_header_conflict(headers: &[h3::Header]) -> bool {
    let mut has_capsule_protocol = false;
    let mut has_forbidden = false;

    for header in headers {
        match header.name() {
            b"capsule-protocol" => {
                has_capsule_protocol = header.value() == b"?1";
            },
            b"content-length" | b"content-type" | b"transfer-encoding" => {
                has_forbidden = true;
            },
            _ => {},
        }
    }

    has_capsule_protocol && has_forbidden
}

/// Extracts the DATAGRAM flow ID proxied over the given `stream_id`,
/// or `None` if this is not a proxy request.
pub(crate) fn extract_flow_id(
    stream_id: u64, headers: &[h3::Header],
) -> Option<u64> {
    extract_flow_info(stream_id, headers).map(|info| info.flow_id)
}

/// Extracts full flow information from request headers, including
/// Capsule-Protocol and protocol type detection.
pub(crate) fn extract_flow_info(
    stream_id: u64, headers: &[h3::Header],
) -> Option<FlowInfo> {
    let mut method = None;
    let mut datagram_flow_id: Option<u64> = None;
    let mut protocol = None;
    let mut has_capsule_protocol = false;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b"datagram-flow-id" =>
                datagram_flow_id = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|v| v.parse().ok()),
            b"capsule-protocol" => {
                // RFC 9297 Section 3.4: value is a boolean structured field
                // "?1" or "?0"
                has_capsule_protocol = header.value() == b"?1";
            },
            _ => {},
        };
    }

    // draft-ietf-masque-connect-udp-03 CONNECT-UDP
    if method == Some(b"CONNECT-UDP") && datagram_flow_id.is_some() {
        Some(FlowInfo {
            flow_id: datagram_flow_id.unwrap(),
            capsule_protocol: has_capsule_protocol,
            is_connect_ip: false,
            // Draft predates Context ID; datagrams carry only flow_id + payload.
            has_context_id: false,
        })
    // RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP
    } else if method == Some(b"CONNECT") && protocol.is_some() {
        let proto = protocol.unwrap();
        let is_connect_ip = proto == b"connect-ip";
        let is_connect_udp = proto == b"connect-udp";

        if is_connect_udp || is_connect_ip {
            // RFC 9297: use the quarter_stream_id
            Some(FlowInfo {
                flow_id: stream_id / 4,
                // CONNECT-IP always uses Capsule Protocol (RFC 9484 Section 4)
                capsule_protocol: has_capsule_protocol || is_connect_ip,
                is_connect_ip,
                // RFC 9298 §5 / RFC 9484 §6: Context ID follows Quarter
                // Stream ID in all QUIC DATAGRAM frames.
                has_context_id: true,
            })
        } else {
            None
        }
    } else {
        None
    }
}

/// Sends an HTTP/3 datagram over the QUIC connection with the given `flow_id`.
pub(crate) fn send_h3_dgram(
    conn: &mut QuicheConnection, flow_id: u64, mut dgram: PooledDgram,
) -> quiche::Result<()> {
    let mut prefix = [0u8; 8];
    let mut buf = octets::OctetsMut::with_slice(&mut prefix);
    let flow_id = buf.put_varint(flow_id)?;

    if dgram.add_prefix(flow_id) {
        conn.dgram_send(&dgram)
    } else {
        let mut inner = dgram.into_inner().into_vec();
        inner.splice(..0, flow_id.iter().copied());
        conn.dgram_send_vec(inner)
    }
}

/// Sends a CONNECT-IP datagram (RFC 9484) with a Context ID prefix.
///
/// Wire format: Quarter Stream ID (varint) + Context ID (varint) + payload.
pub(crate) fn send_connect_ip_dgram(
    conn: &mut QuicheConnection, flow_id: u64, context_id: u64,
    mut dgram: PooledDgram,
) -> quiche::Result<()> {
    // Build prefix: flow_id varint + context_id varint
    let mut prefix = [0u8; 16];
    let prefix_len = {
        let mut buf = octets::OctetsMut::with_slice(&mut prefix);
        buf.put_varint(flow_id)?;
        buf.put_varint(context_id)?;
        buf.off()
    };
    let prefix_bytes = &prefix[..prefix_len];

    if dgram.add_prefix(prefix_bytes) {
        conn.dgram_send(&dgram)
    } else {
        let mut inner = dgram.into_inner().into_vec();
        inner.splice(..0, prefix_bytes.iter().copied());
        conn.dgram_send_vec(inner)
    }
}

/// Reads the next CONNECT-IP datagram (RFC 9484) from the QUIC connection.
///
/// Returns `(flow_id, context_id, payload)`.
pub(crate) fn receive_connect_ip_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, u64, InboundFrame)> {
    let dgram = conn.dgram_recv_vec()?;
    let mut buf = octets::Octets::with_slice(&dgram);

    let flow_id = buf
        .get_varint()
        .map_err(|_| quiche::Error::InvalidFrame)?;

    if flow_id > MAX_QUARTER_STREAM_ID {
        return Err(quiche::Error::InvalidFrame);
    }

    let context_id = buf
        .get_varint()
        .map_err(|_| quiche::Error::InvalidFrame)?;

    let advance = buf.off();
    let datagram =
        InboundFrame::Datagram(BufFactory::dgram_from_slice(&dgram[advance..]));

    Ok((flow_id, context_id, datagram))
}

/// The maximum valid Quarter Stream ID value per RFC 9297 Section 2.1.
/// Quarter Stream IDs larger than 2^60-1 are invalid.
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 60) - 1;

/// Maximum UDP Proxying Payload length for Context ID 0 (RFC 9298 §5).
/// Derived from the maximum UDP payload: 65535 − 8 (UDP header) = 65527.
pub(crate) const MAX_UDP_PAYLOAD_SIZE: usize = 65527;

/// Strips the Context ID varint prefix from a datagram payload
/// (RFC 9298 §5, RFC 9484 §6). Returns the Context ID and the
/// remaining payload as an [`InboundFrame`].
///
/// Returns `quiche::Error::InvalidFrame` if the Context ID cannot be parsed.
pub(crate) fn strip_context_id(
    frame: InboundFrame,
) -> Result<(u64, InboundFrame), quiche::Error> {
    match frame {
        InboundFrame::Datagram(dgram) => {
            let buf = dgram.as_ref();
            let mut oct = octets::Octets::with_slice(buf);
            let context_id = oct
                .get_varint()
                .map_err(|_| quiche::Error::InvalidFrame)?;
            let off = oct.off();
            let payload = BufFactory::dgram_from_slice(&buf[off..]);
            Ok((context_id, InboundFrame::Datagram(payload)))
        },
        other => Ok((0, other)),
    }
}

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
///
/// Returns `quiche::Error::InvalidFrame` if the Quarter Stream ID is
/// malformed or exceeds 2^60-1 (RFC 9297 Section 2.1).
pub(crate) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, InboundFrame)> {
    let dgram = conn.dgram_recv_vec()?;
    let mut buf = octets::Octets::with_slice(&dgram);

    // RFC 9297 Section 2.1: payload too short to parse Quarter Stream ID
    // MUST be treated as H3_DATAGRAM_ERROR.
    let flow_id = buf
        .get_varint()
        .map_err(|_| quiche::Error::InvalidFrame)?;

    // RFC 9297 Section 2.1: Quarter Stream ID > 2^60-1 MUST be treated
    // as H3_DATAGRAM_ERROR.
    if flow_id > MAX_QUARTER_STREAM_ID {
        return Err(quiche::Error::InvalidFrame);
    }

    let advance = buf.off();
    let datagram =
        InboundFrame::Datagram(BufFactory::dgram_from_slice(&dgram[advance..]));

    Ok((flow_id, datagram))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_info_connect_udp_draft() {
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
            h3::Header::new(b"datagram-flow-id", b"42"),
        ];
        let info = extract_flow_info(0, &headers).unwrap();
        assert_eq!(info.flow_id, 42);
        assert!(!info.capsule_protocol);
        assert!(!info.is_connect_ip);
        assert!(!info.has_context_id); // draft predates Context ID
    }

    #[test]
    fn flow_info_connect_udp_rfc9298() {
        // RFC 9298: CONNECT method with :protocol = connect-udp
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-udp"),
        ];
        let info = extract_flow_info(4, &headers).unwrap();
        assert_eq!(info.flow_id, 1); // quarter_stream_id = 4 / 4
        assert!(!info.capsule_protocol);
        assert!(!info.is_connect_ip);
        assert!(info.has_context_id); // RFC 9298 §5
    }

    #[test]
    fn flow_info_connect_ip() {
        // RFC 9484: CONNECT method with :protocol = connect-ip
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-ip"),
        ];
        let info = extract_flow_info(8, &headers).unwrap();
        assert_eq!(info.flow_id, 2); // quarter_stream_id = 8 / 4
        assert!(info.capsule_protocol); // always true for CONNECT-IP
        assert!(info.is_connect_ip);
        assert!(info.has_context_id); // RFC 9484 §6
    }

    #[test]
    fn flow_info_connect_ip_implicit_capsule_protocol() {
        // CONNECT-IP sets capsule_protocol=true even without the header
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-ip"),
        ];
        let info = extract_flow_info(0, &headers).unwrap();
        assert!(info.capsule_protocol);
    }

    #[test]
    fn flow_info_connect_ip_with_explicit_capsule_header() {
        // CONNECT-IP with explicit capsule-protocol: ?1 — still true
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-ip"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        let info = extract_flow_info(0, &headers).unwrap();
        assert!(info.capsule_protocol);
        assert!(info.is_connect_ip);
    }

    #[test]
    fn flow_info_capsule_protocol_enabled() {
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-udp"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        let info = extract_flow_info(0, &headers).unwrap();
        assert!(info.capsule_protocol);
    }

    #[test]
    fn flow_info_capsule_protocol_disabled() {
        // capsule-protocol: ?0 means NOT using capsule protocol
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-udp"),
            h3::Header::new(b"capsule-protocol", b"?0"),
        ];
        let info = extract_flow_info(0, &headers).unwrap();
        assert!(!info.capsule_protocol);
    }

    #[test]
    fn flow_info_non_proxy_request() {
        let headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"/"),
        ];
        assert!(extract_flow_info(0, &headers).is_none());
    }

    #[test]
    fn flow_info_connect_unknown_protocol() {
        // CONNECT with an unrecognized :protocol should return None
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"websocket"),
        ];
        assert!(extract_flow_info(0, &headers).is_none());
    }

    #[test]
    fn flow_info_connect_without_protocol() {
        // Plain CONNECT (no :protocol) is not a proxy request
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
        ];
        assert!(extract_flow_info(0, &headers).is_none());
    }

    #[test]
    fn flow_id_delegates_to_flow_info() {
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-udp"),
        ];
        assert_eq!(extract_flow_id(12, &headers), Some(3)); // 12 / 4 = 3
    }

    #[test]
    fn flow_info_draft_connect_udp_without_flow_id() {
        // CONNECT-UDP without datagram-flow-id → None
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
        ];
        assert!(extract_flow_info(0, &headers).is_none());
    }

    #[test]
    fn flow_info_draft_connect_udp_invalid_flow_id() {
        // CONNECT-UDP with non-numeric datagram-flow-id → None
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT-UDP"),
            h3::Header::new(b"datagram-flow-id", b"not-a-number"),
        ];
        assert!(extract_flow_info(0, &headers).is_none());
    }

    #[test]
    fn max_quarter_stream_id_value() {
        assert_eq!(MAX_QUARTER_STREAM_ID, (1u64 << 60) - 1);
    }

    #[test]
    fn capsule_header_conflict_content_length() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_header_conflict_content_type() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"content-type", b"application/octet-stream"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn capsule_header_conflict_transfer_encoding() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"transfer-encoding", b"chunked"),
        ];
        assert!(has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_without_capsule_protocol() {
        // Content-Length without capsule-protocol is fine
        let headers = vec![
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_capsule_disabled() {
        // capsule-protocol: ?0 with content-length is fine
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?0"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_clean() {
        // capsule-protocol: ?1 without forbidden headers is fine
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b":method", b"CONNECT"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }
}
