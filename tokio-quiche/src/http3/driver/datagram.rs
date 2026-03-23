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
    let mut method = None;
    let mut datagram_flow_id: Option<u64> = None;
    let mut protocol = None;

    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            b"datagram-flow-id" =>
                datagram_flow_id = std::str::from_utf8(header.value())
                    .ok()
                    .and_then(|v| v.parse().ok()),
            _ => {},
        };

        // We have all of the information needed to get a flow_id or
        // quarter_stream_id
        if method.is_some() && (datagram_flow_id.is_some() || protocol.is_some())
        {
            break;
        }
    }

    // draft-ietf-masque-connect-udp-03 CONNECT-UDP
    if method == Some(b"CONNECT-UDP") && datagram_flow_id.is_some() {
        datagram_flow_id
    // RFC 9298 CONNECT-UDP
    } else if method == Some(b"CONNECT") && protocol == Some(b"connect-udp") {
        // RFC 9297 Section 2.1: Quarter Stream ID
        Some(stream_id / 4)
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

/// The maximum valid Quarter Stream ID value per RFC 9297 Section 2.1.
/// Quarter Stream IDs larger than 2^60-1 are invalid.
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 60) - 1;

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
        let headers = vec![
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_capsule_disabled() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?0"),
            h3::Header::new(b"content-length", b"100"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }

    #[test]
    fn no_capsule_header_conflict_clean() {
        let headers = vec![
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b":method", b"CONNECT"),
        ];
        assert!(!has_capsule_header_conflict(&headers));
    }
}
