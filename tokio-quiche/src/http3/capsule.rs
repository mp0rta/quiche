// Copyright (C) 2025, mp0rta.
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

//! HTTP Capsule Protocol (RFC 9297) and CONNECT-IP capsule types (RFC 9484).
//!
//! This module provides encoding and decoding of capsules as defined in
//! RFC 9297 Section 3, as well as the CONNECT-IP capsule types defined in
//! RFC 9484.
//!
//! A capsule is a variable-length frame on an HTTP data stream, encoded as:
//!
//! ```text
//! Capsule {
//!   Capsule Type (i),
//!   Capsule Value Length (i),
//!   Capsule Value (..),
//! }
//! ```
//!
//! where `(i)` denotes a variable-length integer.
//!
//! The capsule protocol operates at the HTTP semantic layer, above the
//! HTTP/3 framing state machine in [`quiche::h3`]: capsules are opaque
//! information carried in the payload of DATA frames. This module
//! therefore lives in tokio-quiche rather than in the low-level `h3`
//! module, and operates on plain byte slices so it can be used with any
//! API that exposes the stream body bytes.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// Errors raised when encoding or decoding capsules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapsuleError {
    /// The provided buffer is too short.
    #[error("provided buffer is too short")]
    BufferTooShort,

    /// The capsule (or its CONNECT-IP payload) is malformed.
    #[error("invalid capsule")]
    InvalidCapsule,
}

impl From<octets::BufferTooShortError> for CapsuleError {
    fn from(_: octets::BufferTooShortError) -> Self {
        CapsuleError::BufferTooShort
    }
}

/// A specialized [`Result`](std::result::Result) type for capsule
/// operations.
pub type Result<T> = std::result::Result<T, CapsuleError>;

/// RFC 9297 Section 3.2: DATAGRAM capsule type.
pub const DATAGRAM_CAPSULE: u64 = 0x00;

/// RFC 9484 Section 4.7.1: ADDRESS_ASSIGN capsule type.
pub const ADDRESS_ASSIGN_CAPSULE: u64 = 0x01;

/// RFC 9484 Section 4.7.2: ADDRESS_REQUEST capsule type.
pub const ADDRESS_REQUEST_CAPSULE: u64 = 0x02;

/// RFC 9484 Section 4.7.3: ROUTE_ADVERTISEMENT capsule type.
pub const ROUTE_ADVERTISEMENT_CAPSULE: u64 = 0x03;

// IP version constants used on the wire for CONNECT-IP.
const IP_VERSION_4: u8 = 4;
const IP_VERSION_6: u8 = 6;

// Length of an IPv4 address in bytes.
const IPV4_LEN: usize = 4;

// Length of an IPv6 address in bytes.
const IPV6_LEN: usize = 16;

/// Encode a capsule header (type + value length) into `buf`.
///
/// Returns the number of bytes written.
pub fn encode_capsule_header(
    buf: &mut [u8], capsule_type: u64, value_len: u64,
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(capsule_type)?;
    b.put_varint(value_len)?;
    Ok(b.off())
}

/// Encode a complete capsule (header + value) into `buf`.
///
/// Returns the total number of bytes written (header + value).
pub fn encode_capsule(
    buf: &mut [u8], capsule_type: u64, value: &[u8],
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(capsule_type)?;
    b.put_varint(value.len() as u64)?;
    b.put_bytes(value)?;
    Ok(b.off())
}

/// Parser state for incremental capsule parsing from a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseState {
    /// Waiting for the capsule type varint.
    Type,

    /// Waiting for the capsule value length varint.
    Length,

    /// Reading capsule value bytes.
    Value,
}

/// Event returned by [`CapsuleParser::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleEvent {
    /// Not enough data to make progress; feed more bytes.
    Pending,

    /// Capsule header has been fully parsed. The capsule type and value
    /// length are available via [`CapsuleParser::capsule_type`] and
    /// [`CapsuleParser::remaining`].
    Header {
        /// The capsule type identifier.
        capsule_type: u64,
        /// The length of the capsule value in bytes.
        value_len: u64,
    },

    /// A chunk of value data is available in the input buffer at the
    /// given offset and length.
    ValueChunk {
        /// Offset within the input slice where the chunk begins.
        offset: usize,
        /// Number of value bytes in this chunk.
        len: usize,
    },

    /// The capsule has been fully consumed and the parser has been reset
    /// to accept the next capsule.
    Done,
}

/// Incremental capsule parser.
///
/// This parser handles partial reads, buffering varint bytes internally
/// until a complete type or length field can be decoded.
///
/// Typical usage:
///
/// ```ignore
/// let mut parser = CapsuleParser::new();
/// loop {
///     let data = /* read from stream */;
///     let mut off = 0;
///     while off < data.len() {
///         let (event, consumed) = parser.parse(&data[off..])?;
///         off += consumed;
///         match event {
///             CapsuleEvent::Header { capsule_type, value_len } => { /* ... */ },
///             CapsuleEvent::ValueChunk { offset, len } => { /* ... */ },
///             CapsuleEvent::Done => { /* capsule complete */ },
///             CapsuleEvent::Pending => break,
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct CapsuleParser {
    state: ParseState,

    // Buffer for accumulating varint bytes across partial reads.
    hdr_buf: Vec<u8>,

    capsule_type: u64,
    value_len: u64,
    value_read: u64,
}

impl CapsuleParser {
    /// Create a new parser ready to read the first capsule.
    pub fn new() -> Self {
        CapsuleParser {
            state: ParseState::Type,
            hdr_buf: Vec::new(),
            capsule_type: 0,
            value_len: 0,
            value_read: 0,
        }
    }

    /// Returns the capsule type of the capsule currently being parsed.
    ///
    /// Only meaningful after a [`CapsuleEvent::Header`] has been returned.
    pub fn capsule_type(&self) -> u64 {
        self.capsule_type
    }

    /// Returns the number of value bytes remaining to be read.
    pub fn remaining(&self) -> u64 {
        self.value_len - self.value_read
    }

    /// Returns the current parser state.
    pub fn state(&self) -> &ParseState {
        &self.state
    }

    /// Returns `true` if the parser is in the middle of parsing a capsule.
    ///
    /// RFC 9297 §3.3: if the receive side of a stream is terminated cleanly
    /// and this returns `true`, the last capsule was truncated and MUST be
    /// treated as a malformed message.
    pub fn is_in_progress(&self) -> bool {
        match self.state {
            ParseState::Type => !self.hdr_buf.is_empty(),
            ParseState::Length | ParseState::Value => true,
        }
    }

    /// Feed data to the parser.
    ///
    /// Returns a `(CapsuleEvent, usize)` tuple where the `usize` is the
    /// number of bytes consumed from `data`. The caller should advance its
    /// read position by that amount and call `parse` again with the
    /// remaining data until [`CapsuleEvent::Pending`] is returned.
    pub fn parse(&mut self, data: &[u8]) -> Result<(CapsuleEvent, usize)> {
        if data.is_empty() {
            return Ok((CapsuleEvent::Pending, 0));
        }

        match self.state {
            ParseState::Type => self.parse_varint(data, true),

            ParseState::Length => self.parse_varint(data, false),

            ParseState::Value => self.parse_value(data),
        }
    }

    /// Try to parse a varint from accumulated + new data.
    ///
    /// When `is_type` is true we are parsing the capsule type field;
    /// otherwise we are parsing the value length field.
    fn parse_varint(
        &mut self, data: &[u8], is_type: bool,
    ) -> Result<(CapsuleEvent, usize)> {
        // If we have no accumulated bytes, try fast-path: parse directly
        // from the input.
        if self.hdr_buf.is_empty() {
            let mut b = octets::Octets::with_slice(data);
            match b.get_varint() {
                Ok(val) => {
                    let consumed = b.off();
                    return self.varint_complete(val, consumed, is_type);
                },

                Err(_) => {
                    // Not enough data; buffer what we have.
                    self.hdr_buf.extend_from_slice(data);
                    return Ok((CapsuleEvent::Pending, data.len()));
                },
            }
        }

        // Slow path: we have accumulated partial varint bytes. Append
        // one byte at a time until we can decode.
        let mut consumed = 0;
        while consumed < data.len() {
            self.hdr_buf.push(data[consumed]);
            consumed += 1;

            let mut b = octets::Octets::with_slice(&self.hdr_buf);
            match b.get_varint() {
                Ok(val) => {
                    self.hdr_buf.clear();
                    return self.varint_complete(val, consumed, is_type);
                },

                Err(_) => {
                    // Check if the buffer is unreasonably large (a varint
                    // is at most 8 bytes).
                    if self.hdr_buf.len() > 8 {
                        return Err(CapsuleError::InvalidCapsule);
                    }
                    continue;
                },
            }
        }

        // Consumed all input but still not enough for the varint.
        Ok((CapsuleEvent::Pending, consumed))
    }

    /// Handle a successfully decoded varint.
    fn varint_complete(
        &mut self, val: u64, consumed: usize, is_type: bool,
    ) -> Result<(CapsuleEvent, usize)> {
        if is_type {
            self.capsule_type = val;
            self.state = ParseState::Length;
            Ok((CapsuleEvent::Pending, consumed))
        } else {
            self.value_len = val;
            self.value_read = 0;

            if self.value_len == 0 {
                // Zero-length value: go straight to Done.
                self.state = ParseState::Type;
                Ok((CapsuleEvent::Done, consumed))
            } else {
                self.state = ParseState::Value;
                Ok((
                    CapsuleEvent::Header {
                        capsule_type: self.capsule_type,
                        value_len: self.value_len,
                    },
                    consumed,
                ))
            }
        }
    }

    /// Consume value bytes from the input.
    fn parse_value(
        &mut self, data: &[u8],
    ) -> Result<(CapsuleEvent, usize)> {
        let remaining = (self.value_len - self.value_read) as usize;
        let chunk = std::cmp::min(data.len(), remaining);

        if chunk == 0 {
            return Ok((CapsuleEvent::Pending, 0));
        }

        self.value_read += chunk as u64;

        if self.value_read == self.value_len {
            // Value fully consumed; reset for next capsule.
            self.state = ParseState::Type;
            Ok((CapsuleEvent::Done, chunk))
        } else {
            Ok((
                CapsuleEvent::ValueChunk {
                    offset: 0,
                    len: chunk,
                },
                chunk,
            ))
        }
    }

    /// Reset the parser to its initial state.
    pub fn reset(&mut self) {
        self.state = ParseState::Type;
        self.hdr_buf.clear();
        self.capsule_type = 0;
        self.value_len = 0;
        self.value_read = 0;
    }
}

impl Default for CapsuleParser {
    fn default() -> Self {
        CapsuleParser::new()
    }
}

/// An assigned or requested IP address prefix, used in ADDRESS_ASSIGN and
/// ADDRESS_REQUEST capsules (RFC 9484 Sections 4.7.1, 4.7.2).
///
/// Wire format of an Assigned Address:
///
/// ```text
/// Assigned Address {
///   Request ID (i),
///   IP Version (8),
///   IP Address (32..128),
///   IP Prefix Length (8),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    /// Identifier for this address assignment/request.
    pub request_id: u64,
    /// The IP address (v4 or v6).
    pub ip_prefix: IpAddr,
    /// The prefix length (0-32 for IPv4, 0-128 for IPv6).
    pub prefix_length: u8,
}

/// A route entry in a ROUTE_ADVERTISEMENT capsule (RFC 9484 Section 4.7.3).
///
/// Wire format:
///
/// ```text
/// IP Address Range {
///   IP Version (8),
///   Start IP Address (32..128),
///   End IP Address (32..128),
///   IP Protocol (8),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Start of the IP address range (inclusive).
    pub start_ip: IpAddr,
    /// End of the IP address range (inclusive).
    pub end_ip: IpAddr,
    /// IP protocol number (0 means all protocols).
    pub ip_protocol: u8,
}

/// Compute the wire size of an [`AddressEntry`].
fn address_entry_wire_len(entry: &AddressEntry) -> usize {
    let addr_len = match entry.ip_prefix {
        IpAddr::V4(_) => IPV4_LEN,
        IpAddr::V6(_) => IPV6_LEN,
    };

    // request_id (varint) + ip_version (1) + address + prefix_length (1)
    octets::varint_len(entry.request_id) + 1 + addr_len + 1
}

/// Compute the wire size of a [`RouteEntry`].
fn route_entry_wire_len(entry: &RouteEntry) -> usize {
    let addr_len = match entry.start_ip {
        IpAddr::V4(_) => IPV4_LEN,
        IpAddr::V6(_) => IPV6_LEN,
    };

    // ip_version (1) + start_ip + end_ip + ip_protocol (1)
    1 + addr_len + addr_len + 1
}

/// Encode an ADDRESS_ASSIGN capsule value (RFC 9484 Section 4.7.1).
///
/// This encodes the complete capsule (header + value) into `buf`. The
/// value consists of a sequence of Assigned Address entries.
///
/// Returns the total number of bytes written.
pub fn encode_address_assign(
    buf: &mut [u8], entries: &[AddressEntry],
) -> Result<usize> {
    let value_len: usize = entries.iter().map(address_entry_wire_len).sum();

    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(ADDRESS_ASSIGN_CAPSULE)?;
    b.put_varint(value_len as u64)?;

    for entry in entries {
        encode_address_entry(&mut b, entry)?;
    }

    Ok(b.off())
}

/// Encode an ADDRESS_REQUEST capsule value (RFC 9484 Section 4.7.2).
///
/// Same wire format as ADDRESS_ASSIGN but with a different capsule type.
///
/// Returns the total number of bytes written.
pub fn encode_address_request(
    buf: &mut [u8], entries: &[AddressEntry],
) -> Result<usize> {
    let value_len: usize = entries.iter().map(address_entry_wire_len).sum();

    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(ADDRESS_REQUEST_CAPSULE)?;
    b.put_varint(value_len as u64)?;

    for entry in entries {
        encode_address_entry(&mut b, entry)?;
    }

    Ok(b.off())
}

/// Encode a single address entry into the buffer.
fn encode_address_entry(
    b: &mut octets::OctetsMut, entry: &AddressEntry,
) -> Result<()> {
    b.put_varint(entry.request_id)?;

    match entry.ip_prefix {
        IpAddr::V4(addr) => {
            b.put_u8(IP_VERSION_4)?;
            b.put_bytes(&addr.octets())?;
        },

        IpAddr::V6(addr) => {
            b.put_u8(IP_VERSION_6)?;
            b.put_bytes(&addr.octets())?;
        },
    }

    b.put_u8(entry.prefix_length)?;

    Ok(())
}

/// Decode an ADDRESS_ASSIGN capsule value (RFC 9484 Section 4.7.1).
///
/// `data` should contain only the capsule value bytes (after the capsule
/// header has been stripped).
pub fn decode_address_assign(data: &[u8]) -> Result<Vec<AddressEntry>> {
    decode_address_entries(data)
}

/// Decode an ADDRESS_REQUEST capsule value (RFC 9484 Section 4.7.2).
///
/// Same wire format as ADDRESS_ASSIGN but with additional constraints:
/// request IDs MUST NOT be zero and there MUST be at least one entry.
pub fn decode_address_request(data: &[u8]) -> Result<Vec<AddressEntry>> {
    let entries = decode_address_entries(data)?;

    // RFC 9484 §4.7.2: zero Requested Addresses MUST abort stream.
    if entries.is_empty() {
        return Err(CapsuleError::InvalidCapsule);
    }

    // RFC 9484 §4.7.2: Request IDs MUST NOT be zero.
    for entry in &entries {
        if entry.request_id == 0 {
            return Err(CapsuleError::InvalidCapsule);
        }
    }

    Ok(entries)
}

/// Validates that IP address bits below the prefix length are all zero.
fn validate_prefix_lower_bits(ip: &IpAddr, prefix_length: u8) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            if prefix_length >= 32 {
                return true;
            }
            let bits = u32::from_be_bytes(addr.octets());
            let mask = !0u32 >> prefix_length;
            bits & mask == 0
        },

        IpAddr::V6(addr) => {
            if prefix_length >= 128 {
                return true;
            }
            let bits = u128::from_be_bytes(addr.octets());
            let mask = !0u128 >> prefix_length;
            bits & mask == 0
        },
    }
}

/// Decode a sequence of Assigned Address entries.
fn decode_address_entries(data: &[u8]) -> Result<Vec<AddressEntry>> {
    let mut b = octets::Octets::with_slice(data);
    let mut entries = Vec::new();

    while b.cap() > 0 {
        let request_id = b.get_varint()?;
        let ip_version = b.get_u8()?;

        let ip_prefix = match ip_version {
            IP_VERSION_4 => {
                let addr_bytes = b.get_bytes(IPV4_LEN)?;
                let mut octets = [0u8; IPV4_LEN];
                octets.copy_from_slice(addr_bytes.as_ref());
                IpAddr::V4(Ipv4Addr::from(octets))
            },

            IP_VERSION_6 => {
                let addr_bytes = b.get_bytes(IPV6_LEN)?;
                let mut octets = [0u8; IPV6_LEN];
                octets.copy_from_slice(addr_bytes.as_ref());
                IpAddr::V6(Ipv6Addr::from(octets))
            },

            _ => return Err(CapsuleError::InvalidCapsule),
        };

        let prefix_length = b.get_u8()?;

        // Validate prefix length.
        let max_prefix = match ip_prefix {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_length > max_prefix {
            return Err(CapsuleError::InvalidCapsule);
        }

        // RFC 9484 §4.7.1: lower bits not covered by prefix MUST be zero.
        if !validate_prefix_lower_bits(&ip_prefix, prefix_length) {
            return Err(CapsuleError::InvalidCapsule);
        }

        entries.push(AddressEntry {
            request_id,
            ip_prefix,
            prefix_length,
        });
    }

    Ok(entries)
}

/// Encode a ROUTE_ADVERTISEMENT capsule (RFC 9484 Section 4.7.3).
///
/// This encodes the complete capsule (header + value) into `buf`.
///
/// Returns the total number of bytes written.
pub fn encode_route_advertisement(
    buf: &mut [u8], entries: &[RouteEntry],
) -> Result<usize> {
    // Validate that start_ip and end_ip have the same IP version.
    for entry in entries {
        match (&entry.start_ip, &entry.end_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => {},
            (IpAddr::V6(_), IpAddr::V6(_)) => {},
            _ => return Err(CapsuleError::InvalidCapsule),
        }
    }

    let value_len: usize = entries.iter().map(route_entry_wire_len).sum();

    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(ROUTE_ADVERTISEMENT_CAPSULE)?;
    b.put_varint(value_len as u64)?;

    for entry in entries {
        encode_route_entry(&mut b, entry)?;
    }

    Ok(b.off())
}

/// Encode a single route entry into the buffer.
fn encode_route_entry(
    b: &mut octets::OctetsMut, entry: &RouteEntry,
) -> Result<()> {
    match (&entry.start_ip, &entry.end_ip) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            b.put_u8(IP_VERSION_4)?;
            b.put_bytes(&start.octets())?;
            b.put_bytes(&end.octets())?;
        },

        (IpAddr::V6(start), IpAddr::V6(end)) => {
            b.put_u8(IP_VERSION_6)?;
            b.put_bytes(&start.octets())?;
            b.put_bytes(&end.octets())?;
        },

        // Mismatched IP versions are caught in encode_route_advertisement.
        _ => return Err(CapsuleError::InvalidCapsule),
    }

    b.put_u8(entry.ip_protocol)?;

    Ok(())
}

/// Compare two IP addresses of the same version numerically.
fn ip_addr_le(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            u32::from_be_bytes(a.octets()) <= u32::from_be_bytes(b.octets())
        },

        (IpAddr::V6(a), IpAddr::V6(b)) => {
            u128::from_be_bytes(a.octets()) <= u128::from_be_bytes(b.octets())
        },

        _ => false,
    }
}

/// Compare two IP addresses of the same version, returns true if a < b.
fn ip_addr_lt(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            u32::from_be_bytes(a.octets()) < u32::from_be_bytes(b.octets())
        },

        (IpAddr::V6(a), IpAddr::V6(b)) => {
            u128::from_be_bytes(a.octets()) < u128::from_be_bytes(b.octets())
        },

        _ => false,
    }
}

fn ip_version(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => IP_VERSION_4,
        IpAddr::V6(_) => IP_VERSION_6,
    }
}

/// Decode a ROUTE_ADVERTISEMENT capsule value (RFC 9484 Section 4.7.3).
///
/// `data` should contain only the capsule value bytes (after the capsule
/// header has been stripped).
pub fn decode_route_advertisement(data: &[u8]) -> Result<Vec<RouteEntry>> {
    let mut b = octets::Octets::with_slice(data);
    let mut entries = Vec::new();

    while b.cap() > 0 {
        let ip_version = b.get_u8()?;

        let (start_ip, end_ip) = match ip_version {
            IP_VERSION_4 => {
                let start_bytes = b.get_bytes(IPV4_LEN)?;
                let end_bytes = b.get_bytes(IPV4_LEN)?;

                let mut s = [0u8; IPV4_LEN];
                let mut e = [0u8; IPV4_LEN];
                s.copy_from_slice(start_bytes.as_ref());
                e.copy_from_slice(end_bytes.as_ref());

                (
                    IpAddr::V4(Ipv4Addr::from(s)),
                    IpAddr::V4(Ipv4Addr::from(e)),
                )
            },

            IP_VERSION_6 => {
                let start_bytes = b.get_bytes(IPV6_LEN)?;
                let end_bytes = b.get_bytes(IPV6_LEN)?;

                let mut s = [0u8; IPV6_LEN];
                let mut e = [0u8; IPV6_LEN];
                s.copy_from_slice(start_bytes.as_ref());
                e.copy_from_slice(end_bytes.as_ref());

                (
                    IpAddr::V6(Ipv6Addr::from(s)),
                    IpAddr::V6(Ipv6Addr::from(e)),
                )
            },

            _ => return Err(CapsuleError::InvalidCapsule),
        };

        let ip_protocol = b.get_u8()?;

        // RFC 9484 §4.7.3: Start IP Address MUST be <= End IP Address.
        if !ip_addr_le(&start_ip, &end_ip) {
            return Err(CapsuleError::InvalidCapsule);
        }

        entries.push(RouteEntry {
            start_ip,
            end_ip,
            ip_protocol,
        });
    }

    // RFC 9484 §4.7.3: validate entry ordering.
    for i in 1..entries.len() {
        let a = &entries[i - 1];
        let b = &entries[i];
        let a_ver = ip_version(&a.start_ip);
        let b_ver = ip_version(&b.start_ip);

        if a_ver > b_ver {
            return Err(CapsuleError::InvalidCapsule);
        }

        if a_ver == b_ver {
            if a.ip_protocol > b.ip_protocol {
                return Err(CapsuleError::InvalidCapsule);
            }

            if a.ip_protocol == b.ip_protocol &&
                !ip_addr_lt(&a.end_ip, &b.start_ip)
            {
                return Err(CapsuleError::InvalidCapsule);
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_header_encode_decode() {
        let mut buf = [0u8; 64];

        let written =
            encode_capsule_header(&mut buf, DATAGRAM_CAPSULE, 10).unwrap();

        // Type 0x00 = 1 byte varint, length 10 = 1 byte varint.
        assert_eq!(written, 2);

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, DATAGRAM_CAPSULE);
        assert_eq!(value_len, 10);
    }

    #[test]
    fn capsule_header_large_values() {
        let mut buf = [0u8; 64];

        // Use values that require multi-byte varints.
        let ctype = 0x1000;
        let vlen = 0x4000_0000;

        let written = encode_capsule_header(&mut buf, ctype, vlen).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        assert_eq!(b.get_varint().unwrap(), ctype);
        assert_eq!(b.get_varint().unwrap(), vlen);
    }

    #[test]
    fn capsule_header_buffer_too_short() {
        let mut buf = [0u8; 1];

        // Type fits (1 byte) but length (10 = 1 byte) won't fit.
        let result = encode_capsule_header(&mut buf, 0x00, 10);
        assert!(result.is_err());
    }

    #[test]
    fn full_capsule_roundtrip() {
        let mut buf = [0u8; 128];
        let value = b"hello capsule";

        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        // Header: type(1) + length(1) + value(13) = 15.
        assert_eq!(written, 2 + value.len());

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, DATAGRAM_CAPSULE);
        assert_eq!(value_len, value.len() as u64);

        let payload = b.get_bytes(value_len as usize).unwrap();
        assert_eq!(payload.as_ref(), value);
    }

    #[test]
    fn full_capsule_empty_value() {
        let mut buf = [0u8; 64];

        let written = encode_capsule(&mut buf, 0xFF, &[]).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, 0xFF);
        assert_eq!(value_len, 0);
        assert_eq!(b.cap(), 0);
    }

    #[test]
    fn parser_complete_data() {
        let mut buf = [0u8; 128];
        let value = b"test data";
        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        let mut parser = CapsuleParser::new();
        let data = &buf[..written];

        // First parse should consume the type varint and return Pending
        // (type alone doesn't produce a header event).
        let (event, consumed1) = parser.parse(data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(consumed1 > 0);

        // Second parse should consume the length varint and return Header.
        let (event, consumed2) = parser.parse(&data[consumed1..]).unwrap();
        assert_eq!(
            event,
            CapsuleEvent::Header {
                capsule_type: DATAGRAM_CAPSULE,
                value_len: value.len() as u64,
            }
        );

        // Third parse should consume the value and return Done.
        let off = consumed1 + consumed2;
        let (event, consumed3) = parser.parse(&data[off..]).unwrap();
        assert_eq!(event, CapsuleEvent::Done);
        assert_eq!(consumed3, value.len());
        assert_eq!(off + consumed3, written);
    }

    #[test]
    fn parser_chunked_data() {
        let mut buf = [0u8; 128];
        let value = b"chunked";
        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        let mut parser = CapsuleParser::new();

        // Feed one byte at a time.
        let mut pos = 0;
        let mut saw_header = false;
        let mut saw_done = false;
        let mut _value_bytes = 0;

        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;

            match event {
                CapsuleEvent::Pending => {},

                CapsuleEvent::Header {
                    capsule_type,
                    value_len,
                } => {
                    assert_eq!(capsule_type, DATAGRAM_CAPSULE);
                    assert_eq!(value_len, value.len() as u64);
                    saw_header = true;
                },

                CapsuleEvent::ValueChunk { len, .. } => {
                    _value_bytes += len;
                },

                CapsuleEvent::Done => {
                    // Done also accounts for the last value byte consumed.
                    saw_done = true;
                },
            }
        }

        assert!(saw_header);
        assert!(saw_done);
    }

    #[test]
    fn parser_zero_length_capsule() {
        let mut buf = [0u8; 64];
        // Use type 0x00 which is a 1-byte varint so the test is
        // straightforward.
        let written = encode_capsule(&mut buf, 0x00, &[]).unwrap();
        assert_eq!(written, 2); // type(1) + length(1)

        let mut parser = CapsuleParser::new();

        // Feed the type byte.
        let (event, c1) = parser.parse(&buf[..1]).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert_eq!(c1, 1);

        // Feed the length byte (0). Zero-length value goes straight to
        // Done without emitting a Header event.
        let (event, c2) = parser.parse(&buf[c1..written]).unwrap();
        assert_eq!(event, CapsuleEvent::Done);
        assert_eq!(c1 + c2, written);
    }

    #[test]
    fn parser_zero_length_capsule_multipart() {
        let mut buf = [0u8; 64];
        // Use a type that needs a 2-byte varint to exercise partial
        // buffering together with zero-length value.
        let written = encode_capsule(&mut buf, 0x42, &[]).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_done = false;

        // Feed one byte at a time.
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;
            if event == CapsuleEvent::Done {
                saw_done = true;
            }
        }

        assert!(saw_done);
        assert_eq!(pos, written);
    }

    #[test]
    fn parser_multiple_capsules() {
        let mut buf = [0u8; 256];
        let v1 = b"first";
        let v2 = b"second";

        let w1 = encode_capsule(&mut buf, 0x01, v1).unwrap();
        let w2 = encode_capsule(&mut buf[w1..], 0x02, v2).unwrap();
        let total = w1 + w2;

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut capsule_count = 0;

        while pos < total {
            let (event, consumed) =
                parser.parse(&buf[pos..total]).unwrap();
            pos += consumed;

            if event == CapsuleEvent::Done {
                capsule_count += 1;
            }
        }

        assert_eq!(capsule_count, 2);
    }

    #[test]
    fn parser_empty_input() {
        let mut parser = CapsuleParser::new();
        let (event, consumed) = parser.parse(&[]).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn parser_unknown_capsule_type() {
        let mut buf = [0u8; 128];
        let value = b"unknown";
        let written = encode_capsule(&mut buf, 0xFFFF, value).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_header = false;

        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..written]).unwrap();
            pos += consumed;

            if let CapsuleEvent::Header {
                capsule_type,
                value_len,
            } = event
            {
                assert_eq!(capsule_type, 0xFFFF);
                assert_eq!(value_len, value.len() as u64);
                saw_header = true;
            }
        }

        assert!(saw_header);
    }

    #[test]
    fn address_assign_ipv4_roundtrip() {
        let entries = vec![AddressEntry {
            request_id: 1,
            ip_prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_length: 24,
        }];

        let mut buf = [0u8; 256];
        let written = encode_address_assign(&mut buf, &entries).unwrap();

        // Decode: skip the capsule header first.
        let mut b = octets::Octets::with_slice(&buf[..written]);
        let ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        assert_eq!(ctype, ADDRESS_ASSIGN_CAPSULE);

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn address_assign_ipv6_roundtrip() {
        let entries = vec![AddressEntry {
            request_id: 42,
            ip_prefix: IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0,
            )),
            prefix_length: 48,
        }];

        let mut buf = [0u8; 256];
        let written = encode_address_assign(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn address_assign_multiple_entries() {
        let entries = vec![
            AddressEntry {
                request_id: 0,
                ip_prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_length: 32,
            },
            AddressEntry {
                request_id: 1,
                ip_prefix: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix_length: 128,
            },
        ];

        let mut buf = [0u8; 256];
        let written = encode_address_assign(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn address_assign_empty() {
        let entries: Vec<AddressEntry> = vec![];

        let mut buf = [0u8; 64];
        let written = encode_address_assign(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        assert_eq!(ctype, ADDRESS_ASSIGN_CAPSULE);
        assert_eq!(vlen, 0);

        let decoded = decode_address_assign(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn address_request_roundtrip() {
        let entries = vec![AddressEntry {
            request_id: 7,
            ip_prefix: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_length: 0,
        }];

        let mut buf = [0u8; 256];
        let written = encode_address_request(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        assert_eq!(ctype, ADDRESS_REQUEST_CAPSULE);

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_request(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn address_invalid_prefix_length() {
        // IPv4 with prefix length > 32.
        let mut data = [0u8; 32];
        let mut b = octets::OctetsMut::with_slice(&mut data);
        b.put_varint(0).unwrap(); // request_id
        b.put_u8(IP_VERSION_4).unwrap();
        b.put_bytes(&[10, 0, 0, 0]).unwrap();
        b.put_u8(33).unwrap(); // invalid: > 32
        let off = b.off();

        let result = decode_address_assign(&data[..off]);
        assert!(result.is_err());
    }

    #[test]
    fn address_invalid_ip_version() {
        let mut data = [0u8; 32];
        let mut b = octets::OctetsMut::with_slice(&mut data);
        b.put_varint(0).unwrap(); // request_id
        b.put_u8(5).unwrap(); // invalid IP version
        let off = b.off();

        let result = decode_address_assign(&data[..off]);
        assert!(result.is_err());
    }

    #[test]
    fn route_advertisement_ipv4_roundtrip() {
        let entries = vec![RouteEntry {
            start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            end_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
            ip_protocol: 0,
        }];

        let mut buf = [0u8; 256];
        let written =
            encode_route_advertisement(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        assert_eq!(ctype, ROUTE_ADVERTISEMENT_CAPSULE);

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_route_advertisement(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn route_advertisement_ipv6_roundtrip() {
        let entries = vec![RouteEntry {
            start_ip: IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0,
            )),
            end_ip: IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
            ip_protocol: 6, // TCP
        }];

        let mut buf = [0u8; 256];
        let written =
            encode_route_advertisement(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_route_advertisement(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn route_advertisement_multiple_entries() {
        let entries = vec![
            RouteEntry {
                start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)),
                ip_protocol: 0,
            },
            RouteEntry {
                start_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)),
                ip_protocol: 17, // UDP
            },
        ];

        let mut buf = [0u8; 256];
        let written =
            encode_route_advertisement(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_route_advertisement(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn route_advertisement_empty() {
        let entries: Vec<RouteEntry> = vec![];

        let mut buf = [0u8; 64];
        let written =
            encode_route_advertisement(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        assert_eq!(ctype, ROUTE_ADVERTISEMENT_CAPSULE);
        assert_eq!(vlen, 0);

        let decoded = decode_route_advertisement(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn route_advertisement_mismatched_versions() {
        let entries = vec![RouteEntry {
            start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            end_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip_protocol: 0,
        }];

        let mut buf = [0u8; 256];
        let result = encode_route_advertisement(&mut buf, &entries);
        assert!(result.is_err());
    }

    #[test]
    fn route_advertisement_invalid_ip_version() {
        let mut data = [0u8; 32];
        let mut b = octets::OctetsMut::with_slice(&mut data);
        b.put_u8(5).unwrap(); // invalid IP version
        let off = b.off();

        let result = decode_route_advertisement(&data[..off]);
        assert!(result.is_err());
    }

    #[test]
    fn parser_reset() {
        let mut parser = CapsuleParser::new();

        // Partially feed data.
        let mut buf = [0u8; 64];
        let written = encode_capsule(&mut buf, 0x01, b"data").unwrap();

        let (_, consumed) = parser.parse(&buf[..1]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(*parser.state(), ParseState::Length);

        // Reset and verify clean state.
        parser.reset();
        assert_eq!(*parser.state(), ParseState::Type);
        assert_eq!(parser.capsule_type(), 0);
        assert_eq!(parser.remaining(), 0);

        // Should work normally after reset.
        let mut pos = 0;
        let mut saw_done = false;
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..written]).unwrap();
            pos += consumed;
            if event == CapsuleEvent::Done {
                saw_done = true;
            }
        }
        assert!(saw_done);
    }

    #[test]
    fn parser_large_varint_chunked() {
        // Encode a capsule with a type that requires a 4-byte varint.
        let mut buf = [0u8; 128];
        let ctype = 0x3FFF_FFFF; // max 4-byte varint
        let value = b"lg";
        let written = encode_capsule(&mut buf, ctype, value).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_header = false;

        // Feed one byte at a time.
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;

            if let CapsuleEvent::Header {
                capsule_type,
                value_len,
            } = event
            {
                assert_eq!(capsule_type, ctype);
                assert_eq!(value_len, value.len() as u64);
                saw_header = true;
            }
        }

        assert!(saw_header);
    }

    #[test]
    fn encode_capsule_buffer_too_short() {
        let mut buf = [0u8; 2];
        let result = encode_capsule(&mut buf, 0x00, b"too long");
        assert!(result.is_err());
    }

    #[test]
    fn address_entry_large_request_id() {
        let entries = vec![AddressEntry {
            request_id: 0x3FFF_FFFF_FFFF_FFFF,
            ip_prefix: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            prefix_length: 32,
        }];

        let mut buf = [0u8; 256];
        let written = encode_address_assign(&mut buf, &entries).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();

        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();

        assert_eq!(decoded, entries);
    }

    #[test]
    fn address_assign_prefix_lower_bits_valid_ipv4() {
        // 192.168.0.0/16 — lower 16 bits are zero
        let entry = AddressEntry {
            request_id: 1,
            ip_prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix_length: 16,
        };
        let mut buf = [0u8; 256];
        let len = encode_address_assign(&mut buf, &[entry]).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn address_assign_prefix_lower_bits_invalid_ipv4() {
        // 192.168.1.0/16 — bit in position 23 is set but prefix is 16
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // capsule header
        b.put_varint(ADDRESS_ASSIGN_CAPSULE).unwrap();
        // value: request_id(1) + ip_version(1) + addr(4) + prefix(1) = 7
        b.put_varint(7).unwrap();
        b.put_varint(0).unwrap(); // request_id
        b.put_u8(4).unwrap(); // IPv4
        b.put_bytes(&[192, 168, 1, 0]).unwrap(); // addr with non-zero lower
        b.put_u8(16).unwrap(); // prefix_length
        let off = b.off();
        // Decode just the value part (skip capsule header)
        let mut r = octets::Octets::with_slice(&buf[..off]);
        r.get_varint().unwrap(); // skip type
        let vlen = r.get_varint().unwrap() as usize;
        let value_start = r.off();
        assert_eq!(
            decode_address_assign(&buf[value_start..value_start + vlen]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn address_assign_prefix_lower_bits_valid_ipv6() {
        // 2001:db8::/32 — lower 96 bits are zero
        let entry = AddressEntry {
            request_id: 1,
            ip_prefix: IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 0,
            )),
            prefix_length: 32,
        };
        let mut buf = [0u8; 256];
        let len = encode_address_assign(&mut buf, &[entry]).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn address_assign_prefix_lower_bits_invalid_ipv6() {
        // 2001:db8::1/32 — bit set in lower portion
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        b.put_varint(ADDRESS_ASSIGN_CAPSULE).unwrap();
        // value: request_id(1) + ip_version(1) + addr(16) + prefix(1) = 19
        b.put_varint(19).unwrap();
        b.put_varint(0).unwrap(); // request_id
        b.put_u8(6).unwrap(); // IPv6
        let addr =
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        b.put_bytes(&addr.octets()).unwrap();
        b.put_u8(32).unwrap(); // prefix_length
        let off = b.off();
        let mut r = octets::Octets::with_slice(&buf[..off]);
        r.get_varint().unwrap();
        let vlen = r.get_varint().unwrap() as usize;
        let value_start = r.off();
        assert_eq!(
            decode_address_assign(&buf[value_start..value_start + vlen]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn address_assign_full_prefix_length() {
        // /32 for IPv4 — all bits covered, always valid
        let entry = AddressEntry {
            request_id: 1,
            ip_prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            prefix_length: 32,
        };
        let expected_ip = entry.ip_prefix;
        let mut buf = [0u8; 256];
        let len = encode_address_assign(&mut buf, &[entry]).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let _ctype = b.get_varint().unwrap();
        let vlen = b.get_varint().unwrap();
        let value_data = b.get_bytes(vlen as usize).unwrap();
        let decoded =
            decode_address_assign(value_data.as_ref()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].ip_prefix, expected_ip);
    }

    #[test]
    fn address_request_request_id_zero() {
        // Manually encode an ADDRESS_REQUEST with request_id = 0
        let mut raw = Vec::new();
        // request_id = 0 (1 byte varint)
        raw.push(0);
        // ip_version = 4
        raw.push(4);
        // IPv4 addr
        raw.extend_from_slice(&[10, 0, 0, 0]);
        // prefix_length = 8
        raw.push(8);

        assert_eq!(
            decode_address_request(&raw),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn address_request_empty() {
        // Empty ADDRESS_REQUEST (zero entries)
        assert_eq!(
            decode_address_request(&[]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn address_request_valid() {
        // Valid ADDRESS_REQUEST with non-zero request_id
        let mut raw = Vec::new();
        raw.push(1); // request_id = 1
        raw.push(4); // IPv4
        raw.extend_from_slice(&[10, 0, 0, 0]); // 10.0.0.0
        raw.push(8); // /8

        let entries = decode_address_request(&raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_id, 1);
    }

    #[test]
    fn route_advertisement_start_greater_than_end() {
        // start_ip = 10.0.0.2, end_ip = 10.0.0.1 — invalid
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // ip_version
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 2]).unwrap(); // start
        b.put_bytes(&[10, 0, 0, 1]).unwrap(); // end
        b.put_u8(0).unwrap(); // protocol
        let off = b.off();
        assert_eq!(
            decode_route_advertisement(&buf[..off]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn route_advertisement_start_equals_end() {
        // start_ip = end_ip — valid (single address range)
        let entries = vec![RouteEntry {
            start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ip_protocol: 0,
        }];
        let mut buf = [0u8; 256];
        let len =
            encode_route_advertisement(&mut buf, &entries).unwrap();
        // Skip capsule header to get value bytes
        let mut r = octets::Octets::with_slice(&buf[..len]);
        r.get_varint().unwrap(); // type
        let vlen = r.get_varint().unwrap() as usize;
        let value_start = r.off();
        let decoded = decode_route_advertisement(
            &buf[value_start..value_start + vlen],
        )
        .unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn route_advertisement_unsorted_ip_version() {
        // IPv6 entry before IPv4 entry — invalid ordering
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // Entry 1: IPv6
        b.put_u8(6).unwrap();
        b.put_bytes(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets(),
        )
        .unwrap();
        b.put_bytes(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets(),
        )
        .unwrap();
        b.put_u8(0).unwrap();
        // Entry 2: IPv4
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 2]).unwrap();
        b.put_u8(0).unwrap();
        let off = b.off();
        assert_eq!(
            decode_route_advertisement(&buf[..off]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn route_advertisement_unsorted_protocol() {
        // Same IP version but protocol of A > protocol of B — invalid
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // Entry 1: protocol 17 (UDP)
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 2]).unwrap();
        b.put_u8(17).unwrap();
        // Entry 2: protocol 6 (TCP)
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 1, 1]).unwrap();
        b.put_bytes(&[10, 0, 1, 2]).unwrap();
        b.put_u8(6).unwrap();
        let off = b.off();
        assert_eq!(
            decode_route_advertisement(&buf[..off]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn route_advertisement_overlapping_ranges() {
        // Same version and protocol but overlapping IP ranges — invalid
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // Entry 1: 10.0.0.1 - 10.0.0.10
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 10]).unwrap();
        b.put_u8(0).unwrap();
        // Entry 2: 10.0.0.5 - 10.0.0.20 (overlaps with entry 1)
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 5]).unwrap();
        b.put_bytes(&[10, 0, 0, 20]).unwrap();
        b.put_u8(0).unwrap();
        let off = b.off();
        assert_eq!(
            decode_route_advertisement(&buf[..off]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn route_advertisement_sorted_valid() {
        // Two properly ordered entries
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // Entry 1: 10.0.0.1 - 10.0.0.10, protocol 6
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 10]).unwrap();
        b.put_u8(6).unwrap();
        // Entry 2: 10.0.0.11 - 10.0.0.20, protocol 6
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 11]).unwrap();
        b.put_bytes(&[10, 0, 0, 20]).unwrap();
        b.put_u8(6).unwrap();
        let off = b.off();
        let decoded = decode_route_advertisement(&buf[..off]).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn route_advertisement_different_protocols_same_range() {
        // Same IP range but different protocols — valid
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        // Entry 1: protocol 6 (TCP)
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 10]).unwrap();
        b.put_u8(6).unwrap();
        // Entry 2: protocol 17 (UDP), same range
        b.put_u8(4).unwrap();
        b.put_bytes(&[10, 0, 0, 1]).unwrap();
        b.put_bytes(&[10, 0, 0, 10]).unwrap();
        b.put_u8(17).unwrap();
        let off = b.off();
        let decoded = decode_route_advertisement(&buf[..off]).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn route_advertisement_ipv6_start_greater_than_end() {
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        b.put_u8(6).unwrap();
        b.put_bytes(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets(),
        )
        .unwrap();
        b.put_bytes(
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets(),
        )
        .unwrap();
        b.put_u8(0).unwrap();
        let off = b.off();
        assert_eq!(
            decode_route_advertisement(&buf[..off]),
            Err(CapsuleError::InvalidCapsule)
        );
    }

    #[test]
    fn capsule_parser_is_in_progress_initial() {
        let parser = CapsuleParser::new();
        assert!(!parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_partial_type() {
        let mut parser = CapsuleParser::new();
        // Feed a partial varint (2-byte varint, only first byte)
        let data = [0x40]; // First byte of a 2-byte varint
        let (event, _) = parser.parse(&data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_in_length() {
        let mut parser = CapsuleParser::new();
        // Feed complete type but no length
        let data = [0x00]; // type = 0 (1-byte varint)
        let (event, _) = parser.parse(&data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_in_value() {
        let mut parser = CapsuleParser::new();
        // type = 0, length = 5
        let data = [0x00, 0x05, 0xAA];
        let mut off = 0;
        loop {
            let (event, consumed) =
                parser.parse(&data[off..]).unwrap();
            off += consumed;
            match event {
                CapsuleEvent::Pending => break,
                CapsuleEvent::Header { .. } => continue,
                CapsuleEvent::ValueChunk { .. } => break,
                CapsuleEvent::Done => unreachable!(),
            }
        }
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_not_in_progress_after_done() {
        let mut parser = CapsuleParser::new();
        // type = 0, length = 0 (zero-length capsule)
        let data = [0x00, 0x00];
        let mut off = 0;
        loop {
            let (event, consumed) =
                parser.parse(&data[off..]).unwrap();
            off += consumed;
            if event == CapsuleEvent::Done {
                break;
            }
        }
        assert!(!parser.is_in_progress());
    }
}
