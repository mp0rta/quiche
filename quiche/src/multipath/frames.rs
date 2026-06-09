//! Multipath-specific frame parsing and generation.
//!
//! Frame type codes per draft-ietf-quic-multipath-21:
//!   PATH_ACK:                    0x3e / 0x3f (with ECN)    §4.1
//!   PATH_ABANDON:                0x3e75                    §4.2
//!   PATH_STATUS_BACKUP:          0x3e76                    §4.3
//!   PATH_STATUS_AVAILABLE:       0x3e77                    §4.3
//!   PATH_NEW_CONNECTION_ID:      0x3e78                    §4.4
//!   PATH_RETIRE_CONNECTION_ID:   0x3e79                    §4.5
//!   MAX_PATH_ID:                 0x3e7a                    §4.6
//!   PATHS_BLOCKED:               0x3e7b                    §4.7
//!   PATH_CIDS_BLOCKED:           0x3e7c                    §4.7

use crate::ranges::RangeSet;
use crate::frame::EcnCounts;

// Frame type constants
pub const PATH_ACK_TYPE: u64 = 0x3e;
pub const PATH_ACK_ECN_TYPE: u64 = 0x3f;
pub const PATH_ABANDON_TYPE: u64 = 0x3e75;
pub const PATH_STATUS_BACKUP_TYPE: u64 = 0x3e76;
pub const PATH_STATUS_AVAILABLE_TYPE: u64 = 0x3e77;
pub const PATH_NEW_CONNECTION_ID_TYPE: u64 = 0x3e78;
pub const PATH_RETIRE_CONNECTION_ID_TYPE: u64 = 0x3e79;
pub const MAX_PATH_ID_TYPE: u64 = 0x3e7a;
pub const PATHS_BLOCKED_TYPE: u64 = 0x3e7b;
pub const PATH_CIDS_BLOCKED_TYPE: u64 = 0x3e7c;

// PATH_ABANDON error code constants (draft-ietf-quic-multipath-21 §4.2.1)

/// PATH_ABANDON error code: the path is abandoned without error.
///
/// Defined in draft-ietf-quic-multipath-21 §4.2.1.
pub const PATH_ABANDON_NO_ERROR: u64 = 0x0;

/// PATH_ABANDON error code: the path is abandoned at the application's request.
///
/// Defined in draft-ietf-quic-multipath-21 §4.2.1.
pub const APPLICATION_ABANDON_PATH: u64 = 0x3e;

/// PATH_ABANDON error code: cannot allocate sufficient resources to use the path.
///
/// Defined in draft-ietf-quic-multipath-21 §4.2.1.
pub const PATH_RESOURCE_LIMIT_REACHED: u64 = 0x3e75;

/// PATH_ABANDON error code: the path is abandoned due to an unstable interface
/// or poor performance.
///
/// Defined in draft-ietf-quic-multipath-21 §4.2.1.
pub const PATH_UNSTABLE_OR_POOR: u64 = 0x3e76;

/// PATH_ABANDON error code: no connection ID is available for the path.
///
/// Defined in draft-ietf-quic-multipath-21 §4.2.1.
pub const NO_CID_AVAILABLE_FOR_PATH: u64 = 0x3e77;

/// Returns true if the given frame type is a multipath frame.
pub fn is_multipath_frame_type(ty: u64) -> bool {
    matches!(
        ty,
        PATH_ACK_TYPE
            | PATH_ACK_ECN_TYPE
            | PATH_ABANDON_TYPE
            | PATH_STATUS_BACKUP_TYPE
            | PATH_STATUS_AVAILABLE_TYPE
            | PATH_NEW_CONNECTION_ID_TYPE
            | PATH_RETIRE_CONNECTION_ID_TYPE
            | MAX_PATH_ID_TYPE
            | PATHS_BLOCKED_TYPE
            | PATH_CIDS_BLOCKED_TYPE
    )
}

/// Parse a PATH_ACK frame from bytes. The frame type has already been consumed.
pub fn parse_path_ack(
    b: &mut octets::Octets,
    has_ecn: bool,
) -> crate::Result<(u64, u64, RangeSet, Option<EcnCounts>)> {
    let path_id = b.get_varint()?;
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    if largest_ack < ack_block {
        return Err(crate::Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;
    let mut ranges = RangeSet::default();
    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;
        if smallest_ack < gap + 2 {
            return Err(crate::Error::InvalidFrame);
        }
        let largest_ack = smallest_ack - gap - 2;
        let ack_block = b.get_varint()?;
        if largest_ack < ack_block {
            return Err(crate::Error::InvalidFrame);
        }
        smallest_ack = largest_ack - ack_block;
        ranges.insert(smallest_ack..largest_ack + 1);
    }

    let ecn_counts = if has_ecn {
        let ect0 = b.get_varint()?;
        let ect1 = b.get_varint()?;
        let ecn_ce = b.get_varint()?;
        Some(EcnCounts {
            ect0_count: ect0,
            ect1_count: ect1,
            ecn_ce_count: ecn_ce,
        })
    } else {
        None
    };

    Ok((path_id, ack_delay, ranges, ecn_counts))
}

/// Encode a PATH_ACK frame to bytes.
pub fn encode_path_ack(
    b: &mut octets::OctetsMut,
    path_id: u64,
    ack_delay: u64,
    ranges: &RangeSet,
    ecn_counts: &Option<EcnCounts>,
) -> crate::Result<usize> {
    let before = b.cap();

    let ty = if ecn_counts.is_some() {
        PATH_ACK_ECN_TYPE
    } else {
        PATH_ACK_TYPE
    };

    if ranges.len() == 0 {
        return Err(crate::Error::InvalidFrame);
    }

    b.put_varint(ty)?;
    b.put_varint(path_id)?;

    let largest_ack = ranges.last().unwrap_or(0);
    b.put_varint(largest_ack)?;
    b.put_varint(ack_delay)?;

    let blocks: Vec<_> = ranges.iter().rev().collect();
    b.put_varint((blocks.len() - 1) as u64)?;

    let first = &blocks[0];
    b.put_varint(first.end - 1 - first.start)?;

    let mut prev_smallest = first.start;
    for block in &blocks[1..] {
        let gap = prev_smallest - block.end - 1;
        b.put_varint(gap)?;
        b.put_varint(block.end - 1 - block.start)?;
        prev_smallest = block.start;
    }

    if let Some(ecn) = ecn_counts {
        b.put_varint(ecn.ect0_count)?;
        b.put_varint(ecn.ect1_count)?;
        b.put_varint(ecn.ecn_ce_count)?;
    }

    Ok(before - b.cap())
}

// === PATH_ABANDON ===

/// Parse a PATH_ABANDON frame. The frame type has already been consumed.
pub fn parse_path_abandon(
    b: &mut octets::Octets,
) -> crate::Result<(u64, u64)> {
    let path_id = b.get_varint()?;
    let error_code = b.get_varint()?;
    Ok((path_id, error_code))
}

/// Encode a PATH_ABANDON frame.
pub fn encode_path_abandon(
    b: &mut octets::OctetsMut,
    path_id: u64,
    error_code: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_ABANDON_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(error_code)?;
    Ok(before - b.cap())
}

// === PATH_STATUS (Available / Backup) ===

/// Parse a PATH_STATUS frame. The frame type has already been consumed.
pub fn parse_path_status(
    b: &mut octets::Octets,
) -> crate::Result<(u64, u64)> {
    let path_id = b.get_varint()?;
    let seq_num = b.get_varint()?;
    Ok((path_id, seq_num))
}

/// Encode a PATH_STATUS_AVAILABLE frame.
pub fn encode_path_status_available(
    b: &mut octets::OctetsMut,
    path_id: u64,
    seq_num: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_STATUS_AVAILABLE_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(seq_num)?;
    Ok(before - b.cap())
}

/// Encode a PATH_STATUS_BACKUP frame.
pub fn encode_path_status_backup(
    b: &mut octets::OctetsMut,
    path_id: u64,
    seq_num: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_STATUS_BACKUP_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(seq_num)?;
    Ok(before - b.cap())
}

// === MAX_PATH_ID ===

/// Parse a MAX_PATH_ID frame. The frame type has already been consumed.
pub fn parse_max_path_id(b: &mut octets::Octets) -> crate::Result<u64> {
    b.get_varint().map_err(|_| crate::Error::InvalidFrame)
}

/// Encode a MAX_PATH_ID frame.
pub fn encode_max_path_id(
    b: &mut octets::OctetsMut,
    path_id: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(MAX_PATH_ID_TYPE)?;
    b.put_varint(path_id)?;
    Ok(before - b.cap())
}

// === PATHS_BLOCKED ===

/// Parse a PATHS_BLOCKED frame. The frame type has already been consumed.
pub fn parse_paths_blocked(b: &mut octets::Octets) -> crate::Result<u64> {
    b.get_varint().map_err(|_| crate::Error::InvalidFrame)
}

/// Encode a PATHS_BLOCKED frame.
pub fn encode_paths_blocked(
    b: &mut octets::OctetsMut,
    path_id: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATHS_BLOCKED_TYPE)?;
    b.put_varint(path_id)?;
    Ok(before - b.cap())
}

// === PATH_NEW_CONNECTION_ID ===

/// Parse a PATH_NEW_CONNECTION_ID frame. The frame type has already been consumed.
pub fn parse_path_new_connection_id(
    b: &mut octets::Octets,
) -> crate::Result<(u64, u64, u64, u8, Vec<u8>, u128)> {
    use std::convert::TryInto;
    let path_id = b.get_varint()?;
    let seq_num = b.get_varint()?;
    let retire_prior_to = b.get_varint()?;
    let cid_len = b.get_u8()?;
    let cid = b.get_bytes(cid_len as usize)?.to_vec();
    // Read 16 bytes for reset token (u128, big-endian)
    let token_bytes = b.get_bytes(16)?;
    let token_slice: [u8; 16] = token_bytes
        .as_ref()
        .try_into()
        .map_err(|_| crate::Error::InvalidFrame)?;
    let reset_token = u128::from_be_bytes(token_slice);
    Ok((path_id, seq_num, retire_prior_to, cid_len, cid, reset_token))
}

/// Encode a PATH_NEW_CONNECTION_ID frame.
pub fn encode_path_new_connection_id(
    b: &mut octets::OctetsMut,
    path_id: u64,
    seq_num: u64,
    retire_prior_to: u64,
    conn_id: &[u8],
    reset_token: u128,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_NEW_CONNECTION_ID_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(seq_num)?;
    b.put_varint(retire_prior_to)?;
    b.put_u8(conn_id.len() as u8)?;
    b.put_bytes(conn_id)?;
    b.put_bytes(&reset_token.to_be_bytes())?;
    Ok(before - b.cap())
}

// === PATH_RETIRE_CONNECTION_ID ===

/// Parse a PATH_RETIRE_CONNECTION_ID frame. The frame type has already been consumed.
pub fn parse_path_retire_connection_id(
    b: &mut octets::Octets,
) -> crate::Result<(u64, u64)> {
    let path_id = b.get_varint()?;
    let seq_num = b.get_varint()?;
    Ok((path_id, seq_num))
}

/// Encode a PATH_RETIRE_CONNECTION_ID frame.
pub fn encode_path_retire_connection_id(
    b: &mut octets::OctetsMut,
    path_id: u64,
    seq_num: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_RETIRE_CONNECTION_ID_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(seq_num)?;
    Ok(before - b.cap())
}

// === PATH_CIDS_BLOCKED ===

/// Parse a PATH_CIDS_BLOCKED frame. The frame type has already been consumed.
pub fn parse_path_cids_blocked(
    b: &mut octets::Octets,
) -> crate::Result<(u64, u64)> {
    let path_id = b.get_varint()?;
    let seq_num = b.get_varint()?;
    Ok((path_id, seq_num))
}

/// Encode a PATH_CIDS_BLOCKED frame.
pub fn encode_path_cids_blocked(
    b: &mut octets::OctetsMut,
    path_id: u64,
    seq_num: u64,
) -> crate::Result<usize> {
    let before = b.cap();
    b.put_varint(PATH_CIDS_BLOCKED_TYPE)?;
    b.put_varint(path_id)?;
    b.put_varint(seq_num)?;
    Ok(before - b.cap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_ack_roundtrip() {
        let mut ranges = RangeSet::default();
        ranges.insert(0..5);
        ranges.insert(10..15);

        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_ack(&mut b, 3, 100, &ranges, &None).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ACK_TYPE);
        let (path_id, ack_delay, decoded_ranges, ecn) =
            parse_path_ack(&mut b, false).unwrap();
        assert_eq!(path_id, 3);
        assert_eq!(ack_delay, 100);
        assert_eq!(decoded_ranges, ranges);
        assert!(ecn.is_none());
    }

    #[test]
    fn path_ack_with_ecn_roundtrip() {
        let mut ranges = RangeSet::default();
        ranges.insert(0..10);

        let ecn = Some(EcnCounts {
            ect0_count: 5,
            ect1_count: 3,
            ecn_ce_count: 1,
        });

        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_ack(&mut b, 1, 50, &ranges, &ecn).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ACK_ECN_TYPE);
        let (path_id, ack_delay, _, decoded_ecn) =
            parse_path_ack(&mut b, true).unwrap();
        assert_eq!(path_id, 1);
        assert_eq!(ack_delay, 50);
        assert_eq!(decoded_ecn.unwrap().ect0_count, 5);
    }

    #[test]
    fn path_abandon_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_abandon(&mut b, 5, 0x0a).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 5);
        assert_eq!(error_code, 0x0a);
    }

    #[test]
    fn path_status_available_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_status_available(&mut b, 2, 1).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_STATUS_AVAILABLE_TYPE);
        let (path_id, seq_num) = parse_path_status(&mut b).unwrap();
        assert_eq!(path_id, 2);
        assert_eq!(seq_num, 1);
    }

    #[test]
    fn path_status_backup_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_status_backup(&mut b, 3, 5).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_STATUS_BACKUP_TYPE);
        let (path_id, seq_num) = parse_path_status(&mut b).unwrap();
        assert_eq!(path_id, 3);
        assert_eq!(seq_num, 5);
    }

    #[test]
    fn max_path_id_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_max_path_id(&mut b, 10).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, MAX_PATH_ID_TYPE);
        let path_id = parse_max_path_id(&mut b).unwrap();
        assert_eq!(path_id, 10);
    }

    #[test]
    fn paths_blocked_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_paths_blocked(&mut b, 7).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATHS_BLOCKED_TYPE);
        let path_id = parse_paths_blocked(&mut b).unwrap();
        assert_eq!(path_id, 7);
    }

    #[test]
    fn path_new_connection_id_roundtrip() {
        let cid = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let token: u128 = 0xdeadbeef_cafebabe_12345678_9abcdef0;
        let mut buf = [0u8; 256];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_new_connection_id(&mut b, 2, 5, 3, &cid, token)
                .unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_NEW_CONNECTION_ID_TYPE);
        let (path_id, seq_num, retire_prior_to, cid_len, decoded_cid, decoded_token) =
            parse_path_new_connection_id(&mut b).unwrap();
        assert_eq!(path_id, 2);
        assert_eq!(seq_num, 5);
        assert_eq!(retire_prior_to, 3);
        assert_eq!(cid_len, 8);
        assert_eq!(decoded_cid, cid);
        assert_eq!(decoded_token, token);
    }

    #[test]
    fn path_retire_connection_id_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_retire_connection_id(&mut b, 1, 3).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_RETIRE_CONNECTION_ID_TYPE);
        let (path_id, seq_num) = parse_path_retire_connection_id(&mut b).unwrap();
        assert_eq!(path_id, 1);
        assert_eq!(seq_num, 3);
    }

    #[test]
    fn path_cids_blocked_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len = encode_path_cids_blocked(&mut b, 4, 2).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_CIDS_BLOCKED_TYPE);
        let (path_id, seq_num) = parse_path_cids_blocked(&mut b).unwrap();
        assert_eq!(path_id, 4);
        assert_eq!(seq_num, 2);
    }

    // PATH_ABANDON error code round-trip tests (draft-ietf-quic-multipath-21 §4.2.1)

    #[test]
    fn path_abandon_no_error_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_abandon(&mut b, 0, PATH_ABANDON_NO_ERROR).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 0);
        assert_eq!(error_code, PATH_ABANDON_NO_ERROR);
    }

    #[test]
    fn path_abandon_application_abandon_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_abandon(&mut b, 1, APPLICATION_ABANDON_PATH).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 1);
        assert_eq!(error_code, APPLICATION_ABANDON_PATH);
    }

    #[test]
    fn path_abandon_resource_limit_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_abandon(&mut b, 2, PATH_RESOURCE_LIMIT_REACHED)
                .unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 2);
        assert_eq!(error_code, PATH_RESOURCE_LIMIT_REACHED);
    }

    #[test]
    fn path_abandon_unstable_or_poor_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_abandon(&mut b, 3, PATH_UNSTABLE_OR_POOR).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 3);
        assert_eq!(error_code, PATH_UNSTABLE_OR_POOR);
    }

    #[test]
    fn path_abandon_no_cid_available_roundtrip() {
        let mut buf = [0u8; 64];
        let mut b = octets::OctetsMut::with_slice(&mut buf);
        let len =
            encode_path_abandon(&mut b, 4, NO_CID_AVAILABLE_FOR_PATH).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..len]);
        let ty = b.get_varint().unwrap();
        assert_eq!(ty, PATH_ABANDON_TYPE);
        let (path_id, error_code) = parse_path_abandon(&mut b).unwrap();
        assert_eq!(path_id, 4);
        assert_eq!(error_code, NO_CID_AVAILABLE_FOR_PATH);
    }
}
