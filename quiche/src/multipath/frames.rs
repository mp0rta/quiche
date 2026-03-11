//! Multipath-specific frame parsing and generation.
//!
//! Frame type codes per draft-ietf-quic-multipath-20:
//!   PATH_ACK:                    0x3e / 0x3f (with ECN)
//!   PATH_ABANDON:                0x3e75
//!   PATH_STATUS_BACKUP:          0x3e76
//!   PATH_STATUS_AVAILABLE:       0x3e77
//!   PATH_NEW_CONNECTION_ID:      0x3e78
//!   PATH_RETIRE_CONNECTION_ID:   0x3e79
//!   MAX_PATH_ID:                 0x3e7a
//!   PATHS_BLOCKED:               0x3e7b
//!   PATH_CIDS_BLOCKED:           0x3e7c

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
