//! Per-path packet number space management and nonce computation.

/// Compute the multipath AEAD nonce using PPN (Path and Packet Number).
///
/// Implements draft-ietf-quic-multipath Section 5.1: the 96-bit PPN is:
///   Bits 95-64: path_id (lower 32 bits, network byte order)
///   Bits 63-62: 00 (2 zero bits)
///   Bits 61-0:  packet_number (62 bits, network byte order)
///
/// The nonce is: N = IV ^ PPN
///
/// Note: `path_id` is truncated to 32 bits per the spec. The QUIC path_id
/// is a varint (up to 62 bits) but only the lower 32 bits are used in the
/// nonce computation.
///
/// Used by the crypto layer to compute per-path multipath AEAD nonces.
pub fn compute_nonce_mp(
    iv: &[u8],
    pkt_num: u64,
    path_id: u32,
) -> [u8; 12] {
    debug_assert!(iv.len() == 12);
    debug_assert!(pkt_num < (1u64 << 62), "packet number exceeds 62 bits");

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);

    let path_id_bytes = path_id.to_be_bytes();
    for i in 0..4 {
        nonce[i] ^= path_id_bytes[i];
    }

    let pn_bytes = pkt_num.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_zero_inputs() {
        let iv = [0u8; 12];
        let nonce = compute_nonce_mp(&iv, 0, 0);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn nonce_path_id_only() {
        let iv = [0u8; 12];
        let nonce = compute_nonce_mp(&iv, 0, 1);
        assert_eq!(nonce[0..4], [0, 0, 0, 1]);
        assert_eq!(nonce[4..12], [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn nonce_pkt_num_only() {
        let iv = [0u8; 12];
        let nonce = compute_nonce_mp(&iv, 1, 0);
        assert_eq!(nonce[0..4], [0, 0, 0, 0]);
        assert_eq!(nonce[4..12], [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn nonce_xors_with_iv() {
        let iv = [0xff; 12];
        let nonce = compute_nonce_mp(&iv, 0, 0);
        assert_eq!(nonce, [0xff; 12]);
    }

    #[test]
    fn nonce_combined() {
        let iv = [0u8; 12];
        let nonce = compute_nonce_mp(&iv, 42, 7);
        let expected_path = 7u32.to_be_bytes();
        let expected_pn = 42u64.to_be_bytes();
        assert_eq!(nonce[0..4], expected_path);
        assert_eq!(nonce[4..12], expected_pn);
    }

    #[test]
    #[should_panic(expected = "packet number exceeds 62 bits")]
    fn nonce_pkt_num_too_large() {
        let iv = [0u8; 12];
        compute_nonce_mp(&iv, 1u64 << 62, 0);
    }
}
