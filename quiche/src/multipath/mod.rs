//! Multipath QUIC support (draft-ietf-quic-multipath-20).

pub mod scheduler;
pub mod schedulers;
pub mod reinjection;
pub(crate) mod frames;
pub(crate) mod pktns;

use std::time::Instant;

use crate::path::PathMap;
use crate::recovery::RecoveryOps;

/// Refresh the PathInfo buffer from current path state.
///
/// Iterates all paths in the `PathMap`, skips any that are already closed
/// (`mp_closed`), and populates `buf` with a snapshot of each path's
/// scheduling-relevant metrics.
pub(crate) fn refresh_path_info(
    paths: &PathMap,
    buf: &mut Vec<scheduler::PathInfo>,
    now: Instant,
) {
    buf.clear();
    for (_, path) in paths.iter() {
        // Skip paths that are closing or already closed — the scheduler
        // must not select them for new data.
        if path.mp_closing || path.mp_closed {
            continue;
        }
        buf.push(scheduler::PathInfo {
            path_id: path.path_id,
            local_addr: path.local_addr(),
            peer_addr: path.peer_addr(),
            state: path.state(),
            app_status: path.app_status,
            srtt: path.recovery.rtt(),
            rttvar: path.recovery.rttvar(),
            // TODO: expose min_rtt from recovery when available.
            min_rtt: path.recovery.min_rtt(),
            cwnd: path.recovery.cwnd(),
            cwnd_available: path.recovery.cwnd_available(),
            bytes_in_flight: path.recovery.bytes_in_flight(),
            est_bandwidth_bps: Some(
                path.recovery.delivery_rate().to_bits_per_second(),
            ),
            loss_rate: {
                let total =
                    path.total_acked_bytes + path.recovery.bytes_lost();
                if total > 0 {
                    path.recovery.bytes_lost() as f64 / total as f64
                } else {
                    0.0
                }
            },
            mtu: path.recovery.max_datagram_size(),
            next_send_time: path.recovery.get_next_release_time().time(now),
            pacing_rate_bps: Some(path.recovery.pacing_rate() * 8),
        });
    }
}


