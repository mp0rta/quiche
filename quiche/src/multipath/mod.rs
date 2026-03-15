//! Multipath QUIC support (draft-ietf-quic-multipath-20).

pub mod scheduler;
pub mod schedulers;
pub mod reinjection;
pub(crate) mod frames;
pub(crate) mod pktns;

use crate::path::PathMap;
use crate::recovery::RecoveryOps;

/// Refresh the PathInfo buffer from current path state.
///
/// Iterates all paths in the `PathMap`, skips any that are already closed
/// (`mp_closed`), and populates `buf` with a snapshot of each path's
/// scheduling-relevant metrics.
#[allow(dead_code)]
pub(crate) fn refresh_path_info(
    paths: &PathMap,
    buf: &mut Vec<scheduler::PathInfo>,
) {
    buf.clear();
    for (_, path) in paths.iter() {
        // Skip paths that have been fully closed in the multipath sense.
        if path.mp_closed {
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
            // TODO: expose delivery rate from recovery.
            est_bandwidth_bps: None,
            // TODO: compute loss_rate from path statistics.
            loss_rate: 0.0,
            mtu: path.recovery.max_datagram_size(),
        });
    }
}


