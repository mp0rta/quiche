//! RoundRobin scheduler — distributes packets evenly across paths.

use super::super::scheduler::*;
use crate::path::PathAppStatus;
use crate::path::PathState;

/// Distributes packets round-robin across available paths.
/// Skips congestion-blocked paths.
#[derive(Debug, Default)]
pub struct RoundRobinScheduler {
    last_index: usize,
}

impl Scheduler for RoundRobinScheduler {
    fn select_path(
        &mut self,
        paths: &[PathInfo],
        _packet: &PacketMeta,
    ) -> SchedulerDecision {
        if paths.is_empty() {
            return SchedulerDecision::NoAvailablePath;
        }

        let usable: Vec<&PathInfo> = paths
            .iter()
            .filter(|p| {
                p.state >= PathState::Validated
                    && p.cwnd_available > 0
                    && p.app_status == PathAppStatus::Available
            })
            .collect();

        if usable.is_empty() {
            let backup: Vec<&PathInfo> = paths
                .iter()
                .filter(|p| {
                    p.state >= PathState::Validated
                        && p.cwnd_available > 0
                        && p.app_status == PathAppStatus::Backup
                })
                .collect();

            if backup.is_empty() {
                let any_validated = paths
                    .iter()
                    .any(|p| p.state >= PathState::Validated);
                return if any_validated {
                    SchedulerDecision::AllBlocked
                } else {
                    SchedulerDecision::NoAvailablePath
                };
            }

            self.last_index %= backup.len();
            let chosen = backup[self.last_index].path_id;
            self.last_index = (self.last_index + 1) % backup.len();
            return SchedulerDecision::Send(chosen);
        }

        self.last_index %= usable.len();
        let chosen = usable[self.last_index].path_id;
        self.last_index = (self.last_index + 1) % usable.len();
        SchedulerDecision::Send(chosen)
    }
}

/// Factory for RoundRobinScheduler.
#[derive(Debug, Default)]
pub struct RoundRobinSchedulerFactory;

impl SchedulerFactory for RoundRobinSchedulerFactory {
    fn create(&self) -> Box<dyn Scheduler> {
        Box::new(RoundRobinScheduler::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_path(id: u64, srtt_ms: u64, cwnd_avail: usize,
                 status: PathAppStatus) -> PathInfo {
        PathInfo {
            path_id: id,
            local_addr: "127.0.0.1:1234".parse().unwrap(),
            peer_addr: "127.0.0.1:5678".parse().unwrap(),
            state: PathState::Validated,
            app_status: status,
            srtt: Duration::from_millis(srtt_ms),
            rttvar: Duration::from_millis(5),
            min_rtt: Some(Duration::from_millis(srtt_ms)),
            cwnd: 65535,
            cwnd_available: cwnd_avail,
            bytes_in_flight: 0,
            est_bandwidth_bps: None,
            loss_rate: 0.0,
            mtu: 1200,
        }
    }

    fn default_packet() -> PacketMeta {
        PacketMeta {
            packet_type: PacketContentType::Stream,
            size_estimate: 1200,
            is_retransmission: false,
            is_reinjection: false,
            original_path_id: None,
        }
    }

    #[test]
    fn round_robin_distributes_evenly() {
        let mut sched = RoundRobinScheduler::default();
        let paths = vec![
            make_path(0, 50, 10000, PathAppStatus::Available),
            make_path(1, 50, 10000, PathAppStatus::Available),
            make_path(2, 50, 10000, PathAppStatus::Available),
        ];
        let pkt = default_packet();

        assert_eq!(sched.select_path(&paths, &pkt), SchedulerDecision::Send(0));
        assert_eq!(sched.select_path(&paths, &pkt), SchedulerDecision::Send(1));
        assert_eq!(sched.select_path(&paths, &pkt), SchedulerDecision::Send(2));
        assert_eq!(sched.select_path(&paths, &pkt), SchedulerDecision::Send(0));
    }

    #[test]
    fn skips_blocked_paths() {
        let mut sched = RoundRobinScheduler::default();
        let paths = vec![
            make_path(0, 50, 0, PathAppStatus::Available),
            make_path(1, 50, 10000, PathAppStatus::Available),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::Send(1),
        );
    }

    #[test]
    fn empty_returns_no_available() {
        let mut sched = RoundRobinScheduler::default();
        assert_eq!(
            sched.select_path(&[], &default_packet()),
            SchedulerDecision::NoAvailablePath,
        );
    }
}
