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
        packet: &PacketMeta,
    ) -> SchedulerDecision {
        if paths.is_empty() {
            return SchedulerDecision::NoAvailablePath;
        }

        let now = packet.now;

        // For reinjections, try to avoid the path the original was lost on.
        let skip_path_id = if packet.is_reinjection {
            packet.original_path_id
        } else {
            None
        };

        for pass in 0..2usize {
            let skip = |p: &&PathInfo| -> bool {
                pass == 0 && Some(p.path_id) == skip_path_id
            };

            // Tier 1: ready (not pacing-delayed) Available paths.
            let ready: Vec<&PathInfo> = paths
                .iter()
                .filter(|p| {
                    !skip(p)
                        && p.state >= PathState::Validated
                        && p.cwnd_available > 0
                        && p.app_status == PathAppStatus::Available
                        && p.next_send_time.map_or(true, |t| t <= now)
                })
                .collect();

            if !ready.is_empty() {
                self.last_index %= ready.len();
                let chosen = ready[self.last_index].path_id;
                self.last_index = (self.last_index + 1) % ready.len();
                return SchedulerDecision::Send(chosen);
            }

            // Tier 2: all Available paths with cwnd (including pacing-delayed).
            let usable: Vec<&PathInfo> = paths
                .iter()
                .filter(|p| {
                    !skip(p)
                        && p.state >= PathState::Validated
                        && p.cwnd_available > 0
                        && p.app_status == PathAppStatus::Available
                })
                .collect();

            if !usable.is_empty() {
                self.last_index %= usable.len();
                let chosen = usable[self.last_index].path_id;
                self.last_index = (self.last_index + 1) % usable.len();
                return SchedulerDecision::Send(chosen);
            }

            // Tier 3: Backup paths.
            let backup: Vec<&PathInfo> = paths
                .iter()
                .filter(|p| {
                    !skip(p)
                        && p.state >= PathState::Validated
                        && p.cwnd_available > 0
                        && p.app_status == PathAppStatus::Backup
                })
                .collect();

            if !backup.is_empty() {
                self.last_index %= backup.len();
                let chosen = backup[self.last_index].path_id;
                self.last_index = (self.last_index + 1) % backup.len();
                return SchedulerDecision::Send(chosen);
            }

            // No candidates found in this pass.
            // If there's no path to skip, no point doing a second pass.
            if skip_path_id.is_none() {
                break;
            }
        }

        let any_validated = paths.iter().any(|p| p.state >= PathState::Validated);
        if any_validated {
            SchedulerDecision::AllBlocked
        } else {
            SchedulerDecision::NoAvailablePath
        }
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
            next_send_time: None,
            pacing_rate_bps: None,
        }
    }

    fn default_packet() -> PacketMeta {
        PacketMeta {
            packet_type: PacketContentType::Stream,
            size_estimate: 1200,
            is_retransmission: false,
            is_reinjection: false,
            original_path_id: None,
            now: std::time::Instant::now(),
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
    fn prefers_ready_paths_in_round_robin() {
        let mut sched = RoundRobinScheduler::default();
        let now = std::time::Instant::now();
        let future = now + Duration::from_millis(50);

        let paths = vec![
            {
                let mut p =
                    make_path(0, 50, 10000, PathAppStatus::Available);
                p.next_send_time = Some(future); // delayed
                p
            },
            {
                let mut p =
                    make_path(1, 50, 10000, PathAppStatus::Available);
                p.next_send_time = None; // ready
                p
            },
            {
                let mut p =
                    make_path(2, 50, 10000, PathAppStatus::Available);
                p.next_send_time = None; // ready
                p
            },
        ];

        let mut pkt = default_packet();
        pkt.now = now;

        let d1 = sched.select_path(&paths, &pkt);
        let d2 = sched.select_path(&paths, &pkt);
        let d3 = sched.select_path(&paths, &pkt);

        assert_eq!(d1, SchedulerDecision::Send(1));
        assert_eq!(d2, SchedulerDecision::Send(2));
        assert_eq!(d3, SchedulerDecision::Send(1)); // wraps around
    }

    #[test]
    fn empty_returns_no_available() {
        let mut sched = RoundRobinScheduler::default();
        assert_eq!(
            sched.select_path(&[], &default_packet()),
            SchedulerDecision::NoAvailablePath,
        );
    }

    #[test]
    fn reinjection_avoids_original_path() {
        let mut sched = RoundRobinScheduler::default();
        let paths = vec![
            make_path(0, 10, 10000, PathAppStatus::Available),
            make_path(1, 50, 10000, PathAppStatus::Available),
        ];
        let packet = PacketMeta {
            is_reinjection: true,
            original_path_id: Some(0),
            ..default_packet()
        };
        assert_eq!(sched.select_path(&paths, &packet), SchedulerDecision::Send(1));
    }

    #[test]
    fn reinjection_fallback_single_path() {
        let mut sched = RoundRobinScheduler::default();
        let paths = vec![
            make_path(0, 10, 10000, PathAppStatus::Available),
        ];
        let packet = PacketMeta {
            is_reinjection: true,
            original_path_id: Some(0),
            ..default_packet()
        };
        assert_eq!(sched.select_path(&paths, &packet), SchedulerDecision::Send(0));
    }
}
