//! MinRTT scheduler — selects path with lowest smoothed RTT.

use super::super::scheduler::*;
use crate::path::PathAppStatus;
use crate::path::PathState;

/// Selects the path with the lowest smoothed RTT among Available paths.
/// Falls back to Backup paths when all Available paths are blocked.
#[derive(Debug, Default)]
pub struct MinRttScheduler;

impl Scheduler for MinRttScheduler {
    fn select_path(
        &mut self,
        paths: &[PathInfo],
        _packet: &PacketMeta,
    ) -> SchedulerDecision {
        let mut best_available: Option<(u64, std::time::Duration)> = None;
        let mut best_backup: Option<(u64, std::time::Duration)> = None;
        let mut has_validated = false;

        for p in paths {
            if p.state < PathState::Validated {
                continue;
            }
            has_validated = true;

            if p.cwnd_available == 0 {
                continue;
            }

            let target = match p.app_status {
                PathAppStatus::Available => &mut best_available,
                PathAppStatus::Backup => &mut best_backup,
            };

            match target {
                Some((_, rtt)) if p.srtt < *rtt => {
                    *target = Some((p.path_id, p.srtt));
                }
                None => {
                    *target = Some((p.path_id, p.srtt));
                }
                _ => {}
            }
        }

        if let Some((id, _)) = best_available {
            SchedulerDecision::Send(id)
        } else if let Some((id, _)) = best_backup {
            SchedulerDecision::Send(id)
        } else if has_validated {
            SchedulerDecision::AllBlocked
        } else {
            SchedulerDecision::NoAvailablePath
        }
    }
}

/// Factory for MinRttScheduler.
#[derive(Debug, Default)]
pub struct MinRttSchedulerFactory;

impl SchedulerFactory for MinRttSchedulerFactory {
    fn create(&self) -> Box<dyn Scheduler> {
        Box::new(MinRttScheduler)
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
    fn selects_lowest_rtt() {
        let mut sched = MinRttScheduler;
        let paths = vec![
            make_path(0, 50, 10000, PathAppStatus::Available),
            make_path(1, 20, 10000, PathAppStatus::Available),
            make_path(2, 80, 10000, PathAppStatus::Available),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::Send(1),
        );
    }

    #[test]
    fn skips_blocked_paths() {
        let mut sched = MinRttScheduler;
        let paths = vec![
            make_path(0, 10, 0, PathAppStatus::Available),
            make_path(1, 50, 10000, PathAppStatus::Available),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::Send(1),
        );
    }

    #[test]
    fn falls_back_to_backup() {
        let mut sched = MinRttScheduler;
        let paths = vec![
            make_path(0, 10, 0, PathAppStatus::Available),
            make_path(1, 30, 10000, PathAppStatus::Backup),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::Send(1),
        );
    }

    #[test]
    fn all_blocked_returns_all_blocked() {
        let mut sched = MinRttScheduler;
        let paths = vec![
            make_path(0, 10, 0, PathAppStatus::Available),
            make_path(1, 20, 0, PathAppStatus::Available),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::AllBlocked,
        );
    }

    #[test]
    fn empty_paths_returns_no_available() {
        let mut sched = MinRttScheduler;
        assert_eq!(
            sched.select_path(&[], &default_packet()),
            SchedulerDecision::NoAvailablePath,
        );
    }

    #[test]
    fn unvalidated_paths_skipped() {
        let mut sched = MinRttScheduler;
        let mut p = make_path(0, 10, 10000, PathAppStatus::Available);
        p.state = PathState::Validating;
        assert_eq!(
            sched.select_path(&[p], &default_packet()),
            SchedulerDecision::NoAvailablePath,
        );
    }

    #[test]
    fn factory_creates_scheduler() {
        let factory = MinRttSchedulerFactory;
        let mut sched = factory.create();
        let paths = vec![
            make_path(0, 50, 10000, PathAppStatus::Available),
        ];
        assert_eq!(
            sched.select_path(&paths, &default_packet()),
            SchedulerDecision::Send(0),
        );
    }
}
