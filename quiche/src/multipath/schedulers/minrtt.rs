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
