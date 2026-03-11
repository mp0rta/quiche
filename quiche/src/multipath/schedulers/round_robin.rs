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

            self.last_index = (self.last_index) % backup.len();
            let chosen = backup[self.last_index].path_id;
            self.last_index = (self.last_index + 1) % backup.len();
            return SchedulerDecision::Send(chosen);
        }

        self.last_index = (self.last_index) % usable.len();
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
