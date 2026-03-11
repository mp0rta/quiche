//! Reinjection controller trait and default implementation.

use std::time::Duration;
use std::time::Instant;

use super::scheduler::PacketContentType;
use super::scheduler::PathInfo;

/// Application-provided QoS requirements per stream.
#[derive(Debug, Clone)]
pub struct StreamQosHint {
    pub stream_id: u64,
    pub deadline: Option<Duration>,
    pub priority: u8,
    pub redundant: bool,
}

/// When to perform reinjection relative to normal scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinjectionMode {
    AfterScheduling,
    BeforeScheduling,
}

impl Default for ReinjectionMode {
    fn default() -> Self {
        ReinjectionMode::AfterScheduling
    }
}

/// Information about a packet that is a candidate for reinjection.
#[derive(Debug, Clone)]
pub struct ReinjectionCandidate {
    pub packet_number: u64,
    pub original_path_id: u64,
    pub sent_time: Instant,
    pub size: usize,
    pub content_type: PacketContentType,
    pub is_already_reinjected: bool,
}

/// Context for reinjection decisions.
pub struct ReinjectionContext<'a> {
    pub original_path: &'a PathInfo,
    pub all_paths: &'a [PathInfo],
    pub elapsed_since_sent: Duration,
    pub qos_hint: Option<&'a StreamQosHint>,
}

/// Implement this trait to create custom reinjection strategies.
pub trait ReinjectionController: Send {
    fn should_reinject(
        &mut self,
        candidate: &ReinjectionCandidate,
        ctx: &ReinjectionContext,
    ) -> bool;
}

/// Factory for creating per-connection reinjection controller instances.
pub trait ReinjectionControllerFactory: Send + Sync {
    fn create(&self) -> Box<dyn ReinjectionController>;
}

/// RTT-based reinjection controller.
#[derive(Debug)]
pub struct DefaultReinjectionController {
    pub rtt_multiplier: f64,
}

impl Default for DefaultReinjectionController {
    fn default() -> Self {
        Self {
            rtt_multiplier: 1.5,
        }
    }
}

impl ReinjectionController for DefaultReinjectionController {
    fn should_reinject(
        &mut self,
        candidate: &ReinjectionCandidate,
        ctx: &ReinjectionContext,
    ) -> bool {
        if candidate.is_already_reinjected {
            return false;
        }

        if let Some(hint) = ctx.qos_hint {
            if hint.redundant {
                return true;
            }
        }

        let base_threshold = ctx
            .original_path
            .srtt
            .mul_f64(self.rtt_multiplier);

        let threshold = if let Some(hint) = ctx.qos_hint {
            if let Some(deadline) = hint.deadline {
                let best_alt_srtt = ctx
                    .all_paths
                    .iter()
                    .filter(|p| p.path_id != candidate.original_path_id)
                    .filter(|p| p.cwnd_available > 0)
                    .map(|p| p.srtt)
                    .min()
                    .unwrap_or(ctx.original_path.srtt);

                let deadline_threshold = deadline
                    .checked_sub(best_alt_srtt)
                    .unwrap_or(Duration::ZERO);

                let priority_factor =
                    1.0 - (hint.priority as f64 / 255.0) * 0.5;
                let adjusted = base_threshold.mul_f64(priority_factor);

                adjusted.min(deadline_threshold)
            } else {
                base_threshold
            }
        } else {
            base_threshold
        };

        ctx.elapsed_since_sent > threshold
    }
}

/// Factory for DefaultReinjectionController.
#[derive(Debug)]
pub struct DefaultReinjectionControllerFactory {
    pub rtt_multiplier: f64,
}

impl Default for DefaultReinjectionControllerFactory {
    fn default() -> Self {
        Self {
            rtt_multiplier: 1.5,
        }
    }
}

impl ReinjectionControllerFactory for DefaultReinjectionControllerFactory {
    fn create(&self) -> Box<dyn ReinjectionController> {
        Box::new(DefaultReinjectionController {
            rtt_multiplier: self.rtt_multiplier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_path(id: u64, srtt_ms: u64) -> PathInfo {
        use crate::path::{PathAppStatus, PathState};
        PathInfo {
            path_id: id,
            local_addr: "127.0.0.1:1234".parse().unwrap(),
            peer_addr: "127.0.0.1:5678".parse().unwrap(),
            state: PathState::Validated,
            app_status: PathAppStatus::Available,
            srtt: Duration::from_millis(srtt_ms),
            rttvar: Duration::from_millis(5),
            min_rtt: Some(Duration::from_millis(srtt_ms)),
            cwnd: 65535,
            cwnd_available: 10000,
            bytes_in_flight: 0,
            est_bandwidth_bps: None,
            loss_rate: 0.0,
            mtu: 1200,
        }
    }

    fn make_candidate(path_id: u64, elapsed_ms: u64) -> ReinjectionCandidate {
        ReinjectionCandidate {
            packet_number: 42,
            original_path_id: path_id,
            sent_time: Instant::now() - Duration::from_millis(elapsed_ms),
            size: 1200,
            content_type: PacketContentType::Stream,
            is_already_reinjected: false,
        }
    }

    #[test]
    fn no_reinject_when_under_threshold() {
        let mut ctrl = DefaultReinjectionController::default();
        let paths = vec![make_path(0, 100), make_path(1, 50)];
        let candidate = make_candidate(0, 100);
        let ctx = ReinjectionContext {
            original_path: &paths[0],
            all_paths: &paths,
            elapsed_since_sent: Duration::from_millis(100),
            qos_hint: None,
        };
        assert!(!ctrl.should_reinject(&candidate, &ctx));
    }

    #[test]
    fn reinject_when_over_threshold() {
        let mut ctrl = DefaultReinjectionController::default();
        let paths = vec![make_path(0, 100), make_path(1, 50)];
        let candidate = make_candidate(0, 200);
        let ctx = ReinjectionContext {
            original_path: &paths[0],
            all_paths: &paths,
            elapsed_since_sent: Duration::from_millis(200),
            qos_hint: None,
        };
        assert!(ctrl.should_reinject(&candidate, &ctx));
    }

    #[test]
    fn no_reinject_already_reinjected() {
        let mut ctrl = DefaultReinjectionController::default();
        let paths = vec![make_path(0, 100), make_path(1, 50)];
        let mut candidate = make_candidate(0, 200);
        candidate.is_already_reinjected = true;
        let ctx = ReinjectionContext {
            original_path: &paths[0],
            all_paths: &paths,
            elapsed_since_sent: Duration::from_millis(200),
            qos_hint: None,
        };
        assert!(!ctrl.should_reinject(&candidate, &ctx));
    }

    #[test]
    fn redundant_stream_always_reinjects() {
        let mut ctrl = DefaultReinjectionController::default();
        let paths = vec![make_path(0, 100), make_path(1, 50)];
        let candidate = make_candidate(0, 1);
        let hint = StreamQosHint {
            stream_id: 0,
            deadline: None,
            priority: 0,
            redundant: true,
        };
        let ctx = ReinjectionContext {
            original_path: &paths[0],
            all_paths: &paths,
            elapsed_since_sent: Duration::from_millis(1),
            qos_hint: Some(&hint),
        };
        assert!(ctrl.should_reinject(&candidate, &ctx));
    }
}
