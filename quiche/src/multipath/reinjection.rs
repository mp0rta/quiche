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
