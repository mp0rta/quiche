//! Scheduler trait and types for multipath packet scheduling.

use std::net::SocketAddr;
use std::time::Duration;

use crate::path::PathAppStatus;
use crate::path::PathState;

/// Read-only view of path state for scheduler decisions.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path_id: u64,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub state: PathState,
    pub app_status: PathAppStatus,
    pub srtt: Duration,
    pub rttvar: Duration,
    pub min_rtt: Option<Duration>,
    pub cwnd: usize,
    pub cwnd_available: usize,
    pub bytes_in_flight: usize,
    pub est_bandwidth_bps: Option<u64>,
    pub loss_rate: f64,
    pub mtu: usize,
}

/// Metadata about the packet being scheduled.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub packet_type: PacketContentType,
    pub size_estimate: usize,
    pub is_retransmission: bool,
    pub is_reinjection: bool,
    pub original_path_id: Option<u64>,
}

/// Type of content in the packet being scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketContentType {
    Stream,
    Datagram,
    Control,
}

/// Path-level events for the scheduler.
#[derive(Debug, Clone)]
pub enum SchedulerPathEvent {
    Activated(u64),
    CwndAvailable(u64),
    Congested(u64),
    Lost(u64),
    Closed(u64),
    StatusChanged(u64, PathAppStatus),
}

/// Connection-level events for the scheduler.
#[derive(Debug, Clone, Copy)]
pub enum SchedulerConnEvent {
    RoundStart,
    RoundEnd,
}

/// Result of a scheduling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerDecision {
    Send(u64),
    AllBlocked,
    NoAvailablePath,
}

/// Core scheduler trait. Implement this to create custom schedulers.
pub trait Scheduler: Send {
    fn select_path(
        &mut self,
        paths: &[PathInfo],
        packet: &PacketMeta,
    ) -> SchedulerDecision;

    fn on_path_event(&mut self, _event: SchedulerPathEvent) {}
    fn on_conn_event(&mut self, _event: SchedulerConnEvent) {}
}

/// Factory for creating per-connection scheduler instances.
pub trait SchedulerFactory: Send + Sync {
    fn create(&self) -> Box<dyn Scheduler>;
}

/// Built-in scheduler algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathSchedulerAlgorithm {
    MinRtt,
    RoundRobin,
}
