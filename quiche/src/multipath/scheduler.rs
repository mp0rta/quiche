//! Scheduler trait and types for multipath packet scheduling.

use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use crate::path::PathAppStatus;
use crate::path::PathState;

/// Read-only view of path state for scheduler decisions.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Unique identifier for this path.
    pub path_id: u64,
    /// Local socket address for this path.
    pub local_addr: SocketAddr,
    /// Remote peer socket address for this path.
    pub peer_addr: SocketAddr,
    /// Current validation state of this path.
    pub state: PathState,
    /// Application-level status of this path (available, backup, etc.).
    pub app_status: PathAppStatus,
    /// Smoothed round-trip time estimate for this path.
    pub srtt: Duration,
    /// Round-trip time variation for this path.
    pub rttvar: Duration,
    /// Minimum observed round-trip time, if available.
    pub min_rtt: Option<Duration>,
    /// Current congestion window size in bytes.
    pub cwnd: usize,
    /// Available congestion window space in bytes.
    pub cwnd_available: usize,
    /// Number of bytes currently in flight on this path.
    pub bytes_in_flight: usize,
    /// Estimated bandwidth in bits per second, if available.
    pub est_bandwidth_bps: Option<u64>,
    /// Estimated packet loss rate (0.0 = no loss, 1.0 = all lost).
    pub loss_rate: f64,
    /// Maximum transmission unit for this path in bytes.
    pub mtu: usize,
    /// Next time this path's pacer allows sending, if pacing-delayed.
    /// `None` means the path is ready to send immediately.
    pub next_send_time: Option<Instant>,
    /// Pacing rate in bits per second, if available.
    /// `Some(0)` means pacing is not available (legacy recovery).
    pub pacing_rate_bps: Option<u64>,
}

/// Metadata about the packet being scheduled.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// The type of content carried in this packet.
    pub packet_type: PacketContentType,
    /// Estimated size of the packet in bytes.
    pub size_estimate: usize,
    /// Whether this packet is a retransmission of previously sent data.
    pub is_retransmission: bool,
    /// Whether this packet is a reinjection onto an alternate path.
    pub is_reinjection: bool,
    /// The path ID the packet was originally sent on, if applicable.
    pub original_path_id: Option<u64>,
}

/// Type of content in the packet being scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketContentType {
    /// QUIC stream data.
    Stream,
    /// QUIC datagram (unreliable).
    Datagram,
    /// QUIC control frames (ACK, etc.).
    Control,
}

/// Path-level events for the scheduler.
#[derive(Debug, Clone)]
pub enum SchedulerPathEvent {
    /// A path became active and ready for use.
    Activated(u64),
    /// Congestion window became available on the given path.
    CwndAvailable(u64),
    /// A path became congestion-blocked.
    Congested(u64),
    /// Packet loss was detected on the given path.
    Lost(u64),
    /// A path was closed and is no longer available.
    Closed(u64),
    /// The application-level status of a path changed.
    StatusChanged(u64, PathAppStatus),
}

/// Connection-level events for the scheduler.
#[derive(Debug, Clone, Copy)]
pub enum SchedulerConnEvent {
    /// A new scheduling round has started.
    RoundStart,
    /// The current scheduling round has ended.
    RoundEnd,
}

/// Result of a scheduling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerDecision {
    /// Send the packet on the path with the given path ID.
    Send(u64),
    /// All validated paths are congestion-blocked; retry later.
    AllBlocked,
    /// No validated path is available for sending.
    NoAvailablePath,
}

/// Core scheduler trait. Implement this to create custom schedulers.
pub trait Scheduler: Send + Sync {
    /// Select the path to send a packet on.
    ///
    /// Given the current snapshot of all path states and metadata about the
    /// packet to be sent, returns a [`SchedulerDecision`] indicating which
    /// path to use or why no path is available.
    fn select_path(
        &mut self,
        paths: &[PathInfo],
        packet: &PacketMeta,
    ) -> SchedulerDecision;

    /// Notify the scheduler of a path-level event.
    fn on_path_event(&mut self, _event: SchedulerPathEvent) {}
    /// Notify the scheduler of a connection-level event.
    fn on_conn_event(&mut self, _event: SchedulerConnEvent) {}
}

/// Factory for creating per-connection scheduler instances.
pub trait SchedulerFactory: Send + Sync {
    /// Create a new scheduler instance for a connection.
    fn create(&self) -> Box<dyn Scheduler>;
}

/// Built-in scheduler algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathSchedulerAlgorithm {
    /// Send on the path with the lowest smoothed RTT.
    MinRtt,
    /// Distribute packets evenly across all available paths.
    RoundRobin,
}
