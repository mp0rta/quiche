// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Registry of UDP sockets for multipath send-side routing.
//!
//! Maps local addresses to their send-capable socket handles, enabling
//! IoWorker to route outbound packets to the correct socket based on
//! the path's local address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Manages multiple sockets for multipath connections.
///
/// Each socket is registered by its local address. The registry provides
/// lookup for send-side routing and a default fallback socket.
pub(crate) struct SocketRegistry<Tx: ?Sized> {
    default_socket: Arc<Tx>,
    sockets: HashMap<SocketAddr, Arc<Tx>>,
}

impl<Tx: ?Sized> SocketRegistry<Tx> {
    /// Create a new registry with the initial (default) socket.
    pub fn new(default_socket: Arc<Tx>) -> Self {
        Self {
            default_socket,
            sockets: HashMap::new(),
        }
    }

    /// Register a socket for the given local address.
    pub fn insert(&mut self, local_addr: SocketAddr, socket: Arc<Tx>) {
        self.sockets.insert(local_addr, socket);
    }

    /// Look up the socket for a local address, falling back to the default.
    pub fn get(&self, local_addr: &SocketAddr) -> &Arc<Tx> {
        self.sockets.get(local_addr).unwrap_or(&self.default_socket)
    }

    /// Remove a socket registration. Returns the socket if it existed.
    pub fn remove(&mut self, local_addr: &SocketAddr) -> Option<Arc<Tx>> {
        self.sockets.remove(local_addr)
    }

    /// Returns all registered local addresses (excluding the default).
    pub fn local_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.sockets.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn get_returns_default_when_no_match() {
        let default = Arc::new(5000u16);
        let registry = SocketRegistry::new(default.clone());
        let result = registry.get(&addr(9999));
        assert_eq!(**result, 5000);
    }

    #[test]
    fn get_returns_registered_socket() {
        let default = Arc::new(5000u16);
        let mut registry = SocketRegistry::new(default);
        let a = addr(6000);
        registry.insert(a, Arc::new(6000u16));
        assert_eq!(**registry.get(&a), 6000);
    }

    #[test]
    fn remove_returns_socket_and_falls_back() {
        let default = Arc::new(5000u16);
        let mut registry = SocketRegistry::new(default);
        let a = addr(6000);
        registry.insert(a, Arc::new(6000u16));

        let removed = registry.remove(&a);
        assert!(removed.is_some());
        assert_eq!(*removed.unwrap(), 6000);

        // Falls back to default after removal
        assert_eq!(**registry.get(&a), 5000);
    }

    #[test]
    fn local_addrs_returns_registered_addresses() {
        let default = Arc::new(0u16);
        let mut registry = SocketRegistry::new(default);
        let a1 = addr(6000);
        let a2 = addr(7000);
        registry.insert(a1, Arc::new(6000u16));
        registry.insert(a2, Arc::new(7000u16));

        let addrs: Vec<_> = registry.local_addrs().collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&&a1));
        assert!(addrs.contains(&&a2));
    }
}
