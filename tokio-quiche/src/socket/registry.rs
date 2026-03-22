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
/// lookup for send-side routing: only explicitly registered addresses are
/// returned. The main listening socket is NOT registered here — it uses
/// the IoWorker's primary socket directly.
pub(crate) struct SocketRegistry<Tx: ?Sized> {
    sockets: HashMap<SocketAddr, Arc<Tx>>,
}

impl<Tx: ?Sized> SocketRegistry<Tx> {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    /// Register a socket for the given local address.
    pub fn insert(&mut self, local_addr: SocketAddr, socket: Arc<Tx>) {
        self.sockets.insert(local_addr, socket);
    }

    /// Look up a registered socket by local address.
    pub fn lookup(&self, local_addr: &SocketAddr) -> Option<&Arc<Tx>> {
        self.sockets.get(local_addr)
    }

    /// Remove a socket registration. Returns the socket if it existed.
    pub fn remove(&mut self, local_addr: &SocketAddr) -> Option<Arc<Tx>> {
        self.sockets.remove(local_addr)
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
    fn lookup_returns_registered_socket() {
        let mut registry = SocketRegistry::new();
        let a = addr(6000);
        registry.insert(a, Arc::new(6000u16));
        assert_eq!(**registry.lookup(&a).unwrap(), 6000);
    }

    #[test]
    fn lookup_returns_none_for_unregistered() {
        let mut registry: SocketRegistry<u16> = SocketRegistry::new();
        let a = addr(6000);
        let b = addr(7000);
        registry.insert(a, Arc::new(6000u16));

        assert_eq!(**registry.lookup(&a).unwrap(), 6000);
        assert!(registry.lookup(&b).is_none());
    }

    #[test]
    fn remove_returns_socket() {
        let mut registry = SocketRegistry::new();
        let a = addr(6000);
        registry.insert(a, Arc::new(6000u16));

        let removed = registry.remove(&a);
        assert!(removed.is_some());
        assert_eq!(*removed.unwrap(), 6000);

        // Gone after removal
        assert!(registry.lookup(&a).is_none());
    }

}
