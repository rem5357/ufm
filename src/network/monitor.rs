//! Network Interface Monitor
//!
//! Watches for network interface changes (up/down) and triggers
//! immediate peer discovery when changes occur.

use std::sync::Arc;
use tokio::sync::RwLock;

use super::discovery::DiscoveryManager;
use super::peer::PeerManager;

/// Monitors network interface changes and triggers discovery
pub struct NetworkMonitor {
    /// Discovery manager for triggering re-discovery
    discovery: Arc<RwLock<DiscoveryManager>>,
    /// Peer manager for managing peer connections
    peer_manager: Arc<PeerManager>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(
        discovery: Arc<RwLock<DiscoveryManager>>,
        peer_manager: Arc<PeerManager>,
    ) -> Self {
        Self {
            discovery,
            peer_manager,
        }
    }

    /// Start monitoring network interfaces
    ///
    /// This runs in a loop watching for interface changes.
    /// When an interface comes up, it triggers immediate discovery.
    /// When an interface goes down, it logs the event.
    pub async fn start(self) -> anyhow::Result<()> {
        use futures::StreamExt;
        use if_watch::IfEvent;
        use if_watch::tokio::IfWatcher;

        tracing::info!("Starting network interface monitor");

        let mut watcher = IfWatcher::new()?;

        // Log initial interfaces
        for addr in watcher.iter() {
            tracing::debug!("Initial interface: {}", addr);
        }

        loop {
            tokio::select! {
                event = watcher.next() => {
                    match event {
                        Some(Ok(IfEvent::Up(addr))) => {
                            tracing::info!("Network interface up: {}", addr);

                            // Trigger immediate discovery
                            let discovery = self.discovery.read().await;
                            let peers = discovery.discover_now().await;
                            tracing::info!(
                                "Triggered discovery after interface up, found {} peers",
                                peers.len()
                            );
                        }
                        Some(Ok(IfEvent::Down(addr))) => {
                            tracing::info!("Network interface down: {}", addr);

                            // Could mark peers as potentially unreachable here
                            // For now, just log it - the next discovery cycle will handle it
                        }
                        Some(Err(e)) => {
                            tracing::warn!("Network monitor error: {}", e);
                        }
                        None => {
                            tracing::debug!("Network monitor stream ended");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
