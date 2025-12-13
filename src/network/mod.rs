//! UFM Peer-to-Peer Network Module
//!
//! This module enables UFM instances to discover each other and communicate
//! directly, forming a peer-to-peer mesh network.

pub mod identity;
pub mod protocol;
pub mod peer;
pub mod discovery;
pub mod router;
pub mod config;
pub mod transfer;

pub use identity::{NodeIdentity, Capability};
pub use protocol::{PeerMessage, PROTOCOL_VERSION};
pub use peer::{PeerManager, PeerInfo, PeerStatus, NodeRef};
pub use discovery::DiscoveryManager;
pub use router::RequestRouter;
pub use config::{NetworkConfig, DiscoveryConfig, TransferConfig, Compression};
pub use transfer::{TransferManager, TransferInfo, TransferState, TransferDirection};

use std::sync::Arc;
use tokio::sync::RwLock;

/// The main network service that coordinates all P2P functionality
pub struct NetworkService {
    /// Our identity
    pub identity: NodeIdentity,

    /// Peer connection manager
    pub peers: Arc<PeerManager>,

    /// Discovery service
    pub discovery: Arc<RwLock<DiscoveryManager>>,

    /// Request router
    pub router: Arc<RequestRouter>,

    /// Configuration
    pub config: NetworkConfig,

    /// Whether networking is enabled
    pub enabled: bool,
}

impl NetworkService {
    /// Create a new network service
    pub async fn new(config: NetworkConfig) -> anyhow::Result<Self> {
        let identity = NodeIdentity::load_or_create(&config.identity_path)?;

        tracing::info!(
            "Network identity: {} ({})",
            identity.name,
            identity.uuid
        );

        let peers = Arc::new(PeerManager::new(identity.clone(), config.clone()).await?);
        let discovery = Arc::new(RwLock::new(
            DiscoveryManager::new(identity.clone(), peers.clone(), config.discovery.clone())
        ));
        let router = Arc::new(RequestRouter::new(identity.clone(), peers.clone()));

        Ok(Self {
            identity,
            peers,
            discovery,
            router,
            config: config.clone(),
            enabled: config.enabled,
        })
    }

    /// Start the network service (listening and discovery)
    pub async fn start(&self) -> anyhow::Result<()> {
        if !self.enabled {
            tracing::info!("P2P networking disabled");
            return Ok(());
        }

        tracing::info!(
            "Starting P2P network on port {}",
            self.config.listen_port
        );

        // Start listening for incoming connections
        let peers = self.peers.clone();
        let listen_addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);

        tokio::spawn(async move {
            if let Err(e) = peers.start_listener(&listen_addr).await {
                tracing::error!("Listener failed: {}", e);
            }
        });

        // Start discovery
        {
            let mut discovery = self.discovery.write().await;
            discovery.start().await?;
        }

        Ok(())
    }

    /// Stop the network service
    pub async fn stop(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }

        tracing::info!("Stopping P2P network");

        // Stop discovery
        {
            let mut discovery = self.discovery.write().await;
            discovery.stop().await;
        }

        // Disconnect all peers
        self.peers.disconnect_all().await;

        Ok(())
    }

    /// Check if we're connected to any peers
    pub async fn has_peers(&self) -> bool {
        self.peers.connected_count().await > 0
    }
}
