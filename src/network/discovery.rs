//! Peer Discovery
//!
//! Automatic discovery of UFM peers via mDNS and bootstrap nodes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use uuid::Uuid;

use super::config::DiscoveryConfig;
use super::identity::NodeIdentity;
use super::peer::PeerManager;
use super::protocol::{DiscoveredPeer, DiscoverySource, PeerMessage};

/// Manages peer discovery via multiple methods
pub struct DiscoveryManager {
    identity: NodeIdentity,
    peer_manager: Arc<PeerManager>,
    config: DiscoveryConfig,
    mdns_daemon: Option<ServiceDaemon>,
    mdns_receiver: Option<mdns_sd::Receiver<ServiceEvent>>,
    running: bool,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new(
        identity: NodeIdentity,
        peer_manager: Arc<PeerManager>,
        config: DiscoveryConfig,
    ) -> Self {
        Self {
            identity,
            peer_manager,
            config,
            mdns_daemon: None,
            mdns_receiver: None,
            running: false,
        }
    }

    /// Start discovery services
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Ok(());
        }

        self.running = true;

        // Start mDNS if enabled
        if self.config.mdns_enabled {
            self.start_mdns().await?;
        }

        // Start periodic discovery
        self.start_discovery_loop().await;

        Ok(())
    }

    /// Stop discovery services
    pub async fn stop(&mut self) {
        self.running = false;

        if let Some(daemon) = self.mdns_daemon.take() {
            let _ = daemon.shutdown();
        }
    }

    /// Start mDNS service
    async fn start_mdns(&mut self) -> anyhow::Result<()> {
        let daemon = ServiceDaemon::new()?;

        // Announce ourselves
        let service_type = &self.config.mdns_service_type;
        let instance_name = &self.identity.name;

        let mut properties = HashMap::new();
        properties.insert("uuid".to_string(), self.identity.uuid.to_string());
        properties.insert("version".to_string(), self.identity.version.clone());
        properties.insert("os".to_string(), self.identity.os.clone());

        // Get our listen port from peer manager config
        let port = 9847u16; // TODO: Get from config

        let service = ServiceInfo::new(
            service_type,
            instance_name,
            &format!("{}.{}", instance_name, service_type),
            "",
            port,
            properties,
        )?;

        daemon.register(service)?;
        tracing::info!("mDNS service registered: {}", instance_name);

        // Create browse receiver once - don't call browse() repeatedly
        let receiver = daemon.browse(service_type)?;
        tracing::info!("mDNS browse started for: {}", service_type);

        self.mdns_receiver = Some(receiver);
        self.mdns_daemon = Some(daemon);
        Ok(())
    }

    /// Start the periodic discovery loop
    async fn start_discovery_loop(&self) {
        let peer_manager = self.peer_manager.clone();
        let config = self.config.clone();
        let identity = self.identity.clone();
        let mdns_receiver = self.mdns_receiver.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.discovery_interval());

            loop {
                interval.tick().await;

                // mDNS discovery - use the persistent receiver
                if let Some(ref receiver) = mdns_receiver {
                    if let Ok(peers) = collect_mdns_peers(receiver, &identity).await {
                        for peer in peers {
                            peer_manager.add_discovered_peer(peer).await;
                        }
                    }
                }

                // Bootstrap discovery
                if !config.bootstrap_nodes.is_empty() {
                    if let Ok(peers) = discover_bootstrap(&config.bootstrap_nodes, &identity).await {
                        for peer in peers {
                            peer_manager.add_discovered_peer(peer).await;
                        }
                    }
                }
            }
        });
    }

    /// Trigger immediate discovery
    pub async fn discover_now(&self) -> Vec<DiscoveredPeer> {
        let mut all_peers = Vec::new();

        // mDNS - use the persistent receiver
        if let Some(ref receiver) = self.mdns_receiver {
            if let Ok(peers) = collect_mdns_peers(receiver, &self.identity).await {
                all_peers.extend(peers);
            }
        }

        // Bootstrap
        if !self.config.bootstrap_nodes.is_empty() {
            if let Ok(peers) = discover_bootstrap(&self.config.bootstrap_nodes, &self.identity).await {
                all_peers.extend(peers);
            }
        }

        // Add to peer manager
        for peer in &all_peers {
            self.peer_manager.add_discovered_peer(peer.clone()).await;
        }

        all_peers
    }
}

/// Collect peers from an existing mDNS receiver (non-blocking drain)
async fn collect_mdns_peers(
    receiver: &mdns_sd::Receiver<ServiceEvent>,
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    let mut peers = Vec::new();

    // Drain any pending events from the receiver (non-blocking)
    // We use try_recv to avoid blocking, collecting what's available
    let timeout = Duration::from_secs(3);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(100), async {
            // Use a blocking task for the sync receiver
            tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(Duration::from_millis(50))
            })
            .await
        })
        .await
        {
            Ok(Ok(Ok(event))) => {
                if let ServiceEvent::ServiceResolved(info) = event {
                    // Skip ourselves
                    let uuid_str = info
                        .get_property_val_str("uuid")
                        .unwrap_or_default();

                    if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                        if uuid == our_identity.uuid {
                            continue;
                        }

                        let addresses: Vec<SocketAddr> = info
                            .get_addresses()
                            .iter()
                            .map(|ip| SocketAddr::new(*ip, info.get_port()))
                            .collect();

                        if !addresses.is_empty() {
                            peers.push(DiscoveredPeer {
                                name: info.get_fullname().split('.').next()
                                    .unwrap_or("unknown").to_string(),
                                uuid: Some(uuid),
                                addresses,
                                version: info
                                    .get_property_val_str("version")
                                    .map(|s| s.to_string()),
                                os: info.get_property_val_str("os").map(|s| s.to_string()),
                                source: DiscoverySource::Mdns,
                            });
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    Ok(peers)
}

/// Discover peers via bootstrap nodes
async fn discover_bootstrap(
    bootstrap_nodes: &[SocketAddr],
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    let mut all_peers = Vec::new();

    for addr in bootstrap_nodes {
        match query_bootstrap(*addr, our_identity).await {
            Ok(peers) => {
                tracing::debug!("Got {} peers from bootstrap {}", peers.len(), addr);
                all_peers.extend(peers);
            }
            Err(e) => {
                tracing::debug!("Bootstrap {} unreachable: {}", addr, e);
            }
        }
    }

    // Deduplicate by UUID
    all_peers.sort_by_key(|p| p.uuid);
    all_peers.dedup_by_key(|p| p.uuid);

    Ok(all_peers)
}

/// Query a single bootstrap node
async fn query_bootstrap(
    addr: SocketAddr,
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
    use tokio::net::TcpStream;

    let timeout = Duration::from_secs(5);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    stream.set_nodelay(true)?;

    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // Send discovery request
    let request = PeerMessage::DiscoveryRequest {
        requester: our_identity.clone(),
    };
    let data = request.encode()?;
    writer.write_all(&data).await?;
    writer.flush().await?;

    // Read response
    use super::protocol::FrameHeader;

    let mut header_buf = [0u8; FrameHeader::SIZE];
    tokio::time::timeout(timeout, reader.read_exact(&mut header_buf)).await??;
    let header = FrameHeader::parse(&header_buf)?;

    let mut payload = vec![0u8; header.length as usize];
    tokio::time::timeout(timeout, reader.read_exact(&mut payload)).await??;
    let response = PeerMessage::decode(&payload)?;

    match response {
        PeerMessage::DiscoveryResponse { peers } => Ok(peers),
        _ => anyhow::bail!("Unexpected response from bootstrap"),
    }
}
