//! Peer Connection Management
//!
//! Manages connections to other UFM nodes in the network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bimap::BiMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::config::NetworkConfig;
use super::identity::NodeIdentity;
use super::protocol::{DiscoveredPeer, FrameHeader, PeerMessage, ToolResult, PROTOCOL_VERSION};

/// Local node ID type (0 = local, 1+ = peers)
pub type NodeId = u32;

/// Reference to a node (by ID, name, or UUID)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NodeRef {
    /// Local node (default when omitted)
    #[serde(skip)]
    Local,
    /// Node by local ID (0, 1, 2, ...)
    Id(NodeId),
    /// Node by name ("goldshire", "falcon")
    Name(String),
    /// Node by UUID
    Uuid(Uuid),
}

impl Default for NodeRef {
    fn default() -> Self {
        NodeRef::Local
    }
}

impl NodeRef {
    /// Check if this refers to the local node
    pub fn is_local(&self) -> bool {
        matches!(self, NodeRef::Local | NodeRef::Id(0))
    }
}

/// Status of a peer connection
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Found via discovery, not yet connected
    Discovered,
    /// Connection in progress
    Connecting,
    /// Active connection
    Connected,
    /// Was connected, lost connection
    Disconnected,
    /// Failed to connect
    Unreachable,
}

/// Information about a peer
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Locally assigned ID (1, 2, 3...)
    pub local_id: NodeId,
    /// Peer's identity
    pub identity: NodeIdentity,
    /// All known addresses for this peer
    pub addresses: Vec<SocketAddr>,
    /// Current status
    pub status: PeerStatus,
    /// Measured latency in milliseconds
    pub latency_ms: Option<u32>,
    /// When we last heard from this peer
    pub last_seen: Instant,
    /// When connection was established
    pub connected_at: Option<Instant>,
}

/// Serializable node info for API responses
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub name: String,
    pub uuid: Uuid,
    pub addresses: Vec<String>,
    pub status: PeerStatus,
    pub latency_ms: Option<u32>,
    pub os: String,
    pub version: String,
}

/// Active connection to a peer
pub struct PeerConnection {
    pub info: PeerInfo,
    pub reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    pub writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
}

impl PeerConnection {
    /// Send a message to this peer
    pub async fn send(&mut self, msg: &PeerMessage) -> anyhow::Result<()> {
        let data = msg.encode()?;
        self.writer.write_all(&data).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Receive a message from this peer
    pub async fn recv(&mut self) -> anyhow::Result<PeerMessage> {
        // Read header
        let mut header_buf = [0u8; FrameHeader::SIZE];
        self.reader.read_exact(&mut header_buf).await?;
        let header = FrameHeader::parse(&header_buf)?;

        // Read payload
        let mut payload = vec![0u8; header.length as usize];
        self.reader.read_exact(&mut payload).await?;

        PeerMessage::decode(&payload)
    }
}

/// Manages all peer connections
pub struct PeerManager {
    /// Our identity
    identity: NodeIdentity,

    /// All known peers (by UUID)
    peers: RwLock<HashMap<Uuid, PeerInfo>>,

    /// Active connections (by UUID)
    connections: RwLock<HashMap<Uuid, Arc<tokio::sync::Mutex<PeerConnection>>>>,

    /// Local ID assignments (UUID <-> NodeId)
    id_assignments: RwLock<BiMap<Uuid, NodeId>>,

    /// Next local ID to assign
    next_id: AtomicU32,

    /// Next request ID
    next_request_id: AtomicU64,

    /// Network configuration
    config: NetworkConfig,
}

impl PeerManager {
    /// Create a new peer manager
    pub async fn new(identity: NodeIdentity, config: NetworkConfig) -> anyhow::Result<Self> {
        Ok(Self {
            identity,
            peers: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            id_assignments: RwLock::new(BiMap::new()),
            next_id: AtomicU32::new(1), // 0 is reserved for local
            next_request_id: AtomicU64::new(1),
            config,
        })
    }

    /// Get our identity
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Generate next request ID
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Start listening for incoming connections
    pub async fn start_listener(&self, addr: &str) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Listening for peer connections on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::debug!("Incoming connection from {}", peer_addr);
                    // Handle in background
                    let identity = self.identity.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_incoming(stream, peer_addr, identity).await {
                            tracing::warn!("Failed to handle connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Accept failed: {}", e);
                }
            }
        }
    }

    /// Handle an incoming connection
    async fn handle_incoming(
        stream: TcpStream,
        peer_addr: SocketAddr,
        our_identity: NodeIdentity,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Read hello
        let mut header_buf = [0u8; FrameHeader::SIZE];
        reader.read_exact(&mut header_buf).await?;
        let header = FrameHeader::parse(&header_buf)?;

        let mut payload = vec![0u8; header.length as usize];
        reader.read_exact(&mut payload).await?;
        let msg = PeerMessage::decode(&payload)?;

        match msg {
            PeerMessage::Hello {
                identity,
                protocol_version,
            } => {
                if protocol_version != PROTOCOL_VERSION {
                    let reject = PeerMessage::Reject {
                        reason: format!(
                            "Protocol version mismatch: expected {}, got {}",
                            PROTOCOL_VERSION, protocol_version
                        ),
                    };
                    let data = reject.encode()?;
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    anyhow::bail!("Protocol version mismatch");
                }

                tracing::info!(
                    "Peer connected: {} ({}) from {}",
                    identity.name,
                    identity.uuid,
                    peer_addr
                );

                // Send accept
                let accept = PeerMessage::Accept {
                    identity: our_identity,
                };
                let data = accept.encode()?;
                writer.write_all(&data).await?;
                writer.flush().await?;

                // TODO: Add to peer manager and start handling requests
                Ok(())
            }
            _ => {
                anyhow::bail!("Expected Hello message, got {:?}", msg);
            }
        }
    }

    /// List all known nodes
    pub async fn list_nodes(&self) -> Vec<NodeInfo> {
        let mut nodes = vec![NodeInfo {
            id: 0,
            name: self.identity.name.clone(),
            uuid: self.identity.uuid,
            addresses: vec!["local".to_string()],
            status: PeerStatus::Connected,
            latency_ms: Some(0),
            os: self.identity.os.clone(),
            version: self.identity.version.clone(),
        }];

        let peers = self.peers.read().await;
        for peer in peers.values() {
            nodes.push(NodeInfo {
                id: peer.local_id,
                name: peer.identity.name.clone(),
                uuid: peer.identity.uuid,
                addresses: peer.addresses.iter().map(|a| a.to_string()).collect(),
                status: peer.status.clone(),
                latency_ms: peer.latency_ms,
                os: peer.identity.os.clone(),
                version: peer.identity.version.clone(),
            });
        }

        nodes.sort_by_key(|n| n.id);
        nodes
    }

    /// Resolve a node reference to a UUID
    pub async fn resolve_node(&self, node_ref: &NodeRef) -> anyhow::Result<Uuid> {
        match node_ref {
            NodeRef::Local | NodeRef::Id(0) => Ok(self.identity.uuid),
            NodeRef::Id(id) => {
                let assignments = self.id_assignments.read().await;
                assignments
                    .get_by_right(id)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("Node not found: id {}", id))
            }
            NodeRef::Name(name) => {
                let peers = self.peers.read().await;
                peers
                    .values()
                    .find(|p| p.identity.name.eq_ignore_ascii_case(name))
                    .map(|p| p.identity.uuid)
                    .ok_or_else(|| anyhow::anyhow!("Node not found: {}", name))
            }
            NodeRef::Uuid(uuid) => Ok(*uuid),
        }
    }

    /// Check if a node reference points to local
    pub async fn is_local(&self, node_ref: &NodeRef) -> bool {
        match node_ref {
            NodeRef::Local | NodeRef::Id(0) => true,
            NodeRef::Uuid(uuid) => *uuid == self.identity.uuid,
            _ => false,
        }
    }

    /// Add a discovered peer
    pub async fn add_discovered_peer(&self, discovered: DiscoveredPeer) {
        let uuid = match discovered.uuid {
            Some(u) => u,
            None => return, // Can't add without UUID
        };

        // Don't add ourselves
        if uuid == self.identity.uuid {
            return;
        }

        let mut peers = self.peers.write().await;

        if let Some(existing) = peers.get_mut(&uuid) {
            // Update existing peer
            for addr in discovered.addresses {
                if !existing.addresses.contains(&addr) {
                    existing.addresses.push(addr);
                }
            }
            existing.last_seen = Instant::now();
        } else {
            // New peer - assign local ID
            let local_id = self.next_id.fetch_add(1, Ordering::SeqCst);

            let mut id_assignments = self.id_assignments.write().await;
            id_assignments.insert(uuid, local_id);

            let identity = NodeIdentity {
                uuid,
                name: discovered.name,
                os: discovered.os.unwrap_or_else(|| "unknown".to_string()),
                arch: "unknown".to_string(),
                version: discovered.version.unwrap_or_else(|| "unknown".to_string()),
                build: "0".to_string(),
                capabilities: vec![],
            };

            peers.insert(
                uuid,
                PeerInfo {
                    local_id,
                    identity,
                    addresses: discovered.addresses,
                    status: PeerStatus::Discovered,
                    latency_ms: None,
                    last_seen: Instant::now(),
                    connected_at: None,
                },
            );

            tracing::info!("Discovered new peer: {} (id={})", uuid, local_id);
        }
    }

    /// Connect to a peer by UUID
    pub async fn connect(&self, peer_uuid: Uuid) -> anyhow::Result<()> {
        let peer_info = {
            let peers = self.peers.read().await;
            peers
                .get(&peer_uuid)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_uuid))?
        };

        // Update status to connecting
        {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(&peer_uuid) {
                peer.status = PeerStatus::Connecting;
            }
        }

        // Try each known address
        for addr in &peer_info.addresses {
            match self.try_connect(*addr, &peer_info).await {
                Ok(conn) => {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(&peer_uuid) {
                        peer.status = PeerStatus::Connected;
                        peer.connected_at = Some(Instant::now());
                    }

                    let mut connections = self.connections.write().await;
                    connections.insert(peer_uuid, Arc::new(tokio::sync::Mutex::new(conn)));

                    tracing::info!("Connected to peer {} at {}", peer_info.identity.name, addr);
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to connect to {} at {}: {}",
                        peer_info.identity.name,
                        addr,
                        e
                    );
                    continue;
                }
            }
        }

        // All addresses failed
        {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(&peer_uuid) {
                peer.status = PeerStatus::Unreachable;
            }
        }

        anyhow::bail!(
            "Failed to connect to peer {} at any address",
            peer_info.identity.name
        )
    }

    /// Try to connect to a specific address
    async fn try_connect(&self, addr: SocketAddr, _peer: &PeerInfo) -> anyhow::Result<PeerConnection> {
        let timeout = Duration::from_secs(5);
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        stream.set_nodelay(true)?;

        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send hello
        let hello = PeerMessage::Hello {
            identity: self.identity.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        let data = hello.encode()?;
        writer.write_all(&data).await?;
        writer.flush().await?;

        // Read response
        let mut header_buf = [0u8; FrameHeader::SIZE];
        reader.read_exact(&mut header_buf).await?;
        let header = FrameHeader::parse(&header_buf)?;

        let mut payload = vec![0u8; header.length as usize];
        reader.read_exact(&mut payload).await?;
        let response = PeerMessage::decode(&payload)?;

        match response {
            PeerMessage::Accept { identity } => {
                let info = PeerInfo {
                    local_id: 0, // Will be set by caller
                    identity,
                    addresses: vec![addr],
                    status: PeerStatus::Connected,
                    latency_ms: None,
                    last_seen: Instant::now(),
                    connected_at: Some(Instant::now()),
                };

                Ok(PeerConnection {
                    info,
                    reader,
                    writer,
                })
            }
            PeerMessage::Reject { reason } => {
                anyhow::bail!("Connection rejected: {}", reason)
            }
            _ => {
                anyhow::bail!("Unexpected response to Hello")
            }
        }
    }

    /// Check if connected to a peer
    pub async fn is_connected(&self, peer_uuid: Uuid) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(&peer_uuid)
    }

    /// Get count of connected peers
    pub async fn connected_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_uuid: Uuid) {
        let mut connections = self.connections.write().await;
        if connections.remove(&peer_uuid).is_some() {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(&peer_uuid) {
                peer.status = PeerStatus::Disconnected;
                peer.connected_at = None;
            }
            tracing::info!("Disconnected from peer {}", peer_uuid);
        }
    }

    /// Disconnect from all peers
    pub async fn disconnect_all(&self) {
        let mut connections = self.connections.write().await;
        let uuids: Vec<_> = connections.keys().copied().collect();
        connections.clear();

        let mut peers = self.peers.write().await;
        for uuid in uuids {
            if let Some(peer) = peers.get_mut(&uuid) {
                peer.status = PeerStatus::Disconnected;
                peer.connected_at = None;
            }
        }

        tracing::info!("Disconnected from all peers");
    }

    /// Send a tool request to a peer and wait for response
    pub async fn send_tool_request(
        &self,
        peer_uuid: Uuid,
        tool: String,
        params: serde_json::Value,
    ) -> anyhow::Result<ToolResult> {
        // Ensure connected
        if !self.is_connected(peer_uuid).await {
            self.connect(peer_uuid).await?;
        }

        let request_id = self.next_request_id();
        let request = PeerMessage::ToolRequest {
            id: request_id,
            tool,
            params,
        };

        let connections = self.connections.read().await;
        let conn = connections
            .get(&peer_uuid)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer"))?;

        let mut conn = conn.lock().await;
        conn.send(&request).await?;

        // Wait for response
        let response = conn.recv().await?;
        match response {
            PeerMessage::ToolResponse { id, result } if id == request_id => Ok(result),
            PeerMessage::Error { code, message } => {
                anyhow::bail!("Peer error ({}): {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    /// Ping a peer and measure latency
    pub async fn ping(&self, peer_uuid: Uuid) -> anyhow::Result<u32> {
        if !self.is_connected(peer_uuid).await {
            self.connect(peer_uuid).await?;
        }

        let start = Instant::now();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ping = PeerMessage::Ping { timestamp };

        let connections = self.connections.read().await;
        let conn = connections
            .get(&peer_uuid)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer"))?;

        let mut conn = conn.lock().await;
        conn.send(&ping).await?;

        let response = conn.recv().await?;
        let latency = start.elapsed().as_millis() as u32;

        match response {
            PeerMessage::Pong { .. } => {
                // Update stored latency
                drop(conn);
                drop(connections);

                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.get_mut(&peer_uuid) {
                    peer.latency_ms = Some(latency);
                    peer.last_seen = Instant::now();
                }

                Ok(latency)
            }
            _ => anyhow::bail!("Expected Pong response"),
        }
    }
}
