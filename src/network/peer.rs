//! Peer Connection Management
//!
//! Manages connections to other UFM nodes in the network.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hasher;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bimap::BiMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::config::{Compression, NetworkConfig};
use super::identity::NodeIdentity;
use super::protocol::{DiscoveredPeer, FrameHeader, PeerMessage, ToolResult, PROTOCOL_VERSION};
use super::transfer::{TransferManager, TransferInfo, DEFAULT_CHUNK_SIZE};

/// Trait for executing tools locally (used for handling remote tool requests)
pub trait ToolExecutor: Send + Sync {
    /// Execute a tool with the given name and parameters
    fn execute<'a>(
        &'a self,
        tool: &'a str,
        params: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = ToolResult> + Send + 'a>>;
}

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

    /// Tool executor for handling incoming tool requests
    tool_executor: RwLock<Option<Arc<dyn ToolExecutor>>>,

    /// Transfer manager for streaming file transfers
    pub transfers: Arc<TransferManager>,
}

impl PeerManager {
    /// Create a new peer manager
    pub async fn new(identity: NodeIdentity, config: NetworkConfig) -> anyhow::Result<Self> {
        let compression = config.transfer.compression;
        Ok(Self {
            identity,
            peers: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            id_assignments: RwLock::new(BiMap::new()),
            next_id: AtomicU32::new(1), // 0 is reserved for local
            next_request_id: AtomicU64::new(1),
            config,
            tool_executor: RwLock::new(None),
            transfers: Arc::new(TransferManager::new(DEFAULT_CHUNK_SIZE, compression)),
        })
    }

    /// Set the tool executor for handling incoming tool requests
    pub async fn set_tool_executor(&self, executor: Arc<dyn ToolExecutor>) {
        let mut guard = self.tool_executor.write().await;
        *guard = Some(executor);
        tracing::debug!("Tool executor set for peer manager");
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
        let listener = if self.config.security.tailscale_only {
            // Bind only to Tailscale interface
            match super::tailscale::bind_tailscale_only(self.config.listen_port).await {
                Ok(listener) => {
                    tracing::info!("Listening on Tailscale interface only (port {})", self.config.listen_port);
                    listener
                }
                Err(e) => {
                    anyhow::bail!("Failed to bind to Tailscale interface: {}. Is Tailscale running?", e);
                }
            }
        } else {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!("Listening for peer connections on {}", addr);
            listener
        };


        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::debug!("Incoming connection from {}", peer_addr);

                    // Verify connection is from Tailscale if required
                    if self.config.security.tailscale_only {
                        if let Err(e) = super::tailscale::verify_tailscale_source(peer_addr) {
                            tracing::warn!("Rejected connection from {}: {}", peer_addr, e);
                            continue;
                        }
                        tracing::debug!("Verified Tailscale connection from {}", peer_addr);
                    }

                    // Handle in background
                    let identity = self.identity.clone();
                    // Get tool executor if available
                    let executor = self.tool_executor.read().await.clone();
                    // Get transfer manager
                    let transfers = Some(self.transfers.clone());
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_incoming(stream, peer_addr, identity, executor, transfers).await {
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
        executor: Option<Arc<dyn ToolExecutor>>,
        transfers: Option<Arc<TransferManager>>,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr().ok();
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Read initial message
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
                    identity: our_identity.clone(),
                };
                let data = accept.encode()?;
                writer.write_all(&data).await?;
                writer.flush().await?;

                // Now handle subsequent requests in a loop
                Self::handle_peer_session(reader, writer, peer_addr, identity, executor, transfers).await
            }
            PeerMessage::DiscoveryRequest { requester } => {
                // Bootstrap discovery request - respond with our info
                tracing::info!(
                    "Discovery request from: {} ({}) at {}",
                    requester.name,
                    requester.uuid,
                    peer_addr
                );

                // Respond with ourselves as a discovered peer
                // Use our local address (the one the peer connected to)
                let addresses = if let Some(addr) = local_addr {
                    vec![addr]
                } else {
                    vec![]
                };
                let response = PeerMessage::DiscoveryResponse {
                    peers: vec![super::protocol::DiscoveredPeer {
                        name: our_identity.name.clone(),
                        uuid: Some(our_identity.uuid),
                        addresses,
                        version: Some(our_identity.version.clone()),
                        os: Some(our_identity.os.clone()),
                        source: super::protocol::DiscoverySource::Bootstrap,
                    }],
                };
                let data = response.encode()?;
                writer.write_all(&data).await?;
                writer.flush().await?;
                Ok(())
            }
            _ => {
                anyhow::bail!("Expected Hello or DiscoveryRequest message, got {:?}", msg);
            }
        }
    }

    /// Handle an established peer session - process tool requests and stream transfers
    async fn handle_peer_session(
        mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
        mut writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
        peer_addr: SocketAddr,
        peer_identity: NodeIdentity,
        executor: Option<Arc<dyn ToolExecutor>>,
        transfers: Option<Arc<TransferManager>>,
    ) -> anyhow::Result<()> {
        tracing::debug!("Starting session handler for {} ({})", peer_identity.name, peer_addr);
        let peer_uuid = peer_identity.uuid;

        loop {
            // Read next message
            let mut header_buf = [0u8; FrameHeader::SIZE];
            match reader.read_exact(&mut header_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::debug!("Peer {} disconnected", peer_identity.name);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Error reading from {}: {}", peer_identity.name, e);
                    return Err(e.into());
                }
            }

            let header = FrameHeader::parse(&header_buf)?;
            let mut payload = vec![0u8; header.length as usize];
            reader.read_exact(&mut payload).await?;
            let msg = PeerMessage::decode(&payload)?;

            match msg {
                PeerMessage::Ping { timestamp } => {
                    tracing::debug!("Ping from {} (ts={})", peer_identity.name, timestamp);
                    let server_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let pong = PeerMessage::Pong { timestamp, server_time };
                    let data = pong.encode()?;
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                    tracing::debug!("Sent pong to {}", peer_identity.name);
                }
                PeerMessage::ToolRequest { id, tool, params_json } => {
                    tracing::debug!(
                        "Tool request from {}: {} (id={})",
                        peer_identity.name,
                        tool,
                        id
                    );

                    // Deserialize params from JSON string
                    let params: serde_json::Value = match serde_json::from_str(&params_json) {
                        Ok(v) => v,
                        Err(e) => {
                            let response = PeerMessage::ToolResponse {
                                id,
                                result: ToolResult::Error(format!("Invalid params JSON: {}", e)),
                            };
                            let data = response.encode()?;
                            writer.write_all(&data).await?;
                            writer.flush().await?;
                            continue;
                        }
                    };

                    let result = if let Some(ref exec) = executor {
                        exec.execute(&tool, params).await
                    } else {
                        tracing::warn!("No tool executor available, rejecting request");
                        ToolResult::Error("Tool execution not available on this node".to_string())
                    };

                    let response = PeerMessage::ToolResponse { id, result };
                    let data = response.encode()?;
                    writer.write_all(&data).await?;
                    writer.flush().await?;

                    tracing::debug!("Sent response for tool request id={}", id);
                }
                PeerMessage::Error { code, message } => {
                    tracing::warn!(
                        "Received error from {}: {} (code={})",
                        peer_identity.name,
                        message,
                        code
                    );
                }
                // Stream transfer messages
                PeerMessage::StreamStart { transfer_id, path, size, is_directory: _, compression } => {
                    tracing::info!(
                        "Stream start from {}: transfer_id={}, path={}, size={}",
                        peer_identity.name, transfer_id, path, size
                    );
                    if let Some(ref tm) = transfers {
                        // This node is receiving a file - start incoming transfer
                        // The path is the destination path on this node
                        let dest_path = std::path::PathBuf::from(&path);
                        if let Err(e) = tm.start_incoming(
                            transfer_id,
                            peer_uuid,
                            path.clone(),
                            &dest_path,
                            size,
                            compression,
                        ).await {
                            tracing::error!("Failed to start incoming transfer: {}", e);
                            let abort = PeerMessage::StreamAbort {
                                transfer_id,
                                reason: format!("Failed to start transfer: {}", e),
                            };
                            let data = abort.encode()?;
                            writer.write_all(&data).await?;
                            writer.flush().await?;
                        }
                    }
                }
                PeerMessage::StreamData { transfer_id, sequence, data } => {
                    if let Some(ref tm) = transfers {
                        match tm.receive_chunk(transfer_id, sequence, data).await {
                            Ok(received) => {
                                // Send ack periodically (every 10 chunks or so)
                                if sequence % 10 == 0 {
                                    let ack = PeerMessage::StreamAck {
                                        transfer_id,
                                        received_bytes: received,
                                    };
                                    let data = ack.encode()?;
                                    writer.write_all(&data).await?;
                                    writer.flush().await?;
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to receive chunk: {}", e);
                                let abort = PeerMessage::StreamAbort {
                                    transfer_id,
                                    reason: format!("Chunk error: {}", e),
                                };
                                let data = abort.encode()?;
                                writer.write_all(&data).await?;
                                writer.flush().await?;
                            }
                        }
                    }
                }
                PeerMessage::StreamEnd { transfer_id, checksum } => {
                    tracing::info!("Stream end for transfer_id={}", transfer_id);
                    if let Some(ref tm) = transfers {
                        match tm.complete_incoming(transfer_id, checksum.as_deref()).await {
                            Ok(info) => {
                                tracing::info!(
                                    "Transfer {} completed: {} bytes",
                                    transfer_id, info.transferred_bytes
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to complete transfer: {}", e);
                            }
                        }
                    }
                }
                PeerMessage::StreamAck { transfer_id, received_bytes } => {
                    tracing::debug!(
                        "Stream ack for transfer_id={}, received={}",
                        transfer_id, received_bytes
                    );
                    // Could update transfer progress here
                }
                PeerMessage::StreamAbort { transfer_id, reason } => {
                    tracing::warn!("Stream abort for transfer_id={}: {}", transfer_id, reason);
                    if let Some(ref tm) = transfers {
                        let _ = tm.abort_incoming(transfer_id, reason).await;
                    }
                }
                // Handle pull request - peer wants us to stream a file to them
                PeerMessage::StreamPullRequest { transfer_id, path, compression } => {
                    tracing::info!(
                        "Stream pull request from {}: transfer_id={}, path={}",
                        peer_identity.name, transfer_id, path
                    );

                    // Stream the file back to the requester
                    match Self::handle_stream_pull_request(
                        &mut writer,
                        transfer_id,
                        &path,
                        compression,
                        false, // not a directory
                    ).await {
                        Ok(bytes) => {
                            tracing::info!(
                                "Completed streaming {} bytes for pull request {}",
                                bytes, transfer_id
                            );
                        }
                        Err(e) => {
                            tracing::error!("Failed to handle pull request: {}", e);
                            let abort = PeerMessage::StreamAbort {
                                transfer_id,
                                reason: format!("Pull failed: {}", e),
                            };
                            if let Ok(data) = abort.encode() {
                                let _ = writer.write_all(&data).await;
                                let _ = writer.flush().await;
                            }
                        }
                    }
                }
                // Handle directory pull request - stream as tar
                PeerMessage::StreamPullDirectoryRequest { transfer_id, path, compression } => {
                    tracing::info!(
                        "Stream pull directory request from {}: transfer_id={}, path={}",
                        peer_identity.name, transfer_id, path
                    );

                    match Self::handle_stream_pull_request(
                        &mut writer,
                        transfer_id,
                        &path,
                        compression,
                        true, // is a directory
                    ).await {
                        Ok(bytes) => {
                            tracing::info!(
                                "Completed streaming {} bytes for directory pull request {}",
                                bytes, transfer_id
                            );
                        }
                        Err(e) => {
                            tracing::error!("Failed to handle directory pull request: {}", e);
                            let abort = PeerMessage::StreamAbort {
                                transfer_id,
                                reason: format!("Directory pull failed: {}", e),
                            };
                            if let Ok(data) = abort.encode() {
                                let _ = writer.write_all(&data).await;
                                let _ = writer.flush().await;
                            }
                        }
                    }
                }
                other => {
                    tracing::debug!(
                        "Received unexpected message from {}: {:?}",
                        peer_identity.name,
                        other
                    );
                }
            }
        }
    }

    /// Handle a pull request by streaming a file back to the requester
    async fn handle_stream_pull_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        transfer_id: u64,
        path: &str,
        compression: Compression,
        is_directory: bool,
    ) -> anyhow::Result<u64> {
        let path = std::path::PathBuf::from(path);

        if is_directory {
            return Self::handle_directory_stream(writer, transfer_id, &path, compression).await;
        }

        // Open file and get metadata
        let metadata = tokio::fs::metadata(&path).await?;
        if !metadata.is_file() {
            anyhow::bail!("Path is not a file: {}", path.display());
        }
        let file_size = metadata.len();

        // Send StreamStart
        let start_msg = PeerMessage::StreamStart {
            transfer_id,
            path: path.to_string_lossy().to_string(),
            size: file_size,
            is_directory: false,
            compression,
        };
        let data = start_msg.encode()?;
        writer.write_all(&data).await?;
        writer.flush().await?;

        // Open file for reading
        let mut file = tokio::fs::File::open(&path).await?;

        // Stream file in chunks
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut buffer = vec![0u8; chunk_size];
        let mut sequence = 0u64;
        let mut total_sent = 0u64;
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let chunk = &buffer[..bytes_read];
            hasher.update(chunk);

            // Compress if needed
            let data_bytes = match compression {
                Compression::None => chunk.to_vec(),
                Compression::Gzip => {
                    let mut encoder = flate2::write::GzEncoder::new(
                        Vec::new(),
                        flate2::Compression::fast(),
                    );
                    std::io::Write::write_all(&mut encoder, chunk)?;
                    encoder.finish()?
                }
                Compression::Zstd => {
                    zstd::encode_all(std::io::Cursor::new(chunk), 1)?
                }
            };

            let data_msg = PeerMessage::StreamData {
                transfer_id,
                sequence,
                data: data_bytes,
            };
            let data = data_msg.encode()?;
            writer.write_all(&data).await?;

            total_sent += bytes_read as u64;
            sequence += 1;

            // Flush periodically (every 10 chunks)
            if sequence % 10 == 0 {
                writer.flush().await?;
            }
        }

        // Send StreamEnd with checksum
        let checksum = format!("{:016x}", hasher.finish());
        let end_msg = PeerMessage::StreamEnd {
            transfer_id,
            checksum: Some(checksum),
        };
        let data = end_msg.encode()?;
        writer.write_all(&data).await?;
        writer.flush().await?;

        Ok(total_sent)
    }

    /// Handle directory streaming as a tar archive
    async fn handle_directory_stream<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        transfer_id: u64,
        dir_path: &std::path::Path,
        compression: Compression,
    ) -> anyhow::Result<u64> {
        use std::io::Write as StdWrite;

        // Verify it's a directory
        let metadata = tokio::fs::metadata(dir_path).await?;
        if !metadata.is_dir() {
            anyhow::bail!("Path is not a directory: {}", dir_path.display());
        }

        tracing::info!("Building tar archive for directory: {}", dir_path.display());

        // Build tar archive in memory (for moderate-sized directories)
        // For very large directories, we'd need true streaming tar
        let tar_data = tokio::task::spawn_blocking({
            let dir_path = dir_path.to_path_buf();
            move || -> anyhow::Result<Vec<u8>> {
                let mut tar_builder = tar::Builder::new(Vec::new());

                // Walk directory and add entries
                for entry in walkdir::WalkDir::new(&dir_path)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let path = entry.path();
                    let relative = path.strip_prefix(&dir_path)?;

                    // Skip the root directory itself
                    if relative.as_os_str().is_empty() {
                        continue;
                    }

                    if entry.file_type().is_file() {
                        tar_builder.append_path_with_name(path, relative)?;
                    } else if entry.file_type().is_dir() {
                        tar_builder.append_dir(relative, path)?;
                    }
                    // Skip symlinks for security
                }

                tar_builder.finish()?;
                Ok(tar_builder.into_inner()?)
            }
        }).await??;

        // Optionally compress the tar data
        let final_data = match compression {
            Compression::None => tar_data,
            Compression::Gzip => {
                let mut encoder = flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::fast(),
                );
                encoder.write_all(&tar_data)?;
                encoder.finish()?
            }
            Compression::Zstd => {
                zstd::encode_all(std::io::Cursor::new(&tar_data), 3)?
            }
        };

        let total_size = final_data.len() as u64;
        tracing::info!(
            "Directory tar size: {} bytes (compressed: {:?})",
            total_size, compression
        );

        // Send StreamStart
        let start_msg = PeerMessage::StreamStart {
            transfer_id,
            path: dir_path.to_string_lossy().to_string(),
            size: total_size,
            is_directory: true,
            compression,
        };
        let data = start_msg.encode()?;
        writer.write_all(&data).await?;
        writer.flush().await?;

        // Stream the tar data in chunks
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut offset = 0usize;
        let mut sequence = 0u64;
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();

        while offset < final_data.len() {
            let end = (offset + chunk_size).min(final_data.len());
            let chunk = &final_data[offset..end];
            hasher.update(chunk);

            let data_msg = PeerMessage::StreamData {
                transfer_id,
                sequence,
                data: chunk.to_vec(),
            };
            let encoded = data_msg.encode()?;
            writer.write_all(&encoded).await?;

            offset = end;
            sequence += 1;

            // Flush periodically
            if sequence % 10 == 0 {
                writer.flush().await?;
            }
        }

        // Send StreamEnd with checksum
        let checksum = format!("{:016x}", hasher.finish());
        let end_msg = PeerMessage::StreamEnd {
            transfer_id,
            checksum: Some(checksum),
        };
        let data = end_msg.encode()?;
        writer.write_all(&data).await?;
        writer.flush().await?;

        Ok(total_size)
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
        // Serialize params to JSON string (bincode can't handle serde_json::Value)
        let params_json = serde_json::to_string(&params)?;
        let request = PeerMessage::ToolRequest {
            id: request_id,
            tool,
            params_json,
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

    /// Stream a file to a remote peer (push transfer)
    /// This sends the file directly over the P2P connection, not through tool requests
    pub async fn stream_file_to_peer(
        &self,
        peer_uuid: Uuid,
        local_path: &std::path::Path,
        remote_path: &str,
        compression: Compression,
    ) -> anyhow::Result<TransferInfo> {
        use tokio::io::AsyncReadExt;

        // Ensure connected
        if !self.is_connected(peer_uuid).await {
            self.connect(peer_uuid).await?;
        }

        // Get file metadata
        let metadata = tokio::fs::metadata(local_path).await?;
        let file_size = metadata.len();

        // Open local file
        let mut file = tokio::fs::File::open(local_path).await?;

        // Generate transfer ID
        let transfer_id = self.transfers.next_transfer_id();

        // Get connection
        let connections = self.connections.read().await;
        let conn = connections
            .get(&peer_uuid)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer"))?;
        let mut conn = conn.lock().await;

        // Send StreamStart
        let start_msg = PeerMessage::StreamStart {
            transfer_id,
            path: remote_path.to_string(),
            size: file_size,
            is_directory: false,
            compression,
        };
        conn.send(&start_msg).await?;

        tracing::info!(
            "Starting stream transfer {} to peer: {} -> {} ({} bytes)",
            transfer_id, local_path.display(), remote_path, file_size
        );

        // Stream file in chunks
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut buffer = vec![0u8; chunk_size];
        let mut sequence = 0u64;
        let mut total_sent = 0u64;
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();
        let start_time = Instant::now();

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let chunk = &buffer[..bytes_read];
            hasher.update(chunk);

            // Compress if needed
            let data = match compression {
                Compression::None => chunk.to_vec(),
                Compression::Gzip => {
                    let mut encoder = flate2::write::GzEncoder::new(
                        Vec::new(),
                        flate2::Compression::fast(),
                    );
                    std::io::Write::write_all(&mut encoder, chunk)?;
                    encoder.finish()?
                }
                Compression::Zstd => {
                    zstd::encode_all(std::io::Cursor::new(chunk), 1)?
                }
            };

            let data_msg = PeerMessage::StreamData {
                transfer_id,
                sequence,
                data,
            };
            conn.send(&data_msg).await?;

            total_sent += bytes_read as u64;
            sequence += 1;

            // Log progress every MB
            if total_sent % (1024 * 1024) < chunk_size as u64 {
                tracing::debug!(
                    "Transfer {} progress: {} / {} bytes ({:.1}%)",
                    transfer_id, total_sent, file_size,
                    (total_sent as f64 / file_size as f64) * 100.0
                );
            }
        }

        // Send StreamEnd with checksum
        let checksum = format!("{:016x}", hasher.finish());
        let end_msg = PeerMessage::StreamEnd {
            transfer_id,
            checksum: Some(checksum),
        };
        conn.send(&end_msg).await?;

        let elapsed = start_time.elapsed();
        let speed = total_sent as f64 / elapsed.as_secs_f64() / 1_000_000.0;

        tracing::info!(
            "Completed stream transfer {}: {} bytes in {:.2}s ({:.2} MB/s)",
            transfer_id, total_sent, elapsed.as_secs_f64(), speed
        );

        Ok(TransferInfo {
            id: transfer_id,
            source_path: local_path.to_string_lossy().to_string(),
            dest_path: remote_path.to_string(),
            peer_uuid,
            direction: super::transfer::TransferDirection::Outgoing,
            total_bytes: Some(file_size),
            transferred_bytes: total_sent,
            state: super::transfer::TransferState::Completed,
            compression,
            started_at: Some(start_time),
            completed_at: Some(Instant::now()),
        })
    }

    /// Pull a file from a remote peer using streaming (pull transfer)
    /// This requests the file from the remote and streams it locally
    pub async fn pull_file_from_peer(
        &self,
        peer_uuid: Uuid,
        remote_path: &str,
        local_path: &std::path::Path,
        compression: Compression,
    ) -> anyhow::Result<TransferInfo> {
        // Ensure connected
        if !self.is_connected(peer_uuid).await {
            self.connect(peer_uuid).await?;
        }

        // Generate transfer ID
        let transfer_id = self.transfers.next_transfer_id();

        // Create parent directories for local file
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Get connection
        let connections = self.connections.read().await;
        let conn = connections
            .get(&peer_uuid)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer"))?;
        let mut conn = conn.lock().await;

        // Send StreamPullRequest
        let pull_request = PeerMessage::StreamPullRequest {
            transfer_id,
            path: remote_path.to_string(),
            compression,
        };
        conn.send(&pull_request).await?;

        tracing::info!(
            "Requesting stream pull {} from peer: {} -> {}",
            transfer_id, remote_path, local_path.display()
        );

        let start_time = Instant::now();

        // Receive StreamStart
        let start_msg = conn.recv().await?;
        let (file_size, actual_compression) = match start_msg {
            PeerMessage::StreamStart { transfer_id: tid, size, compression: comp, .. } => {
                if tid != transfer_id {
                    anyhow::bail!("Unexpected transfer_id in StreamStart");
                }
                (size, comp)
            }
            PeerMessage::StreamAbort { reason, .. } => {
                anyhow::bail!("Pull request rejected: {}", reason);
            }
            PeerMessage::Error { message, .. } => {
                anyhow::bail!("Pull request error: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response to pull request: {:?}", other);
            }
        };

        tracing::debug!("Pull transfer {} started, expecting {} bytes", transfer_id, file_size);

        // Open local file for writing
        let mut file = tokio::fs::File::create(local_path).await?;
        let mut total_received = 0u64;
        let mut expected_sequence = 0u64;
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();

        // Receive chunks until StreamEnd
        loop {
            let msg = conn.recv().await?;
            match msg {
                PeerMessage::StreamData { transfer_id: tid, sequence, data } => {
                    if tid != transfer_id {
                        continue; // Ignore messages for other transfers
                    }
                    if sequence != expected_sequence {
                        anyhow::bail!(
                            "Out of sequence chunk: expected {}, got {}",
                            expected_sequence, sequence
                        );
                    }

                    // Decompress if needed
                    let decompressed = match actual_compression {
                        Compression::None => data,
                        Compression::Gzip => {
                            use std::io::Read;
                            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                            let mut buf = Vec::new();
                            decoder.read_to_end(&mut buf)?;
                            buf
                        }
                        Compression::Zstd => {
                            zstd::decode_all(std::io::Cursor::new(&data))?
                        }
                    };

                    // Update checksum with decompressed data
                    hasher.update(&decompressed);

                    // Write to file
                    file.write_all(&decompressed).await?;
                    total_received += decompressed.len() as u64;
                    expected_sequence += 1;

                    // Log progress every MB
                    if total_received % (1024 * 1024) < DEFAULT_CHUNK_SIZE as u64 {
                        tracing::debug!(
                            "Pull transfer {} progress: {} / {} bytes ({:.1}%)",
                            transfer_id, total_received, file_size,
                            (total_received as f64 / file_size as f64) * 100.0
                        );
                    }
                }
                PeerMessage::StreamEnd { transfer_id: tid, checksum } => {
                    if tid != transfer_id {
                        continue;
                    }

                    // Verify checksum if provided
                    if let Some(expected) = checksum {
                        let actual = format!("{:016x}", hasher.finish());
                        if actual != expected {
                            // Clean up partial file
                            let _ = tokio::fs::remove_file(local_path).await;
                            anyhow::bail!(
                                "Checksum mismatch: expected {}, got {}",
                                expected, actual
                            );
                        }
                    }

                    // Flush and close file
                    file.flush().await?;
                    break;
                }
                PeerMessage::StreamAbort { transfer_id: tid, reason } => {
                    if tid == transfer_id {
                        // Clean up partial file
                        let _ = tokio::fs::remove_file(local_path).await;
                        anyhow::bail!("Transfer aborted: {}", reason);
                    }
                }
                _ => {
                    // Ignore other messages
                }
            }
        }

        let elapsed = start_time.elapsed();
        let speed = total_received as f64 / elapsed.as_secs_f64() / 1_000_000.0;

        tracing::info!(
            "Completed pull transfer {}: {} bytes in {:.2}s ({:.2} MB/s)",
            transfer_id, total_received, elapsed.as_secs_f64(), speed
        );

        Ok(TransferInfo {
            id: transfer_id,
            source_path: remote_path.to_string(),
            dest_path: local_path.to_string_lossy().to_string(),
            peer_uuid,
            direction: super::transfer::TransferDirection::Incoming,
            total_bytes: Some(file_size),
            transferred_bytes: total_received,
            state: super::transfer::TransferState::Completed,
            compression: actual_compression,
            started_at: Some(start_time),
            completed_at: Some(Instant::now()),
        })
    }

    /// Pull a directory from a remote peer using streaming tar
    pub async fn pull_directory_from_peer(
        &self,
        peer_uuid: Uuid,
        remote_path: &str,
        local_path: &std::path::Path,
        compression: Compression,
    ) -> anyhow::Result<TransferInfo> {
        use std::io::Read as StdRead;

        // Ensure connected
        if !self.is_connected(peer_uuid).await {
            self.connect(peer_uuid).await?;
        }

        // Generate transfer ID
        let transfer_id = self.transfers.next_transfer_id();

        // Create destination directory
        tokio::fs::create_dir_all(local_path).await?;

        // Get connection
        let connections = self.connections.read().await;
        let conn = connections
            .get(&peer_uuid)
            .ok_or_else(|| anyhow::anyhow!("Not connected to peer"))?;
        let mut conn = conn.lock().await;

        // Send StreamPullDirectoryRequest
        let pull_request = PeerMessage::StreamPullDirectoryRequest {
            transfer_id,
            path: remote_path.to_string(),
            compression,
        };
        conn.send(&pull_request).await?;

        tracing::info!(
            "Requesting directory pull {} from peer: {} -> {}",
            transfer_id, remote_path, local_path.display()
        );

        let start_time = Instant::now();

        // Receive StreamStart
        let start_msg = conn.recv().await?;
        let (file_size, actual_compression, is_dir) = match start_msg {
            PeerMessage::StreamStart { transfer_id: tid, size, compression: comp, is_directory, .. } => {
                if tid != transfer_id {
                    anyhow::bail!("Unexpected transfer_id in StreamStart");
                }
                if !is_directory {
                    anyhow::bail!("Expected directory stream but got file stream");
                }
                (size, comp, is_directory)
            }
            PeerMessage::StreamAbort { reason, .. } => {
                anyhow::bail!("Pull request rejected: {}", reason);
            }
            PeerMessage::Error { message, .. } => {
                anyhow::bail!("Pull request error: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response to pull request: {:?}", other);
            }
        };

        tracing::debug!(
            "Directory pull transfer {} started, expecting {} bytes (is_dir: {})",
            transfer_id, file_size, is_dir
        );

        // Collect all tar data (we need the complete stream to extract)
        let mut tar_data = Vec::with_capacity(file_size as usize);
        let mut expected_sequence = 0u64;
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();

        // Receive chunks until StreamEnd
        loop {
            let msg = conn.recv().await?;
            match msg {
                PeerMessage::StreamData { transfer_id: tid, sequence, data } => {
                    if tid != transfer_id {
                        continue;
                    }
                    if sequence != expected_sequence {
                        anyhow::bail!(
                            "Out of sequence chunk: expected {}, got {}",
                            expected_sequence, sequence
                        );
                    }

                    // Data is already in final form (tar, possibly compressed)
                    hasher.update(&data);
                    tar_data.extend_from_slice(&data);
                    expected_sequence += 1;
                }
                PeerMessage::StreamEnd { transfer_id: tid, checksum } => {
                    if tid != transfer_id {
                        continue;
                    }

                    // Verify checksum if provided
                    if let Some(expected) = checksum {
                        let actual = format!("{:016x}", hasher.finish());
                        if actual != expected {
                            anyhow::bail!(
                                "Checksum mismatch: expected {}, got {}",
                                expected, actual
                            );
                        }
                    }
                    break;
                }
                PeerMessage::StreamAbort { transfer_id: tid, reason } => {
                    if tid == transfer_id {
                        anyhow::bail!("Transfer aborted: {}", reason);
                    }
                }
                _ => {}
            }
        }

        let total_received = tar_data.len() as u64;
        tracing::debug!("Received {} bytes of tar data, extracting...", total_received);

        // Decompress if needed
        let decompressed = match actual_compression {
            Compression::None => tar_data,
            Compression::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(&tar_data[..]);
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf)?;
                buf
            }
            Compression::Zstd => {
                zstd::decode_all(std::io::Cursor::new(&tar_data))?
            }
        };

        // Extract tar archive
        let local_path_owned = local_path.to_path_buf();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut archive = tar::Archive::new(&decompressed[..]);
            archive.unpack(&local_path_owned)?;
            Ok(())
        }).await??;

        let elapsed = start_time.elapsed();
        let speed = total_received as f64 / elapsed.as_secs_f64() / 1_000_000.0;

        tracing::info!(
            "Completed directory pull transfer {}: {} bytes in {:.2}s ({:.2} MB/s)",
            transfer_id, total_received, elapsed.as_secs_f64(), speed
        );

        Ok(TransferInfo {
            id: transfer_id,
            source_path: remote_path.to_string(),
            dest_path: local_path.to_string_lossy().to_string(),
            peer_uuid,
            direction: super::transfer::TransferDirection::Incoming,
            total_bytes: Some(file_size),
            transferred_bytes: total_received,
            state: super::transfer::TransferState::Completed,
            compression: actual_compression,
            started_at: Some(start_time),
            completed_at: Some(Instant::now()),
        })
    }
}
