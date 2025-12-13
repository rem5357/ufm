//! P2P Protocol Messages
//!
//! Binary protocol for communication between UFM peers.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use super::identity::NodeIdentity;
use super::config::Compression;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Magic bytes to identify UFM protocol
pub const PROTOCOL_MAGIC: &[u8; 4] = b"UFM1";

/// All possible messages between peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    // ==================== Handshake ====================
    /// Initial hello with identity
    Hello {
        identity: NodeIdentity,
        protocol_version: u32,
    },

    /// Reject connection
    Reject { reason: String },

    /// Handshake accepted
    Accept { identity: NodeIdentity },

    // ==================== Discovery ====================
    /// Request peer list from a node
    DiscoveryRequest { requester: NodeIdentity },

    /// Response with known peers
    DiscoveryResponse { peers: Vec<DiscoveredPeer> },

    /// Register with a bootstrap node
    RegisterRequest {
        identity: NodeIdentity,
        addresses: Vec<SocketAddr>,
    },

    /// Registration response
    RegisterResponse {
        success: bool,
        reason: Option<String>,
    },

    // ==================== Tool Execution ====================
    /// Execute a tool on this node
    ToolRequest {
        id: u64,
        tool: String,
        params: serde_json::Value,
    },

    /// Tool execution result
    ToolResponse {
        id: u64,
        result: ToolResult,
    },

    // ==================== Streaming Transfers ====================
    /// Start a streaming transfer
    StreamStart {
        transfer_id: u64,
        path: String,
        size: u64,
        is_directory: bool,
        compression: Compression,
    },

    /// Stream data chunk
    StreamData {
        transfer_id: u64,
        sequence: u64,
        data: Vec<u8>,
    },

    /// End of stream
    StreamEnd {
        transfer_id: u64,
        checksum: Option<String>,
    },

    /// Acknowledge received data
    StreamAck {
        transfer_id: u64,
        received_bytes: u64,
    },

    /// Abort a transfer
    StreamAbort { transfer_id: u64, reason: String },

    // ==================== P2P Transfer Orchestration ====================
    /// Tell a peer to send data to another peer
    InitiateTransfer {
        transfer_id: u64,
        source_path: String,
        dest_address: SocketAddr,
        dest_path: String,
        compression: Compression,
    },

    /// Transfer progress update
    TransferProgress {
        transfer_id: u64,
        bytes_transferred: u64,
        total_bytes: u64,
    },

    /// Transfer completed
    TransferComplete {
        transfer_id: u64,
        bytes_transferred: u64,
        duration_ms: u64,
    },

    /// Transfer failed
    TransferFailed {
        transfer_id: u64,
        error: String,
    },

    // ==================== Health ====================
    /// Ping request
    Ping { timestamp: u64 },

    /// Ping response
    Pong { timestamp: u64, server_time: u64 },

    // ==================== Error ====================
    /// Generic error
    Error { code: u32, message: String },
}

/// Result of a tool execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToolResult {
    Success(serde_json::Value),
    Error(String),
}

/// Information about a discovered peer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    /// Peer's name
    pub name: String,

    /// Peer's UUID (if known)
    pub uuid: Option<Uuid>,

    /// Known addresses for this peer
    pub addresses: Vec<SocketAddr>,

    /// UFM version (if known)
    pub version: Option<String>,

    /// Operating system (if known)
    pub os: Option<String>,

    /// How this peer was discovered
    pub source: DiscoverySource,
}

/// How a peer was discovered
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// Local network mDNS
    Mdns,
    /// Bootstrap node
    Bootstrap,
    /// Manual configuration
    Manual,
    /// Referred by another peer
    Referral,
}

/// Frame header for binary protocol
#[derive(Clone, Debug)]
pub struct FrameHeader {
    /// Total payload length (not including header)
    pub length: u32,
    /// Message type (for quick routing without deserializing)
    pub message_type: MessageType,
}

/// Quick message type identification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 0x01,
    Discovery = 0x02,
    ToolRequest = 0x03,
    ToolResponse = 0x04,
    StreamControl = 0x05,
    StreamData = 0x06,
    Health = 0x07,
    Error = 0x08,
}

impl PeerMessage {
    /// Get the message type for framing
    pub fn message_type(&self) -> MessageType {
        match self {
            PeerMessage::Hello { .. }
            | PeerMessage::Reject { .. }
            | PeerMessage::Accept { .. } => MessageType::Handshake,

            PeerMessage::DiscoveryRequest { .. }
            | PeerMessage::DiscoveryResponse { .. }
            | PeerMessage::RegisterRequest { .. }
            | PeerMessage::RegisterResponse { .. } => MessageType::Discovery,

            PeerMessage::ToolRequest { .. } => MessageType::ToolRequest,
            PeerMessage::ToolResponse { .. } => MessageType::ToolResponse,

            PeerMessage::StreamStart { .. }
            | PeerMessage::StreamEnd { .. }
            | PeerMessage::StreamAck { .. }
            | PeerMessage::StreamAbort { .. }
            | PeerMessage::InitiateTransfer { .. }
            | PeerMessage::TransferProgress { .. }
            | PeerMessage::TransferComplete { .. }
            | PeerMessage::TransferFailed { .. } => MessageType::StreamControl,

            PeerMessage::StreamData { .. } => MessageType::StreamData,

            PeerMessage::Ping { .. } | PeerMessage::Pong { .. } => MessageType::Health,

            PeerMessage::Error { .. } => MessageType::Error,
        }
    }

    /// Serialize message to bytes
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let payload = bincode::serialize(self)?;
        let msg_type = self.message_type() as u8;
        let length = payload.len() as u32;

        let mut frame = Vec::with_capacity(4 + 1 + 4 + payload.len());
        frame.extend_from_slice(PROTOCOL_MAGIC);
        frame.push(msg_type);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);

        Ok(frame)
    }

    /// Deserialize message from bytes (after header)
    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(data)?)
    }
}

impl FrameHeader {
    /// Size of the frame header in bytes
    pub const SIZE: usize = 4 + 1 + 4; // magic + type + length

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < Self::SIZE {
            anyhow::bail!("Frame header too short");
        }

        // Check magic
        if &data[0..4] != PROTOCOL_MAGIC {
            anyhow::bail!("Invalid protocol magic");
        }

        let message_type = match data[4] {
            0x01 => MessageType::Handshake,
            0x02 => MessageType::Discovery,
            0x03 => MessageType::ToolRequest,
            0x04 => MessageType::ToolResponse,
            0x05 => MessageType::StreamControl,
            0x06 => MessageType::StreamData,
            0x07 => MessageType::Health,
            0x08 => MessageType::Error,
            other => anyhow::bail!("Unknown message type: {}", other),
        };

        let length = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);

        Ok(Self {
            length,
            message_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = PeerMessage::Ping {
            timestamp: 12345,
        };

        let encoded = msg.encode().unwrap();
        assert!(encoded.starts_with(PROTOCOL_MAGIC));

        let header = FrameHeader::parse(&encoded).unwrap();
        assert_eq!(header.message_type, MessageType::Health);

        let decoded = PeerMessage::decode(&encoded[FrameHeader::SIZE..]).unwrap();
        if let PeerMessage::Ping { timestamp } = decoded {
            assert_eq!(timestamp, 12345);
        } else {
            panic!("Wrong message type");
        }
    }
}
