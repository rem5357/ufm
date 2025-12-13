//! UFM - Universal File Manager Library
//!
//! Cross-platform file management with MCP integration and P2P networking.

pub mod archive;
pub mod crawler;
pub mod mcp;
pub mod network;
pub mod operations;
pub mod platform;
pub mod security;
pub mod tools;

pub use archive::{ArchiveFormat, ArchiveManager, VirtualPath};
pub use crawler::{CrawlOptions, CrawlResult, Crawler, HashAlgorithm, HashType};
pub use mcp::{run_stdio_server, McpServerHandler};
pub use network::{NetworkConfig, NetworkService, NodeIdentity, NodeRef, PeerManager};
pub use operations::{DirEntry, FileManager, FileMetadata};
pub use security::{SecurityError, SecurityPolicy};
pub use tools::{ToolState, UfmServer};
