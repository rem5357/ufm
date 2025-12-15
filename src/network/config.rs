//! Network Configuration
//!
//! Configuration for P2P networking, discovery, and transfers.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Main network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable P2P networking
    #[serde(default)]
    pub enabled: bool,

    /// Port to listen on for peer connections
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// Address to bind to (0.0.0.0 for all interfaces)
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Path to identity file
    #[serde(default = "default_identity_path")]
    pub identity_path: PathBuf,

    /// Discovery configuration
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Transfer configuration
    #[serde(default)]
    pub transfer: TransferConfig,

    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,
}

fn default_listen_port() -> u16 {
    9847
}

fn default_listen_address() -> String {
    "0.0.0.0".to_string()
}

fn default_identity_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ufm")
        .join("identity.toml")
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: default_listen_port(),
            listen_address: default_listen_address(),
            identity_path: default_identity_path(),
            discovery: DiscoveryConfig::default(),
            transfer: TransferConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl NetworkConfig {
    /// Configuration for a home server (bootstrap node)
    pub fn home_server() -> Self {
        Self {
            enabled: true,
            listen_port: 9847,
            discovery: DiscoveryConfig {
                mdns_enabled: true,
                bootstrap_nodes: vec![], // We ARE the bootstrap
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Configuration for a desktop PC (mDNS zero-config, optional bootstrap)
    pub fn desktop(bootstrap_addr: Option<SocketAddr>) -> Self {
        Self {
            enabled: true,
            listen_port: 9847,
            discovery: DiscoveryConfig {
                mdns_enabled: true,
                bootstrap_nodes: bootstrap_addr.into_iter().collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Configuration for a laptop (more aggressive discovery, mDNS zero-config)
    pub fn laptop(bootstrap_addr: Option<SocketAddr>) -> Self {
        Self {
            enabled: true,
            listen_port: 9847,
            discovery: DiscoveryConfig {
                mdns_enabled: true,
                bootstrap_nodes: bootstrap_addr.into_iter().collect(),
                discovery_interval_secs: 15,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Standalone mode (no networking)
    pub fn standalone() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Discovery configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable mDNS discovery (local network)
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// mDNS service type
    #[serde(default = "default_mdns_service")]
    pub mdns_service_type: String,

    /// Bootstrap nodes (optional - mDNS provides zero-config discovery)
    #[serde(default)]
    pub bootstrap_nodes: Vec<SocketAddr>,

    /// How often to run discovery (seconds)
    #[serde(default = "default_discovery_interval")]
    pub discovery_interval_secs: u64,

    /// How often to re-announce ourselves (seconds)
    #[serde(default = "default_announce_interval")]
    pub announce_interval_secs: u64,

    /// How long before marking a peer as stale (seconds)
    #[serde(default = "default_peer_timeout")]
    pub peer_timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_mdns_service() -> String {
    "_ufm._tcp.local.".to_string()
}

fn default_discovery_interval() -> u64 {
    30
}

fn default_announce_interval() -> u64 {
    60
}

fn default_peer_timeout() -> u64 {
    120
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mdns_enabled: true,
            mdns_service_type: default_mdns_service(),
            bootstrap_nodes: vec![],
            discovery_interval_secs: default_discovery_interval(),
            announce_interval_secs: default_announce_interval(),
            peer_timeout_secs: default_peer_timeout(),
        }
    }
}

impl DiscoveryConfig {
    pub fn discovery_interval(&self) -> Duration {
        Duration::from_secs(self.discovery_interval_secs)
    }

    pub fn announce_interval(&self) -> Duration {
        Duration::from_secs(self.announce_interval_secs)
    }

    pub fn peer_timeout(&self) -> Duration {
        Duration::from_secs(self.peer_timeout_secs)
    }
}

/// Transfer configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferConfig {
    /// Chunk size for streaming transfers (bytes)
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,

    /// Compression for directory transfers
    #[serde(default)]
    pub compression: Compression,

    /// Maximum concurrent transfers
    #[serde(default = "default_max_transfers")]
    pub max_concurrent_transfers: usize,

    /// Network I/O buffer size
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_chunk_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_max_transfers() -> usize {
    4
}

fn default_buffer_size() -> usize {
    64 * 1024 // 64KB
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: default_chunk_size(),
            compression: Compression::default(),
            max_concurrent_transfers: default_max_transfers(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Compression options for transfers
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    Gzip,
    #[default]
    Zstd,
}

/// Security configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Only allow connections from Tailscale network
    #[serde(default)]
    pub tailscale_only: bool,

    /// Allowed network ranges (CIDR notation)
    #[serde(default = "default_allowed_networks")]
    pub allowed_networks: Vec<String>,

    /// Explicitly denied addresses
    #[serde(default)]
    pub denied_addresses: Vec<String>,

    /// Require TLS for connections (future)
    #[serde(default)]
    pub require_tls: bool,
}

fn default_allowed_networks() -> Vec<String> {
    vec![
        "100.64.0.0/10".to_string(),  // Tailscale CGNAT
        "192.168.0.0/16".to_string(), // Private class C
        "10.0.0.0/8".to_string(),     // Private class A
        "172.16.0.0/12".to_string(),  // Private class B
        "127.0.0.0/8".to_string(),    // Localhost
    ]
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            tailscale_only: false,
            allowed_networks: default_allowed_networks(),
            denied_addresses: vec![],
            require_tls: false,
        }
    }
}
