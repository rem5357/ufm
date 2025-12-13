//! Node Identity Management
//!
//! Each UFM instance has a persistent identity that includes a UUID,
//! human-readable name, and capability list.

use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

/// Capabilities that a node can support
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Basic file read operations
    FileRead,
    /// File write operations
    FileWrite,
    /// Archive operations (zip, tar)
    Archive,
    /// Streaming large file transfers
    Streaming,
    /// Directory synchronization
    DirectorySync,
    /// Crawl/indexing operations
    Crawl,
}

/// A node's identity in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Persistent unique identifier (generated once, stored in config)
    pub uuid: Uuid,

    /// Human-readable name (from config or hostname)
    pub name: String,

    /// Operating system
    pub os: String,

    /// CPU architecture
    pub arch: String,

    /// UFM version
    pub version: String,

    /// Build number
    pub build: String,

    /// Capabilities this node supports
    pub capabilities: Vec<Capability>,
}

impl NodeIdentity {
    /// Generate a new identity
    pub fn generate(name: Option<String>) -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            uuid: Uuid::new_v4(),
            name: name.unwrap_or(hostname),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build: option_env!("UFM_BUILD_NUMBER")
                .unwrap_or("0")
                .to_string(),
            capabilities: vec![
                Capability::FileRead,
                Capability::FileWrite,
                Capability::Archive,
                Capability::Streaming,
                Capability::DirectorySync,
                Capability::Crawl,
            ],
        }
    }

    /// Load identity from file or generate new one
    pub fn load_or_create(config_path: &Path) -> anyhow::Result<Self> {
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            let mut identity: NodeIdentity = toml::from_str(&content)?;

            // Update version/build info on load
            identity.version = env!("CARGO_PKG_VERSION").to_string();
            identity.build = option_env!("UFM_BUILD_NUMBER")
                .unwrap_or("0")
                .to_string();
            identity.os = std::env::consts::OS.to_string();
            identity.arch = std::env::consts::ARCH.to_string();

            Ok(identity)
        } else {
            let identity = Self::generate(None);

            // Ensure parent directory exists
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let content = toml::to_string_pretty(&identity)?;
            std::fs::write(config_path, content)?;

            tracing::info!("Generated new node identity: {}", identity.uuid);
            Ok(identity)
        }
    }

    /// Check if this node has a specific capability
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Get a short display string
    pub fn display_short(&self) -> String {
        format!("{} ({})", self.name, &self.uuid.to_string()[..8])
    }
}

impl Default for NodeIdentity {
    fn default() -> Self {
        Self::generate(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let id1 = NodeIdentity::generate(None);
        let id2 = NodeIdentity::generate(None);

        // UUIDs should be unique
        assert_ne!(id1.uuid, id2.uuid);

        // Should have all default capabilities
        assert!(id1.has_capability(&Capability::FileRead));
        assert!(id1.has_capability(&Capability::Streaming));
    }

    #[test]
    fn test_identity_with_name() {
        let id = NodeIdentity::generate(Some("test-node".to_string()));
        assert_eq!(id.name, "test-node");
    }
}
