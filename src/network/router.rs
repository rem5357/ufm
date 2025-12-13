//! Request Routing
//!
//! Routes tool requests to the appropriate node (local or remote).

use std::sync::Arc;
use uuid::Uuid;

use super::identity::NodeIdentity;
use super::peer::{NodeRef, PeerManager};
use super::protocol::ToolResult;

/// Routes requests to the appropriate node
pub struct RequestRouter {
    identity: NodeIdentity,
    peer_manager: Arc<PeerManager>,
}

impl RequestRouter {
    /// Create a new request router
    pub fn new(identity: NodeIdentity, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            identity,
            peer_manager,
        }
    }

    /// Check if a node reference points to local
    pub async fn is_local(&self, node_ref: &NodeRef) -> bool {
        self.peer_manager.is_local(node_ref).await
    }

    /// Resolve a node reference to a UUID
    pub async fn resolve(&self, node_ref: &NodeRef) -> anyhow::Result<Uuid> {
        self.peer_manager.resolve_node(node_ref).await
    }

    /// Route a tool request to the appropriate node
    ///
    /// Returns None if the request should be handled locally,
    /// or Some(result) if it was handled remotely.
    pub async fn route_tool_request(
        &self,
        node_ref: &NodeRef,
        tool: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<Option<ToolResult>> {
        // Check if local
        if self.is_local(node_ref).await {
            return Ok(None); // Handle locally
        }

        // Resolve to UUID
        let peer_uuid = self.resolve(node_ref).await?;

        // Forward to peer
        let result = self
            .peer_manager
            .send_tool_request(peer_uuid, tool.to_string(), params)
            .await?;

        Ok(Some(result))
    }

    /// Get our identity
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Get the peer manager
    pub fn peers(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }
}

/// Helper trait for extracting node reference from tool arguments
pub trait NodeRefExtractor {
    /// Extract the node reference from arguments, defaulting to local
    fn extract_node_ref(args: &serde_json::Value) -> NodeRef {
        if let Some(node) = args.get("node") {
            if node.is_null() {
                return NodeRef::Local;
            }

            // Try as integer (node ID)
            if let Some(id) = node.as_u64() {
                return NodeRef::Id(id as u32);
            }

            // Try as string (name or UUID)
            if let Some(s) = node.as_str() {
                if s.is_empty() || s == "local" || s == "0" {
                    return NodeRef::Local;
                }

                // Try parsing as UUID
                if let Ok(uuid) = Uuid::parse_str(s) {
                    return NodeRef::Uuid(uuid);
                }

                // Otherwise treat as name
                return NodeRef::Name(s.to_string());
            }
        }

        NodeRef::Local
    }
}

// Implement for any type
impl<T> NodeRefExtractor for T {}
