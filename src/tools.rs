//! MCP Tools for UFM
//!
//! Defines all the tools exposed via the Model Context Protocol.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::archive::ArchiveManager;
use crate::crawler::{CrawlOptions, Crawler, DirCheckInput, HashAlgorithm, HashType};
use crate::mcp::{
    CallToolResult, McpServerHandler, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
};
use crate::network::{NetworkService, NodeRef, PeerStatus};
use crate::operations::{CopyOptions, FileManager, ListOptions, ReadOptions, SortBy, WriteOptions};
use crate::platform::FileAttributes;
use crate::security::SecurityPolicy;

/// Shared state for the MCP tools
pub struct ToolState {
    pub file_manager: FileManager,
    pub archive_manager: RwLock<ArchiveManager>,
    pub crawler: Crawler,
    /// Optional network service for P2P functionality
    pub network: Option<Arc<NetworkService>>,
}

impl ToolState {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            file_manager: FileManager::new(policy.clone()),
            archive_manager: RwLock::new(ArchiveManager::new()),
            crawler: Crawler::new(policy),
            network: None,
        }
    }

    /// Create a new ToolState with network service
    pub fn with_network(policy: SecurityPolicy, network: Arc<NetworkService>) -> Self {
        Self {
            file_manager: FileManager::new(policy.clone()),
            archive_manager: RwLock::new(ArchiveManager::new()),
            crawler: Crawler::new(policy),
            network: Some(network),
        }
    }
}

/// UFM MCP Server implementation
pub struct UfmServer {
    pub state: Arc<ToolState>,
    name: String,
    version: String,
    build: String,
}

impl UfmServer {
    pub fn new(policy: SecurityPolicy, name: String, version: String, build: String) -> Self {
        Self {
            state: Arc::new(ToolState::new(policy)),
            name,
            version,
            build,
        }
    }

    /// Create a new UfmServer with P2P networking enabled
    pub fn with_network(
        policy: SecurityPolicy,
        name: String,
        version: String,
        build: String,
        network: Arc<NetworkService>,
    ) -> Self {
        Self {
            state: Arc::new(ToolState::with_network(policy, network)),
            name,
            version,
            build,
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }
}

#[async_trait::async_trait]
impl McpServerHandler for UfmServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }

    fn capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: Some(false),
            }),
        }
    }

    fn instructions(&self) -> Option<String> {
        Some(
            r#"UFM (Universal File Manager) provides comprehensive file management capabilities.

Available operations:
- Read/write files with encoding detection
- List directories with filtering and sorting
- Create, delete, rename, copy files and directories
- Manage file metadata (timestamps, permissions)
- Navigate and extract archives (ZIP, TAR, TAR.GZ)
- Batch operations for multiple files
- Crawl directories for indexing
- Fast file hashing for duplicate detection

Use ufm_list to explore directories and ufm_stat for detailed file info.
Archive paths use :: notation: /path/to/archive.zip::internal/path"#
                .to_string(),
        )
    }

    fn list_tools(&self) -> Vec<Tool> {
        get_tools()
    }

    async fn call_tool(&self, name: &str, args: Value) -> CallToolResult {
        let result = match name {
            "ufm_status" => handle_status(self.state.clone(), args, &self.version, &self.build).await,
            "ufm_read" => handle_read_file(self.state.clone(), args).await,
            "ufm_stat" => handle_stat(self.state.clone(), args).await,
            "ufm_list" => handle_list(self.state.clone(), args).await,
            "ufm_exists" => handle_exists(self.state.clone(), args).await,
            "ufm_search" => handle_search(self.state.clone(), args).await,
            "ufm_write" => handle_write_file(self.state.clone(), args).await,
            "ufm_mkdir" => handle_mkdir(self.state.clone(), args).await,
            "ufm_delete" => handle_delete(self.state.clone(), args).await,
            "ufm_rename" => handle_rename(self.state.clone(), args).await,
            "ufm_copy" => handle_copy(self.state.clone(), args).await,
            "ufm_set_modified" => handle_set_modified(self.state.clone(), args).await,
            "ufm_set_readonly" => handle_set_readonly(self.state.clone(), args).await,
            "ufm_set_permissions" => handle_set_permissions(self.state.clone(), args).await,
            "ufm_batch_set_modified" => handle_batch_set_modified(self.state.clone(), args).await,
            "ufm_batch_set_readonly" => handle_batch_set_readonly(self.state.clone(), args).await,
            "ufm_archive_list" => handle_archive_list(self.state.clone(), args).await,
            "ufm_archive_read" => handle_archive_read(self.state.clone(), args).await,
            "ufm_archive_extract" => handle_archive_extract(self.state.clone(), args).await,
            "ufm_archive_create" => handle_archive_create(self.state.clone(), args).await,
            "ufm_crawl" => handle_crawl(self.state.clone(), args).await,
            "ufm_dir_check" => handle_dir_check(self.state.clone(), args).await,
            "ufm_hash_sample" => handle_hash_sample(self.state.clone(), args).await,
            // P2P Network tools
            "ufm_nodes" => handle_nodes(self.state.clone(), args).await,
            "ufm_ping" => handle_ping(self.state.clone(), args).await,
            "ufm_discover" => handle_discover(self.state.clone(), args).await,
            "ufm_transfer" => handle_transfer(self.state.clone(), args).await,
            "ufm_transfer_status" => handle_transfer_status(self.state.clone(), args).await,
            _ => Err(format!("Unknown tool: {}", name)),
        };

        match result {
            Ok(content) => CallToolResult::success(content),
            Err(e) => CallToolResult::error(e),
        }
    }
}

/// Get all tool definitions
pub fn get_tools() -> Vec<Tool> {
    vec![
        // Status
        status_tool(),
        // Read operations
        read_file_tool(),
        stat_tool(),
        list_tool(),
        exists_tool(),
        search_tool(),
        // Write operations
        write_file_tool(),
        mkdir_tool(),
        delete_tool(),
        rename_tool(),
        copy_tool(),
        // Metadata operations
        set_modified_tool(),
        set_readonly_tool(),
        set_permissions_tool(),
        batch_set_modified_tool(),
        batch_set_readonly_tool(),
        // Archive operations
        archive_list_tool(),
        archive_read_tool(),
        archive_extract_tool(),
        archive_create_tool(),
        // Crawler operations (for USM integration)
        crawl_tool(),
        dir_check_tool(),
        hash_sample_tool(),
        // P2P Network operations
        nodes_tool(),
        ping_tool(),
        discover_tool(),
        transfer_tool(),
        transfer_status_tool(),
    ]
}

// ============================================================================
// Tool Definitions
// ============================================================================

/// Helper to create the node parameter schema for remote execution
fn node_param_schema() -> serde_json::Value {
    json!({
        "oneOf": [
            {"type": "integer", "description": "Node ID (0 = local)"},
            {"type": "string", "description": "Node name or UUID"}
        ],
        "description": "Target node for remote execution. Omit or use 0/'local' for local execution."
    })
}

fn status_tool() -> Tool {
    Tool::new(
        "ufm_status",
        "Get UFM server status including version, build number, and health check. Can target a specific node.",
        json!({
            "type": "object",
            "properties": {
                "node": node_param_schema()
            },
            "required": []
        }),
    )
}

fn read_file_tool() -> Tool {
    Tool::new(
        "ufm_read",
        "Read the contents of a file. Returns text content by default, or base64 for binary files. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read"
                },
                "node": node_param_schema(),
                "encoding": {
                    "type": "string",
                    "description": "Text encoding (utf-8, utf-16, etc.). Auto-detected if not specified."
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset to start reading from"
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to read"
                },
                "as_base64": {
                    "type": "boolean",
                    "description": "Return content as base64 (useful for binary files)"
                }
            },
            "required": ["path"]
        }),
    )
}

fn stat_tool() -> Tool {
    Tool::new(
        "ufm_stat",
        "Get detailed metadata about a file or directory including size, dates, permissions, and MIME type. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to get metadata for"
                },
                "node": node_param_schema()
            },
            "required": ["path"]
        }),
    )
}

fn list_tool() -> Tool {
    Tool::new(
        "ufm_list",
        "List contents of a directory with optional filtering and sorting. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list"
                },
                "node": node_param_schema(),
                "recursive": {
                    "type": "boolean",
                    "description": "List recursively"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum recursion depth"
                },
                "include_hidden": {
                    "type": "boolean",
                    "description": "Include hidden files"
                },
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to filter results (e.g., '*.txt')"
                },
                "sort_by": {
                    "type": "string",
                    "enum": ["name", "size", "modified", "extension"],
                    "description": "Sort order"
                },
                "sort_ascending": {
                    "type": "boolean",
                    "description": "Sort ascending (default true)"
                }
            },
            "required": ["path"]
        }),
    )
}

fn exists_tool() -> Tool {
    Tool::new(
        "ufm_exists",
        "Check if a path exists. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to check"
                },
                "node": node_param_schema()
            },
            "required": ["path"]
        }),
    )
}

fn search_tool() -> Tool {
    Tool::new(
        "ufm_search",
        "Search for files matching a glob pattern recursively. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory to search from"
                },
                "node": node_param_schema(),
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to match (e.g., '*.log', 'test_*')"
                },
                "include_hidden": {
                    "type": "boolean",
                    "description": "Include hidden files in search"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum search depth"
                }
            },
            "required": ["path", "pattern"]
        }),
    )
}

fn write_file_tool() -> Tool {
    Tool::new(
        "ufm_write",
        "Write content to a file. Creates the file and parent directories if they don't exist. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to write to"
                },
                "node": node_param_schema(),
                "content": {
                    "type": "string",
                    "description": "Content to write"
                },
                "append": {
                    "type": "boolean",
                    "description": "Append to file instead of overwriting"
                },
                "from_base64": {
                    "type": "boolean",
                    "description": "Content is base64 encoded (for binary files)"
                }
            },
            "required": ["path", "content"]
        }),
    )
}

fn mkdir_tool() -> Tool {
    Tool::new(
        "ufm_mkdir",
        "Create a directory. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to create"
                },
                "node": node_param_schema(),
                "recursive": {
                    "type": "boolean",
                    "description": "Create parent directories as needed (default true)"
                }
            },
            "required": ["path"]
        }),
    )
}

fn delete_tool() -> Tool {
    Tool::new(
        "ufm_delete",
        "Delete a file or directory. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to delete"
                },
                "node": node_param_schema(),
                "recursive": {
                    "type": "boolean",
                    "description": "Delete directories recursively (required for non-empty dirs)"
                }
            },
            "required": ["path"]
        }),
    )
}

fn rename_tool() -> Tool {
    Tool::new(
        "ufm_rename",
        "Move or rename a file or directory. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "from": {
                    "type": "string",
                    "description": "Source path"
                },
                "to": {
                    "type": "string",
                    "description": "Destination path"
                },
                "node": node_param_schema()
            },
            "required": ["from", "to"]
        }),
    )
}

fn copy_tool() -> Tool {
    Tool::new(
        "ufm_copy",
        "Copy a file or directory. Supports cross-node transfers with source_node and dest_node.",
        json!({
            "type": "object",
            "properties": {
                "from": {
                    "type": "string",
                    "description": "Source path"
                },
                "to": {
                    "type": "string",
                    "description": "Destination path"
                },
                "source_node": node_param_schema(),
                "dest_node": node_param_schema(),
                "overwrite": {
                    "type": "boolean",
                    "description": "Overwrite if destination exists"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Copy directories recursively"
                },
                "preserve_metadata": {
                    "type": "boolean",
                    "description": "Preserve timestamps and permissions"
                }
            },
            "required": ["from", "to"]
        }),
    )
}

fn set_modified_tool() -> Tool {
    Tool::new(
        "ufm_set_modified",
        "Set the modification time of a file.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to modify"
                },
                "time": {
                    "type": "string",
                    "description": "ISO 8601 timestamp (e.g., '2024-01-15T10:30:00Z')"
                }
            },
            "required": ["path", "time"]
        }),
    )
}

fn set_readonly_tool() -> Tool {
    Tool::new(
        "ufm_set_readonly",
        "Set or clear the readonly flag on a file.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to modify"
                },
                "readonly": {
                    "type": "boolean",
                    "description": "True to set readonly, false to clear"
                }
            },
            "required": ["path", "readonly"]
        }),
    )
}

fn set_permissions_tool() -> Tool {
    Tool::new(
        "ufm_set_permissions",
        "Set file permissions (Unix mode or Windows attributes).",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to modify"
                },
                "mode": {
                    "type": "string",
                    "description": "Unix permission mode (e.g., '755', '644'). Ignored on Windows."
                },
                "hidden": {
                    "type": "boolean",
                    "description": "Set hidden attribute (Windows primarily)"
                },
                "readonly": {
                    "type": "boolean",
                    "description": "Set readonly attribute"
                }
            },
            "required": ["path"]
        }),
    )
}

fn batch_set_modified_tool() -> Tool {
    Tool::new(
        "ufm_batch_set_modified",
        "Set modification time on multiple files at once.",
        json!({
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of file paths"
                },
                "time": {
                    "type": "string",
                    "description": "ISO 8601 timestamp to set"
                }
            },
            "required": ["paths", "time"]
        }),
    )
}

fn batch_set_readonly_tool() -> Tool {
    Tool::new(
        "ufm_batch_set_readonly",
        "Set readonly flag on multiple files at once.",
        json!({
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of file paths"
                },
                "readonly": {
                    "type": "boolean",
                    "description": "True to set readonly, false to clear"
                }
            },
            "required": ["paths", "readonly"]
        }),
    )
}

fn archive_list_tool() -> Tool {
    Tool::new(
        "ufm_archive_list",
        "List contents of an archive (ZIP, TAR, TAR.GZ). Use internal_path to navigate within the archive.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the archive file"
                },
                "internal_path": {
                    "type": "string",
                    "description": "Path within the archive (empty for root)"
                }
            },
            "required": ["path"]
        }),
    )
}

fn archive_read_tool() -> Tool {
    Tool::new(
        "ufm_archive_read",
        "Read a file from within an archive without extracting.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the archive file"
                },
                "internal_path": {
                    "type": "string",
                    "description": "Path to the file within the archive"
                },
                "as_base64": {
                    "type": "boolean",
                    "description": "Return content as base64"
                }
            },
            "required": ["path", "internal_path"]
        }),
    )
}

fn archive_extract_tool() -> Tool {
    Tool::new(
        "ufm_archive_extract",
        "Extract a file from an archive to disk.",
        json!({
            "type": "object",
            "properties": {
                "archive_path": {
                    "type": "string",
                    "description": "Path to the archive file"
                },
                "internal_path": {
                    "type": "string",
                    "description": "Path within the archive to extract"
                },
                "destination": {
                    "type": "string",
                    "description": "Destination path on disk"
                }
            },
            "required": ["archive_path", "internal_path", "destination"]
        }),
    )
}

fn archive_create_tool() -> Tool {
    Tool::new(
        "ufm_archive_create",
        "Create a new archive from files. Format determined by extension (.zip, .tar, .tar.gz).",
        json!({
            "type": "object",
            "properties": {
                "archive_path": {
                    "type": "string",
                    "description": "Path for the new archive"
                },
                "files": {
                    "type": "array",
                    "description": "Array of {source, name} objects",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    }
                }
            },
            "required": ["archive_path", "files"]
        }),
    )
}

fn crawl_tool() -> Tool {
    Tool::new(
        "ufm_crawl",
        "Crawl directory tree returning file paths (relative to root), sizes, and modification times. Returns batched results with resume_token for continuation. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "root": {
                    "type": "string",
                    "description": "Root directory to crawl"
                },
                "node": node_param_schema(),
                "batch_size": {
                    "type": "integer",
                    "default": 500,
                    "description": "Number of entries per batch (10-1000, default 500)"
                },
                "resume_token": {
                    "type": "string",
                    "description": "Token from previous incomplete crawl to resume"
                },
                "include_hidden": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include hidden files and directories"
                },
                "skip_patterns": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Glob patterns to skip (e.g., '**/node_modules/*')"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum directory depth (null for unlimited)"
                },
                "dirs_only": {
                    "type": "boolean",
                    "default": false,
                    "description": "Return only directories (for change detection)"
                }
            },
            "required": ["root"]
        }),
    )
}

fn dir_check_tool() -> Tool {
    Tool::new(
        "ufm_dir_check",
        "Quickly check if directories have changed since last crawl without reading all files. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "directories": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "expected_mtime": { "type": "integer" },
                            "expected_children": { "type": "integer" }
                        },
                        "required": ["path", "expected_mtime"]
                    },
                    "description": "Directories to check with their expected state"
                },
                "node": node_param_schema()
            },
            "required": ["directories"]
        }),
    )
}

fn hash_sample_tool() -> Tool {
    Tool::new(
        "ufm_hash_sample",
        "Generate fast fingerprint hashes for duplicate detection without reading entire files. Supports remote nodes.",
        json!({
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Files to hash (max 100 per call)"
                },
                "node": node_param_schema(),
                "algorithm": {
                    "type": "string",
                    "enum": ["sample", "full"],
                    "default": "sample",
                    "description": "sample = first+middle+last 4KB, full = entire file"
                },
                "hash_type": {
                    "type": "string",
                    "enum": ["xxhash", "sha256"],
                    "default": "xxhash",
                    "description": "Hash algorithm (xxhash is faster)"
                }
            },
            "required": ["paths"]
        }),
    )
}

// ============================================================================
// P2P Network Tool Definitions
// ============================================================================

fn nodes_tool() -> Tool {
    Tool::new(
        "ufm_nodes",
        "List all known UFM nodes on the P2P network, including connection status and latency.",
        json!({
            "type": "object",
            "properties": {
                "include_offline": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include disconnected/unreachable nodes"
                }
            }
        }),
    )
}

fn ping_tool() -> Tool {
    Tool::new(
        "ufm_ping",
        "Check connectivity and measure latency to a specific UFM node.",
        json!({
            "type": "object",
            "properties": {
                "node": {
                    "oneOf": [
                        {"type": "integer"},
                        {"type": "string"}
                    ],
                    "description": "Node ID, name, or UUID to ping"
                },
                "count": {
                    "type": "integer",
                    "default": 3,
                    "description": "Number of pings to send"
                }
            },
            "required": ["node"]
        }),
    )
}

fn discover_tool() -> Tool {
    Tool::new(
        "ufm_discover",
        "Trigger immediate network discovery to find new UFM peers.",
        json!({
            "type": "object",
            "properties": {
                "timeout_secs": {
                    "type": "integer",
                    "default": 5,
                    "description": "Discovery timeout in seconds"
                }
            }
        }),
    )
}

fn transfer_tool() -> Tool {
    Tool::new(
        "ufm_transfer",
        "Transfer a file between nodes using streaming. Returns a transfer ID for tracking progress.",
        json!({
            "type": "object",
            "properties": {
                "source_path": {
                    "type": "string",
                    "description": "Path to the source file"
                },
                "source_node": node_param_schema(),
                "dest_path": {
                    "type": "string",
                    "description": "Path to write the file on the destination"
                },
                "dest_node": node_param_schema(),
                "compression": {
                    "type": "string",
                    "enum": ["none", "gzip", "zstd"],
                    "default": "zstd",
                    "description": "Compression method for transfer"
                }
            },
            "required": ["source_path", "dest_path"]
        }),
    )
}

fn transfer_status_tool() -> Tool {
    Tool::new(
        "ufm_transfer_status",
        "Get status of a file transfer by ID, or list all active transfers.",
        json!({
            "type": "object",
            "properties": {
                "transfer_id": {
                    "type": "integer",
                    "description": "Specific transfer ID to check (omit to list all)"
                }
            }
        }),
    )
}

// ============================================================================
// Tool Handlers
// ============================================================================

type ToolResult = Result<String, String>;

/// Extract NodeRef from args and check if it's local or needs remote routing
fn extract_node_ref(args: &Value) -> NodeRef {
    let node = &args["node"];
    if node.is_null() {
        return NodeRef::Local;
    }

    if let Some(id) = node.as_u64() {
        if id == 0 {
            return NodeRef::Local;
        }
        return NodeRef::Id(id as u32);
    }

    if let Some(s) = node.as_str() {
        if s.is_empty() || s == "local" || s == "0" {
            return NodeRef::Local;
        }
        // Try parsing as UUID
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            return NodeRef::Uuid(uuid);
        }
        return NodeRef::Name(s.to_string());
    }

    NodeRef::Local
}

/// Check if a tool request should be routed remotely
/// Returns Ok(None) if local, Ok(Some(result)) if handled remotely, Err if error
async fn maybe_route_remote(
    state: &Arc<ToolState>,
    args: &Value,
    tool_name: &str,
) -> Result<Option<String>, String> {
    let node_ref = extract_node_ref(args);

    // Check if local
    if matches!(node_ref, NodeRef::Local) {
        return Ok(None); // Handle locally
    }

    // Need network service for remote calls
    let network = state.network.as_ref()
        .ok_or("P2P networking not enabled - run with --network flag")?;

    // Check if this node reference is actually local
    if network.peers.is_local(&node_ref).await {
        return Ok(None); // Handle locally
    }

    // Route to remote peer
    let result = network.router.route_tool_request(&node_ref, tool_name, args.clone()).await
        .map_err(|e| format!("Remote call failed: {}", e))?;

    match result {
        Some(tool_result) => {
            match tool_result {
                crate::network::protocol::ToolResult::Success(data) => {
                    Ok(Some(data.to_string()))
                }
                crate::network::protocol::ToolResult::Error(e) => {
                    Err(e)
                }
            }
        }
        None => Ok(None), // Should handle locally (shouldn't happen)
    }
}

async fn handle_status(state: Arc<ToolState>, args: Value, version: &str, build: &str) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_status").await? {
        return Ok(result);
    }

    // Get network interface information
    let network_info = get_network_info();

    // Include P2P network status if enabled
    let p2p_status = if let Some(ref network) = state.network {
        let nodes = network.peers.list_nodes().await;
        let connected = nodes.iter()
            .filter(|n| matches!(n.status, PeerStatus::Connected))
            .count();
        json!({
            "enabled": network.enabled,
            "node_name": network.identity.name,
            "node_uuid": network.identity.uuid.to_string(),
            "peers_discovered": nodes.len() - 1, // Exclude self
            "peers_connected": connected.saturating_sub(1) // Exclude self
        })
    } else {
        json!({
            "enabled": false
        })
    };

    Ok(json!({
        "status": "ok",
        "name": "UFM",
        "version": version,
        "build": build,
        "full_version": format!("{} (build {})", version, build),
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": get_hostname(),
        "network": network_info,
        "p2p": p2p_status
    })
    .to_string())
}

/// Get the system hostname
fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME")) // Windows
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Network interface information
#[derive(serde::Serialize)]
struct NetworkInterface {
    name: String,
    mac: Option<String>,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

/// Get network interface information including MAC addresses and IPs
fn get_network_info() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    // Read from /sys/class/net on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip loopback
                if name == "lo" {
                    continue;
                }

                // Get MAC address
                let mac_path = entry.path().join("address");
                let mac = std::fs::read_to_string(&mac_path)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| s != "00:00:00:00:00:00");

                // Get IP addresses using ip command
                let (ipv4, ipv6) = get_interface_ips(&name);

                // Only include interfaces with MAC or IP
                if mac.is_some() || !ipv4.is_empty() || !ipv6.is_empty() {
                    interfaces.push(NetworkInterface {
                        name,
                        mac,
                        ipv4,
                        ipv6,
                    });
                }
            }
        }
    }

    // On non-Linux, try to get basic info from environment or commands
    #[cfg(not(target_os = "linux"))]
    {
        // Placeholder for Windows/macOS implementation
        // Could use `ipconfig` on Windows or `ifconfig` on macOS
    }

    // Sort interfaces: tailscale first, then eth/en, then others
    interfaces.sort_by(|a: &NetworkInterface, b: &NetworkInterface| {
        let score = |name: &str| -> i32 {
            if name.starts_with("tailscale") { 0 }
            else if name.starts_with("eth") || name.starts_with("en") { 1 }
            else if name.starts_with("wl") { 2 }
            else { 3 }
        };
        score(&a.name).cmp(&score(&b.name))
    });

    interfaces
}

/// Get IPv4 and IPv6 addresses for an interface (Linux)
#[cfg(target_os = "linux")]
fn get_interface_ips(interface: &str) -> (Vec<String>, Vec<String>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    // Try reading from /proc/net or using ip command output parsing
    // Simple approach: read from ip addr show
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", interface])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                // inet 192.168.1.100/24 brd 192.168.1.255 scope global
                if let Some(addr) = line.split_whitespace().nth(1) {
                    // Remove CIDR notation
                    let ip = addr.split('/').next().unwrap_or(addr);
                    ipv4.push(ip.to_string());
                }
            } else if line.starts_with("inet6 ") {
                // inet6 fe80::1/64 scope link
                if let Some(addr) = line.split_whitespace().nth(1) {
                    let ip = addr.split('/').next().unwrap_or(addr);
                    // Skip link-local unless it's the only one
                    if !ip.starts_with("fe80:") {
                        ipv6.push(ip.to_string());
                    }
                }
            }
        }
    }

    (ipv4, ipv6)
}

#[cfg(not(target_os = "linux"))]
fn get_interface_ips(_interface: &str) -> (Vec<String>, Vec<String>) {
    (Vec::new(), Vec::new())
}

async fn handle_read_file(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_read").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let options = ReadOptions {
        encoding: args["encoding"].as_str().map(String::from),
        offset: args["offset"].as_u64(),
        length: args["length"].as_u64(),
        as_base64: args["as_base64"].as_bool().unwrap_or(false),
    };

    // Check if this is an archive path
    let path_str = path.to_string_lossy();
    if ArchiveManager::is_virtual_path(&path_str) {
        if let Some(vpath) = crate::archive::VirtualPath::parse(&path_str) {
            let manager = state.archive_manager.read().await;
            let content = manager
                .read(&vpath.archive_path, &vpath.internal_path)
                .map_err(|e| e.to_string())?;

            let text = if options.as_base64 {
                use base64::{engine::general_purpose::STANDARD, Engine};
                STANDARD.encode(&content)
            } else {
                String::from_utf8_lossy(&content).to_string()
            };

            return Ok(text);
        }
    }

    let content = state
        .file_manager
        .read_string(&path, &options)
        .map_err(|e| e.to_string())?;

    Ok(content)
}

async fn handle_stat(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_stat").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let metadata = state.file_manager.stat(&path).map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&metadata).map_err(|e| e.to_string())
}

async fn handle_list(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_list").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let sort_by = match args["sort_by"].as_str() {
        Some("size") => SortBy::Size,
        Some("modified") => SortBy::Modified,
        Some("extension") => SortBy::Extension,
        _ => SortBy::Name,
    };

    let options = ListOptions {
        recursive: args["recursive"].as_bool().unwrap_or(false),
        max_depth: args["max_depth"].as_u64().map(|d| d as u32),
        include_hidden: args["include_hidden"].as_bool().unwrap_or(false),
        follow_symlinks: false,
        pattern: args["pattern"].as_str().map(String::from),
        sort_by,
        sort_ascending: args["sort_ascending"].as_bool().unwrap_or(true),
    };

    // Check for archive path
    let path_str = path.to_string_lossy();
    if ArchiveManager::is_virtual_path(&path_str) {
        if let Some(vpath) = crate::archive::VirtualPath::parse(&path_str) {
            let mut manager = state.archive_manager.write().await;
            let entries = manager
                .list(&vpath.archive_path, &vpath.internal_path)
                .map_err(|e| e.to_string())?;

            return serde_json::to_string_pretty(&entries).map_err(|e| e.to_string());
        }
    }

    let entries = state
        .file_manager
        .list(&path, &options)
        .map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())
}

async fn handle_exists(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_exists").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let exists = state.file_manager.exists(&path).map_err(|e| e.to_string())?;

    Ok(json!({ "exists": exists }).to_string())
}

async fn handle_search(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_search").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let pattern = args["pattern"]
        .as_str()
        .ok_or("pattern is required")?;

    let options = ListOptions {
        recursive: true,
        max_depth: args["max_depth"].as_u64().map(|d| d as u32),
        include_hidden: args["include_hidden"].as_bool().unwrap_or(false),
        ..Default::default()
    };

    let results = state
        .file_manager
        .search(&path, pattern, &options)
        .map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&results).map_err(|e| e.to_string())
}

async fn handle_write_file(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_write").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let content = args["content"]
        .as_str()
        .ok_or("content is required")?;

    let options = WriteOptions {
        create: true,
        append: args["append"].as_bool().unwrap_or(false),
        truncate: !args["append"].as_bool().unwrap_or(false),
        from_base64: args["from_base64"].as_bool().unwrap_or(false),
        ..Default::default()
    };

    let bytes_written = state
        .file_manager
        .write_string(&path, content, &options)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "bytes_written": bytes_written,
        "path": path.to_string_lossy()
    })
    .to_string())
}

async fn handle_mkdir(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_mkdir").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let recursive = args["recursive"].as_bool().unwrap_or(true);

    state
        .file_manager
        .mkdir(&path, recursive)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path.to_string_lossy()
    })
    .to_string())
}

async fn handle_delete(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_delete").await? {
        return Ok(result);
    }

    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let recursive = args["recursive"].as_bool().unwrap_or(false);

    state
        .file_manager
        .delete(&path, recursive)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "deleted": path.to_string_lossy()
    })
    .to_string())
}

async fn handle_rename(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_rename").await? {
        return Ok(result);
    }

    let from: PathBuf = args["from"]
        .as_str()
        .ok_or("from is required")?
        .into();

    let to: PathBuf = args["to"]
        .as_str()
        .ok_or("to is required")?
        .into();

    state
        .file_manager
        .rename(&from, &to)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "from": from.to_string_lossy(),
        "to": to.to_string_lossy()
    })
    .to_string())
}

async fn handle_copy(state: Arc<ToolState>, args: Value) -> ToolResult {
    let from: PathBuf = args["from"]
        .as_str()
        .ok_or("from is required")?
        .into();

    let to: PathBuf = args["to"]
        .as_str()
        .ok_or("to is required")?
        .into();

    let options = CopyOptions {
        overwrite: args["overwrite"].as_bool().unwrap_or(false),
        recursive: args["recursive"].as_bool().unwrap_or(false),
        preserve_metadata: args["preserve_metadata"].as_bool().unwrap_or(true),
    };

    let bytes_copied = state
        .file_manager
        .copy(&from, &to, &options)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "bytes_copied": bytes_copied
    })
    .to_string())
}

async fn handle_set_modified(state: Arc<ToolState>, args: Value) -> ToolResult {
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let time_str = args["time"]
        .as_str()
        .ok_or("time is required")?;

    let time: DateTime<Utc> = time_str
        .parse()
        .map_err(|e| format!("Invalid timestamp: {}", e))?;

    state
        .file_manager
        .set_modified(&path, time)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path.to_string_lossy()
    })
    .to_string())
}

async fn handle_set_readonly(state: Arc<ToolState>, args: Value) -> ToolResult {
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let readonly = args["readonly"]
        .as_bool()
        .ok_or("readonly is required")?;

    state
        .file_manager
        .set_readonly(&path, readonly)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path.to_string_lossy(),
        "readonly": readonly
    })
    .to_string())
}

async fn handle_set_permissions(_state: Arc<ToolState>, args: Value) -> ToolResult {
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let mode: Option<u32> = args["mode"]
        .as_str()
        .map(|s| u32::from_str_radix(s, 8))
        .transpose()
        .map_err(|e| format!("Invalid mode: {}", e))?;

    let attrs = if args["hidden"].is_boolean() || args["readonly"].is_boolean() {
        let mut current = FileAttributes::get(&path).map_err(|e| e.to_string())?;

        if let Some(hidden) = args["hidden"].as_bool() {
            current.hidden = hidden;
        }
        if let Some(readonly) = args["readonly"].as_bool() {
            current.readonly = readonly;
        }

        Some(current)
    } else {
        None
    };

    crate::platform::set_permissions(&path, mode, attrs).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path.to_string_lossy()
    })
    .to_string())
}

async fn handle_batch_set_modified(state: Arc<ToolState>, args: Value) -> ToolResult {
    let paths: Vec<PathBuf> = args["paths"]
        .as_array()
        .ok_or("paths must be an array")?
        .iter()
        .filter_map(|v| v.as_str().map(PathBuf::from))
        .collect();

    let time_str = args["time"]
        .as_str()
        .ok_or("time is required")?;

    let time: DateTime<Utc> = time_str
        .parse()
        .map_err(|e| format!("Invalid timestamp: {}", e))?;

    let result = state.file_manager.batch_set_modified(&paths, time);

    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

async fn handle_batch_set_readonly(state: Arc<ToolState>, args: Value) -> ToolResult {
    let paths: Vec<PathBuf> = args["paths"]
        .as_array()
        .ok_or("paths must be an array")?
        .iter()
        .filter_map(|v| v.as_str().map(PathBuf::from))
        .collect();

    let readonly = args["readonly"]
        .as_bool()
        .ok_or("readonly is required")?;

    let result = state.file_manager.batch_set_readonly(&paths, readonly);

    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

async fn handle_archive_list(state: Arc<ToolState>, args: Value) -> ToolResult {
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let internal = args["internal_path"].as_str().unwrap_or("");

    let mut manager = state.archive_manager.write().await;
    let entries = manager.list(&path, internal).map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())
}

async fn handle_archive_read(state: Arc<ToolState>, args: Value) -> ToolResult {
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let internal = args["internal_path"]
        .as_str()
        .ok_or("internal_path is required")?;

    let as_base64 = args["as_base64"].as_bool().unwrap_or(false);

    let manager = state.archive_manager.read().await;
    let content = manager.read(&path, internal).map_err(|e| e.to_string())?;

    let text = if as_base64 {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(&content)
    } else {
        String::from_utf8_lossy(&content).to_string()
    };

    Ok(text)
}

async fn handle_archive_extract(state: Arc<ToolState>, args: Value) -> ToolResult {
    let archive: PathBuf = args["archive_path"]
        .as_str()
        .ok_or("archive_path is required")?
        .into();

    let internal = args["internal_path"]
        .as_str()
        .ok_or("internal_path is required")?;

    let dest: PathBuf = args["destination"]
        .as_str()
        .ok_or("destination is required")?
        .into();

    let manager = state.archive_manager.read().await;
    manager
        .extract(&archive, internal, &dest)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "extracted_to": dest.to_string_lossy()
    })
    .to_string())
}

async fn handle_archive_create(state: Arc<ToolState>, args: Value) -> ToolResult {
    let archive: PathBuf = args["archive_path"]
        .as_str()
        .ok_or("archive_path is required")?
        .into();

    let files_array = args["files"]
        .as_array()
        .ok_or("files must be an array")?;

    let files: Vec<(PathBuf, String)> = files_array
        .iter()
        .filter_map(|f| {
            let source = f["source"].as_str()?;
            let name = f["name"].as_str()?;
            Some((PathBuf::from(source), name.to_string()))
        })
        .collect();

    let files_refs: Vec<(&PathBuf, &str)> = files.iter().map(|(p, n)| (p, n.as_str())).collect();

    let manager = state.archive_manager.read().await;
    manager
        .create(&archive, &files_refs)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "archive": archive.to_string_lossy(),
        "files_added": files.len()
    })
    .to_string())
}

/// Maximum response size in bytes to prevent MCP client timeouts
const MAX_RESPONSE_SIZE: usize = 300_000; // 300KB - conservative for Claude Desktop

/// Estimated bytes per entry for size calculation (reduced with minimal entry format)
const ESTIMATED_BYTES_PER_ENTRY: usize = 100;

async fn handle_crawl(state: Arc<ToolState>, args: Value) -> ToolResult {
    // Check for remote routing
    if let Some(result) = maybe_route_remote(&state, &args, "ufm_crawl").await? {
        return Ok(result);
    }

    // Defensive check for empty/null arguments
    if args.is_null() || (args.is_object() && args.as_object().map(|o| o.is_empty()).unwrap_or(false)) {
        tracing::warn!("ufm_crawl: received empty arguments");
        return Err("ufm_crawl requires 'root' parameter".to_string());
    }

    let root: PathBuf = args["root"]
        .as_str()
        .ok_or("root is required")?
        .into();

    // Default to 500 - lightweight entries allow larger batches
    let requested_batch_size = args["batch_size"].as_u64().unwrap_or(500) as usize;

    // Calculate a safe batch size based on estimated response size
    let safe_batch_size = MAX_RESPONSE_SIZE / ESTIMATED_BYTES_PER_ENTRY;
    let batch_size = requested_batch_size.clamp(10, safe_batch_size.min(2000));

    if batch_size != requested_batch_size {
        tracing::debug!(
            "ufm_crawl: adjusted batch_size from {} to {} for response safety",
            requested_batch_size,
            batch_size
        );
    }

    let include_hidden = args["include_hidden"].as_bool().unwrap_or(false);
    let dirs_only = args["dirs_only"].as_bool().unwrap_or(false);
    let max_depth = args["max_depth"].as_u64().map(|d| d as usize);
    let resume_token = args["resume_token"].as_str();

    tracing::info!(
        "ufm_crawl: root={}, batch_size={}, dirs_only={}, resume={}",
        root.display(),
        batch_size,
        dirs_only,
        resume_token.is_some()
    );

    let skip_patterns: Vec<glob::Pattern> = args["skip_patterns"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| glob::Pattern::new(s).ok())
                .collect()
        })
        .unwrap_or_default();

    let options = CrawlOptions {
        batch_size,
        include_hidden,
        skip_patterns,
        max_depth,
        dirs_only,
    };

    let crawl_start = std::time::Instant::now();

    // Run the crawl in a blocking task to avoid blocking the async runtime
    // WalkDir is synchronous and can take a while on large directories
    let crawler = state.crawler.clone();
    let root_clone = root.clone();
    let options_clone = options.clone();
    let resume_token_owned = resume_token.map(|s| s.to_string());

    let result = tokio::task::spawn_blocking(move || {
        crawler.crawl(
            &root_clone,
            &options_clone,
            resume_token_owned.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("Crawl task panicked: {}", e))?
    .map_err(|e| {
        tracing::error!("ufm_crawl error: {}", e);
        e.to_string()
    })?;

    let crawl_duration = crawl_start.elapsed();
    tracing::info!(
        "ufm_crawl: found {} entries, {} dirs, complete={}, took {:?}",
        result.entries.len(),
        result.directories_seen.len(),
        result.complete,
        crawl_duration
    );

    // Use compact JSON (no pretty print) to reduce size
    let json_result = serde_json::to_string(&result).map_err(|e| e.to_string())?;
    let response_size = json_result.len();

    tracing::debug!("ufm_crawl: response size = {} bytes", response_size);

    // If still too large, return a summary with the resume token
    if response_size > MAX_RESPONSE_SIZE {
        tracing::warn!(
            "ufm_crawl: response too large ({} bytes > {} max), returning summary",
            response_size,
            MAX_RESPONSE_SIZE
        );

        // Return a smaller response that still allows continuation
        let summary = json!({
            "warning": format!(
                "Response would be {} bytes, exceeding {} limit. Reduce batch_size (was {}) or use dirs_only:true",
                response_size,
                MAX_RESPONSE_SIZE,
                batch_size
            ),
            "entries_count": result.entries.len(),
            "directories_count": result.directories_seen.len(),
            "complete": result.complete,
            "resume_token": result.resume_token,
            "progress": result.progress,
            "errors": result.errors,
            // Include just the first few entries as a sample
            "entries_sample": result.entries.iter().take(10).collect::<Vec<_>>(),
            "recommended_batch_size": (batch_size / 2).max(10)
        });

        Ok(serde_json::to_string(&summary).map_err(|e| e.to_string())?)
    } else {
        Ok(json_result)
    }
}

async fn handle_dir_check(state: Arc<ToolState>, args: Value) -> ToolResult {
    let directories: Vec<DirCheckInput> = args["directories"]
        .as_array()
        .ok_or("directories must be an array")?
        .iter()
        .filter_map(|v| {
            let path = PathBuf::from(v["path"].as_str()?);
            let expected_mtime = v["expected_mtime"].as_i64()?;
            let expected_children = v["expected_children"].as_u64().map(|c| c as u32);
            Some(DirCheckInput {
                path,
                expected_mtime,
                expected_children,
            })
        })
        .collect();

    let (results, summary) = state
        .crawler
        .dir_check(&directories)
        .map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&json!({
        "results": results,
        "summary": summary
    }))
    .map_err(|e| e.to_string())
}

async fn handle_hash_sample(state: Arc<ToolState>, args: Value) -> ToolResult {
    let paths: Vec<PathBuf> = args["paths"]
        .as_array()
        .ok_or("paths must be an array")?
        .iter()
        .filter_map(|v| v.as_str().map(PathBuf::from))
        .take(100) // Limit to 100 files per call
        .collect();

    let algorithm = match args["algorithm"].as_str() {
        Some("full") => HashAlgorithm::Full,
        _ => HashAlgorithm::Sample,
    };

    let hash_type = match args["hash_type"].as_str() {
        Some("sha256") => HashType::Sha256,
        _ => HashType::XxHash,
    };

    let results = state
        .crawler
        .hash_sample(&paths, algorithm, hash_type)
        .map_err(|e| e.to_string())?;

    // Convert results to serializable format
    let hashes: Vec<Value> = results
        .iter()
        .map(|r| match r {
            Ok(h) => json!({
                "path": h.path.to_string_lossy(),
                "hash": h.hash,
                "algorithm": h.algorithm,
                "bytes_read": h.bytes_read
            }),
            Err(e) => json!({
                "path": e.path.to_string_lossy(),
                "error": e.error
            }),
        })
        .collect();

    let errors: Vec<Value> = results
        .iter()
        .filter_map(|r| match r {
            Err(e) => Some(json!({
                "path": e.path.to_string_lossy(),
                "error": e.error
            })),
            Ok(_) => None,
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "hashes": hashes,
        "errors": errors
    }))
    .map_err(|e| e.to_string())
}

// ============================================================================
// P2P Network Tool Handlers
// ============================================================================

async fn handle_nodes(state: Arc<ToolState>, args: Value) -> ToolResult {
    let include_offline = args["include_offline"].as_bool().unwrap_or(false);

    // Check if network service is available
    if let Some(ref network) = state.network {
        // Use actual network service
        let all_nodes = network.peers.list_nodes().await;

        let nodes: Vec<Value> = all_nodes
            .iter()
            .filter(|n| {
                include_offline || matches!(
                    n.status,
                    PeerStatus::Connected | PeerStatus::Discovered
                )
            })
            .map(|n| {
                json!({
                    "id": n.id,
                    "name": n.name,
                    "uuid": n.uuid.to_string(),
                    "addresses": n.addresses,
                    "status": format!("{:?}", n.status).to_lowercase(),
                    "latency_ms": n.latency_ms,
                    "os": n.os,
                    "version": n.version,
                    "is_local": n.id == 0
                })
            })
            .collect();

        let connected = all_nodes.iter()
            .filter(|n| matches!(n.status, PeerStatus::Connected))
            .count();

        Ok(json!({
            "nodes": nodes,
            "total": all_nodes.len(),
            "connected": connected,
            "network_enabled": network.enabled
        }).to_string())
    } else {
        // Fallback: return local node info only
        let hostname = get_hostname();
        let uuid = get_or_create_node_uuid();

        let local_node = json!({
            "id": 0,
            "name": hostname,
            "uuid": uuid,
            "addresses": ["local"],
            "status": "connected",
            "latency_ms": 0,
            "os": std::env::consts::OS,
            "version": env!("CARGO_PKG_VERSION"),
            "is_local": true
        });

        Ok(json!({
            "nodes": [local_node],
            "total": 1,
            "connected": 1,
            "network_enabled": false,
            "note": "P2P networking not initialized - run with --network flag to enable"
        }).to_string())
    }
}

async fn handle_ping(state: Arc<ToolState>, args: Value) -> ToolResult {
    let node = &args["node"];
    let count = args["count"].as_u64().unwrap_or(3) as u32;

    // Parse node reference
    let is_local = if node.is_null() {
        true
    } else if let Some(id) = node.as_u64() {
        id == 0
    } else if let Some(name) = node.as_str() {
        name == "local" || name.is_empty() || name == "0"
    } else {
        false
    };

    if is_local {
        // Local ping - instant response
        let pings: Vec<u32> = (0..count).map(|_| 0).collect();
        return Ok(json!({
            "node": {
                "id": 0,
                "name": get_hostname(),
                "uuid": get_or_create_node_uuid()
            },
            "pings": pings,
            "avg_ms": 0,
            "min_ms": 0,
            "max_ms": 0,
            "success": true,
            "count": count
        }).to_string());
    }

    // Remote ping - need network service
    if let Some(ref network) = state.network {
        // Parse node reference
        let node_ref = if let Some(id) = node.as_u64() {
            NodeRef::Id(id as u32)
        } else if let Some(name) = node.as_str() {
            // Try parsing as UUID first
            if let Ok(uuid) = uuid::Uuid::parse_str(name) {
                NodeRef::Uuid(uuid)
            } else {
                NodeRef::Name(name.to_string())
            }
        } else {
            return Err("Invalid node reference".to_string());
        };

        // Resolve to UUID
        let peer_uuid = network.peers.resolve_node(&node_ref).await
            .map_err(|e| format!("Node not found: {}", e))?;

        // Get peer info for response
        let nodes = network.peers.list_nodes().await;
        let peer_info = nodes.iter().find(|n| n.uuid == peer_uuid);

        // Perform pings
        let mut pings = Vec::with_capacity(count as usize);
        let mut failures = 0;

        for _ in 0..count {
            match network.peers.ping(peer_uuid).await {
                Ok(latency) => pings.push(latency),
                Err(_) => failures += 1,
            }
        }

        if pings.is_empty() {
            return Err(format!("All {} pings failed", count));
        }

        let avg = pings.iter().sum::<u32>() / pings.len() as u32;
        let min = *pings.iter().min().unwrap_or(&0);
        let max = *pings.iter().max().unwrap_or(&0);

        Ok(json!({
            "node": {
                "id": peer_info.map(|p| p.id).unwrap_or(0),
                "name": peer_info.map(|p| p.name.clone()).unwrap_or_else(|| "unknown".to_string()),
                "uuid": peer_uuid.to_string()
            },
            "pings": pings,
            "avg_ms": avg,
            "min_ms": min,
            "max_ms": max,
            "success": true,
            "count": count,
            "failures": failures
        }).to_string())
    } else {
        Err("P2P networking not initialized - run with --network flag to enable".to_string())
    }
}

async fn handle_discover(state: Arc<ToolState>, args: Value) -> ToolResult {
    let timeout_secs = args["timeout_secs"].as_u64().unwrap_or(5);

    if let Some(ref network) = state.network {
        // Perform discovery
        let discovery = network.discovery.read().await;
        let discovered = discovery.discover_now().await;

        let peers: Vec<Value> = discovered.iter()
            .map(|p| json!({
                "name": p.name,
                "uuid": p.uuid.map(|u| u.to_string()),
                "addresses": p.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "version": p.version,
                "os": p.os,
                "source": format!("{:?}", p.source).to_lowercase()
            }))
            .collect();

        Ok(json!({
            "discovered": peers,
            "count": peers.len(),
            "timeout_secs": timeout_secs,
            "methods": {
                "mdns": network.config.discovery.mdns_enabled,
                "bootstrap": !network.config.discovery.bootstrap_nodes.is_empty()
            }
        }).to_string())
    } else {
        Ok(json!({
            "discovered": [],
            "count": 0,
            "timeout_secs": timeout_secs,
            "methods": {
                "mdns": false,
                "bootstrap": false
            },
            "note": "P2P networking not initialized - run with --network flag to enable"
        }).to_string())
    }
}

/// Get or create a persistent node UUID
fn get_or_create_node_uuid() -> String {
    // Try to read from identity file first
    let identity_path = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ufm")
        .join("identity.json");

    if let Ok(data) = std::fs::read_to_string(&identity_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(uuid) = json["uuid"].as_str() {
                return uuid.to_string();
            }
        }
    }

    // Generate a deterministic UUID from hostname for now
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let hostname = get_hostname();
    let mut hasher = DefaultHasher::new();
    hostname.hash(&mut hasher);
    let hash = hasher.finish();

    // Create a UUID-like string from the hash
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 32) as u32,
        ((hash >> 16) & 0xFFFF) as u16,
        (hash & 0xFFFF) as u16,
        ((hash >> 48) & 0xFFFF) as u16,
        hash & 0xFFFFFFFFFFFF
    )
}

// ============================================================================
// Transfer Tool Handlers
// ============================================================================

async fn handle_transfer(state: Arc<ToolState>, args: Value) -> ToolResult {
    let source_path = args["source_path"]
        .as_str()
        .ok_or("source_path is required")?;

    let dest_path = args["dest_path"]
        .as_str()
        .ok_or("dest_path is required")?;

    // Parse source and dest nodes
    let source_node = {
        let node = &args["source_node"];
        if node.is_null() {
            NodeRef::Local
        } else if let Some(id) = node.as_u64() {
            if id == 0 { NodeRef::Local } else { NodeRef::Id(id as u32) }
        } else if let Some(s) = node.as_str() {
            if s.is_empty() || s == "local" || s == "0" {
                NodeRef::Local
            } else if let Ok(uuid) = uuid::Uuid::parse_str(s) {
                NodeRef::Uuid(uuid)
            } else {
                NodeRef::Name(s.to_string())
            }
        } else {
            NodeRef::Local
        }
    };

    let dest_node = {
        let node = &args["dest_node"];
        if node.is_null() {
            NodeRef::Local
        } else if let Some(id) = node.as_u64() {
            if id == 0 { NodeRef::Local } else { NodeRef::Id(id as u32) }
        } else if let Some(s) = node.as_str() {
            if s.is_empty() || s == "local" || s == "0" {
                NodeRef::Local
            } else if let Ok(uuid) = uuid::Uuid::parse_str(s) {
                NodeRef::Uuid(uuid)
            } else {
                NodeRef::Name(s.to_string())
            }
        } else {
            NodeRef::Local
        }
    };

    let compression = match args["compression"].as_str() {
        Some("none") => crate::network::Compression::None,
        Some("gzip") => crate::network::Compression::Gzip,
        Some("zstd") | None => crate::network::Compression::Zstd,
        Some(other) => return Err(format!("Unknown compression: {}", other)),
    };

    // Check if this is a local-to-local transfer (just use regular copy)
    let source_is_local = matches!(source_node, NodeRef::Local);
    let dest_is_local = matches!(dest_node, NodeRef::Local);

    if source_is_local && dest_is_local {
        // Simple local copy
        let from = PathBuf::from(source_path);
        let to = PathBuf::from(dest_path);

        let options = CopyOptions {
            overwrite: true,
            recursive: false,
            preserve_metadata: true,
        };

        let copied = state.file_manager.copy(&from, &to, &options)
            .map_err(|e| e.to_string())?;

        return Ok(json!({
            "success": true,
            "transfer_type": "local",
            "bytes_copied": copied,
            "source": source_path,
            "dest": dest_path
        }).to_string());
    }

    // Remote transfer - need network service
    let network = state.network.as_ref()
        .ok_or("P2P networking not enabled - run with --network flag")?;

    // For now, implement a simple pull-from-remote or push-to-remote
    // Full P2P relay transfers would need more infrastructure

    if source_is_local && !dest_is_local {
        // Push to remote: read local file and send via ufm_write tool on remote
        let content = tokio::fs::read(source_path).await
            .map_err(|e| format!("Failed to read source file: {}", e))?;

        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &content);

        let remote_args = json!({
            "path": dest_path,
            "content": encoded,
            "from_base64": true,
            "node": args["dest_node"]
        });

        // Route to remote
        let result = network.router.route_tool_request(&dest_node, "ufm_write", remote_args).await
            .map_err(|e| format!("Remote write failed: {}", e))?;

        match result {
            Some(crate::network::protocol::ToolResult::Success(_)) => {
                Ok(json!({
                    "success": true,
                    "transfer_type": "push",
                    "bytes_transferred": content.len(),
                    "source": source_path,
                    "dest": dest_path,
                    "compression": format!("{:?}", compression).to_lowercase()
                }).to_string())
            }
            Some(crate::network::protocol::ToolResult::Error(e)) => Err(e),
            None => Err("Unexpected local routing for remote transfer".to_string()),
        }
    } else if !source_is_local && dest_is_local {
        // Pull from remote: use ufm_read tool on remote, then write locally
        let remote_args = json!({
            "path": source_path,
            "as_base64": true,
            "node": args["source_node"]
        });

        let result = network.router.route_tool_request(&source_node, "ufm_read", remote_args).await
            .map_err(|e| format!("Remote read failed: {}", e))?;

        let content = match result {
            Some(crate::network::protocol::ToolResult::Success(data)) => {
                // Parse the response - it should be base64 content
                let response: serde_json::Value = serde_json::from_str(&data.to_string())
                    .map_err(|_| "Failed to parse remote response")?;
                let encoded = response["content"].as_str()
                    .ok_or("Remote response missing content")?;
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                    .map_err(|e| format!("Failed to decode content: {}", e))?
            }
            Some(crate::network::protocol::ToolResult::Error(e)) => return Err(e),
            None => return Err("Unexpected local routing for remote transfer".to_string()),
        };

        // Write locally
        let dest = PathBuf::from(dest_path);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| format!("Failed to create parent directories: {}", e))?;
        }
        tokio::fs::write(&dest, &content).await
            .map_err(|e| format!("Failed to write destination file: {}", e))?;

        Ok(json!({
            "success": true,
            "transfer_type": "pull",
            "bytes_transferred": content.len(),
            "source": source_path,
            "dest": dest_path,
            "compression": format!("{:?}", compression).to_lowercase()
        }).to_string())
    } else {
        // Remote-to-remote transfer - would need relay or direct P2P
        Err("Remote-to-remote transfers not yet implemented - transfer to local first".to_string())
    }
}

async fn handle_transfer_status(state: Arc<ToolState>, args: Value) -> ToolResult {
    // For now, we don't have a TransferManager in ToolState
    // This is a placeholder for when we add full streaming transfer support

    let transfer_id = args["transfer_id"].as_u64();

    if let Some(_id) = transfer_id {
        // Would look up specific transfer
        Ok(json!({
            "error": "Transfer tracking not yet implemented - transfers complete synchronously"
        }).to_string())
    } else {
        // List all transfers
        Ok(json!({
            "transfers": [],
            "note": "Transfer tracking not yet implemented - transfers complete synchronously"
        }).to_string())
    }
}
