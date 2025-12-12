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
use crate::operations::{CopyOptions, FileManager, ListOptions, ReadOptions, SortBy, WriteOptions};
use crate::platform::FileAttributes;
use crate::security::SecurityPolicy;

/// Shared state for the MCP tools
pub struct ToolState {
    pub file_manager: FileManager,
    pub archive_manager: RwLock<ArchiveManager>,
    pub crawler: Crawler,
}

impl ToolState {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            file_manager: FileManager::new(policy.clone()),
            archive_manager: RwLock::new(ArchiveManager::new()),
            crawler: Crawler::new(policy),
        }
    }
}

/// UFM MCP Server implementation
pub struct UfmServer {
    state: Arc<ToolState>,
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
            "ufm_status" => handle_status(&self.version, &self.build).await,
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
    ]
}

// ============================================================================
// Tool Definitions
// ============================================================================

fn status_tool() -> Tool {
    Tool::new(
        "ufm_status",
        "Get UFM server status including version, build number, and health check.",
        json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    )
}

fn read_file_tool() -> Tool {
    Tool::new(
        "ufm_read",
        "Read the contents of a file. Returns text content by default, or base64 for binary files.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read"
                },
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
        "Get detailed metadata about a file or directory including size, dates, permissions, and MIME type.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to get metadata for"
                }
            },
            "required": ["path"]
        }),
    )
}

fn list_tool() -> Tool {
    Tool::new(
        "ufm_list",
        "List contents of a directory with optional filtering and sorting.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list"
                },
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
        "Check if a path exists.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to check"
                }
            },
            "required": ["path"]
        }),
    )
}

fn search_tool() -> Tool {
    Tool::new(
        "ufm_search",
        "Search for files matching a glob pattern recursively.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root directory to search from"
                },
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
        "Write content to a file. Creates the file and parent directories if they don't exist.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to write to"
                },
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
        "Create a directory.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to create"
                },
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
        "Delete a file or directory.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to delete"
                },
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
        "Move or rename a file or directory.",
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
                }
            },
            "required": ["from", "to"]
        }),
    )
}

fn copy_tool() -> Tool {
    Tool::new(
        "ufm_copy",
        "Copy a file or directory.",
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
        "Crawl directory tree returning file paths (relative to root), sizes, and modification times. Returns batched results with resume_token for continuation. Lightweight output to avoid context overflow.",
        json!({
            "type": "object",
            "properties": {
                "root": {
                    "type": "string",
                    "description": "Root directory to crawl"
                },
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
        "Quickly check if directories have changed since last crawl without reading all files.",
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
                }
            },
            "required": ["directories"]
        }),
    )
}

fn hash_sample_tool() -> Tool {
    Tool::new(
        "ufm_hash_sample",
        "Generate fast fingerprint hashes for duplicate detection without reading entire files.",
        json!({
            "type": "object",
            "properties": {
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Files to hash (max 100 per call)"
                },
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
// Tool Handlers
// ============================================================================

type ToolResult = Result<String, String>;

async fn handle_status(version: &str, build: &str) -> ToolResult {
    Ok(json!({
        "status": "ok",
        "name": "UFM",
        "version": version,
        "build": build,
        "full_version": format!("{} (build {})", version, build),
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH
    })
    .to_string())
}

async fn handle_read_file(state: Arc<ToolState>, args: Value) -> ToolResult {
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
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let metadata = state.file_manager.stat(&path).map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&metadata).map_err(|e| e.to_string())
}

async fn handle_list(state: Arc<ToolState>, args: Value) -> ToolResult {
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
    let path: PathBuf = args["path"]
        .as_str()
        .ok_or("path is required")?
        .into();

    let exists = state.file_manager.exists(&path).map_err(|e| e.to_string())?;

    Ok(json!({ "exists": exists }).to_string())
}

async fn handle_search(state: Arc<ToolState>, args: Value) -> ToolResult {
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
