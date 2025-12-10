# UFM - Universal File Manager
## Design Document for Claude Code Implementation

**Version:** 0.1.0  
**Author:** Robert  
**Date:** December 2024  
**Target Platforms:** Windows, Linux, macOS

---

## Executive Summary

UFM (Universal File Manager) is a cross-platform MCP (Model Context Protocol) server that provides comprehensive file management capabilities. It enables Claude Desktop and other MCP clients to read, write, search, and manage files with proper security sandboxing.

### Key Goals
1. **Single binary deployment** - No runtime dependencies
2. **Cross-platform** - Windows and Linux with identical behavior
3. **Security first** - Sandboxed access with configurable restrictions
4. **Archive transparency** - Navigate ZIP/TAR files like directories
5. **Batch operations** - Bulk metadata changes for distribution prep

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Client (Claude Desktop)             │
└─────────────────────────────────────────────────────────────┘
                              │ stdio (JSON-RPC)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         UFM Server                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Config    │  │   Tools     │  │   Security Policy   │ │
│  │   Loader    │  │   Router    │  │   (Sandboxing)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│         │               │                    │              │
│         ▼               ▼                    ▼              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Tool State                           ││
│  │  ┌──────────────┐  ┌──────────────┐                    ││
│  │  │ FileManager  │  │ArchiveManager│                    ││
│  │  └──────────────┘  └──────────────┘                    ││
│  └─────────────────────────────────────────────────────────┘│
│         │                    │                              │
│         ▼                    ▼                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  operations  │    │   archive    │    │   platform   │  │
│  │    module    │    │    module    │    │    module    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   File System   │
                    └─────────────────┘
```

---

## Module Design

### 1. Security Module (`src/security.rs`)

**Purpose:** Path validation, sandboxing, and access control.

#### Core Types

```rust
pub struct SecurityPolicy {
    allowed_roots: Vec<PathBuf>,      // Directories that can be accessed
    denied_paths: HashSet<PathBuf>,   // Explicit blocks
    denied_patterns: Vec<String>,     // Glob patterns to block
    allow_writes: bool,               // Can write files
    allow_deletes: bool,              // Can delete files
    allow_chmod: bool,                // Can change permissions
    follow_symlinks: bool,            // Security risk if true
    max_read_size: u64,               // Prevent memory exhaustion
    max_recursion_depth: u32,         // Limit directory traversal
}

pub enum SecurityError {
    PathOutsideSandbox(PathBuf),
    PathDenied(PathBuf),
    OperationDenied(String, PathBuf),
    PathTraversal(String),
    CanonicalizationFailed(std::io::Error),
    InvalidPath(String),
}
```

#### Key Functions

```rust
impl SecurityPolicy {
    // Constructors
    fn new(allowed_roots: Vec<PathBuf>) -> Self;
    fn permissive() -> Self;           // Home directory access
    fn sandboxed(root: PathBuf) -> Self; // Single directory
    
    // Validation
    fn validate_path(&self, path: &Path) -> Result<PathBuf, SecurityError>;
    fn validate_write(&self, path: &Path) -> Result<PathBuf, SecurityError>;
    fn validate_delete(&self, path: &Path) -> Result<PathBuf, SecurityError>;
    fn validate_chmod(&self, path: &Path) -> Result<PathBuf, SecurityError>;
    
    // Internal
    fn normalize_path(&self, path: &Path) -> Result<PathBuf, SecurityError>;
    fn is_within_allowed_roots(&self, path: &Path) -> bool;
    fn matches_denied_pattern(&self, path: &Path) -> bool;
}
```

#### Default Denied Patterns
```rust
vec![
    // Unix system
    "/etc/shadow", "/etc/passwd", "/etc/sudoers*",
    "/root/.ssh/*", "**/.ssh/id_*", "**/.gnupg/*",
    
    // Windows system
    "C:\\Windows\\System32\\config\\*", "**/ntuser.dat*",
    
    // Sensitive files
    "**/.env", "**/.env.*", "**/credentials*", "**/secrets*",
    "**/*.pem", "**/*.key", "**/id_rsa*", "**/id_ed25519*",
]
```

---

### 2. Operations Module (`src/operations.rs`)

**Purpose:** Core file system operations with cross-platform behavior.

#### Core Types

```rust
pub struct FileManager {
    policy: SecurityPolicy,
}

pub struct FileMetadata {
    path: PathBuf,
    name: String,
    extension: Option<String>,
    is_file: bool,
    is_dir: bool,
    is_symlink: bool,
    size: u64,
    created: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    accessed: Option<DateTime<Utc>>,
    readonly: bool,
    hidden: bool,
    permissions: FilePermissions,
    mime_type: Option<String>,
}

pub struct FilePermissions {
    mode: Option<u32>,    // Unix only
    readable: bool,
    writable: bool,
    executable: bool,
}

pub struct DirEntry {
    name: String,
    path: PathBuf,
    is_file: bool,
    is_dir: bool,
    is_symlink: bool,
    size: u64,
    modified: Option<DateTime<Utc>>,
}

pub struct ListOptions {
    recursive: bool,
    max_depth: Option<u32>,
    include_hidden: bool,
    follow_symlinks: bool,
    pattern: Option<String>,     // Glob filter
    sort_by: SortBy,
    sort_ascending: bool,
}

pub enum SortBy { Name, Size, Modified, Extension }

pub struct ReadOptions {
    encoding: Option<String>,
    offset: Option<u64>,
    length: Option<u64>,
    as_base64: bool,
}

pub struct WriteOptions {
    create: bool,
    append: bool,
    truncate: bool,
    encoding: Option<String>,
    from_base64: bool,
}

pub struct CopyOptions {
    overwrite: bool,
    recursive: bool,
    preserve_metadata: bool,
}

pub struct BatchResult {
    total: usize,
    succeeded: usize,
    failed: usize,
    errors: Vec<BatchError>,
}
```

#### Key Functions

```rust
impl FileManager {
    // Read operations
    fn read_string(&self, path: &Path, options: &ReadOptions) -> Result<String>;
    fn read_bytes(&self, path: &Path, options: &ReadOptions) -> Result<Vec<u8>>;
    fn stat(&self, path: &Path) -> Result<FileMetadata>;
    fn list(&self, path: &Path, options: &ListOptions) -> Result<Vec<DirEntry>>;
    fn exists(&self, path: &Path) -> Result<bool>;
    fn search(&self, root: &Path, pattern: &str, options: &ListOptions) -> Result<Vec<DirEntry>>;
    
    // Write operations
    fn write_string(&self, path: &Path, content: &str, options: &WriteOptions) -> Result<u64>;
    fn write_bytes(&self, path: &Path, content: &[u8], options: &WriteOptions) -> Result<u64>;
    fn mkdir(&self, path: &Path, recursive: bool) -> Result<()>;
    fn delete(&self, path: &Path, recursive: bool) -> Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    fn copy(&self, from: &Path, to: &Path, options: &CopyOptions) -> Result<u64>;
    
    // Metadata operations
    fn set_modified(&self, path: &Path, time: DateTime<Utc>) -> Result<()>;
    fn set_accessed(&self, path: &Path, time: DateTime<Utc>) -> Result<()>;
    fn set_readonly(&self, path: &Path, readonly: bool) -> Result<()>;
    
    // Batch operations
    fn batch_set_modified(&self, paths: &[PathBuf], time: DateTime<Utc>) -> BatchResult;
    fn batch_set_readonly(&self, paths: &[PathBuf], readonly: bool) -> BatchResult;
}
```

#### Implementation Notes

- **Encoding detection:** Use `encoding_rs` to auto-detect text encoding, fallback to UTF-8
- **MIME detection:** Use `infer` crate to detect file type by magic bytes
- **Hidden files:** Unix = starts with `.`, Windows = `FILE_ATTRIBUTE_HIDDEN`
- **Directory listing:** Use `walkdir` for recursive traversal

---

### 3. Archive Module (`src/archive.rs`)

**Purpose:** Read/write archives, virtual path navigation.

#### Core Types

```rust
pub enum ArchiveFormat {
    Zip,
    TarGz,
    Tar,
    Unknown,
}

pub struct VirtualPath {
    archive_path: PathBuf,    // /home/user/file.zip
    internal_path: String,    // folder/document.txt
}

pub struct ArchiveEntry {
    name: String,
    path: String,
    is_file: bool,
    is_dir: bool,
    size: u64,
    compressed_size: Option<u64>,
    modified: Option<DateTime<Utc>>,
    crc32: Option<u32>,
    compression_method: Option<String>,
}

pub struct ArchiveManager {
    cache: HashMap<PathBuf, CachedArchive>,  // Performance optimization
}
```

#### Virtual Path Syntax

```
/path/to/archive.zip::internal/folder/file.txt
                    ^^
              Separator (double colon)
```

Example usage:
- `ufm_list` on `/home/user/backup.zip::` lists archive root
- `ufm_list` on `/home/user/backup.zip::documents/` lists documents folder inside
- `ufm_read` on `/home/user/backup.zip::readme.txt` reads file from archive

#### Key Functions

```rust
impl ArchiveManager {
    fn is_archive(path: &Path) -> bool;
    fn is_virtual_path(path: &str) -> bool;
    
    fn list(&mut self, archive_path: &Path, internal_path: &str) -> Result<Vec<ArchiveEntry>>;
    fn read(&self, archive_path: &Path, internal_path: &str) -> Result<Vec<u8>>;
    fn extract(&self, archive_path: &Path, internal_path: &str, dest: &Path) -> Result<()>;
    fn add(&self, archive_path: &Path, internal_path: &str, content: &[u8]) -> Result<()>;
    fn create<P: AsRef<Path>>(&self, archive_path: &Path, files: &[(P, &str)]) -> Result<()>;
}

impl VirtualPath {
    fn parse(path: &str) -> Option<Self>;
    fn new(archive: PathBuf, internal: &str) -> Self;
    fn to_string(&self) -> String;
    fn is_root(&self) -> bool;
}

impl ArchiveFormat {
    fn from_extension(path: &Path) -> Self;
    fn from_magic(data: &[u8]) -> Self;
}
```

#### Supported Formats

| Extension | Format | Read | Write |
|-----------|--------|------|-------|
| .zip, .jar, .war | ZIP | ✓ | ✓ |
| .tar | TAR | ✓ | ✓ |
| .tar.gz, .tgz | TAR+GZIP | ✓ | ✓ |

---

### 4. Platform Module (`src/platform.rs`)

**Purpose:** Platform-specific operations abstracted behind common interface.

#### Unix-Specific (`#[cfg(unix)]`)

```rust
pub mod unix {
    fn chmod(path: &Path, mode: u32) -> Result<()>;
    fn get_mode(path: &Path) -> Result<u32>;
    fn chown(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()>;
    fn get_owner(path: &Path) -> Result<(u32, u32)>;
    
    // Extended attributes
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> Result<()>;
    fn get_xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>>;
    fn list_xattr(path: &Path) -> Result<Vec<String>>;
    fn remove_xattr(path: &Path, name: &str) -> Result<()>;
    
    // Folder appearance
    fn set_folder_color(path: &Path, color: &str) -> Result<()>;
    fn get_folder_color(path: &Path) -> Result<Option<String>>;
}
```

#### Windows-Specific (`#[cfg(windows)]`)

```rust
pub mod windows {
    // File attributes
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
    
    fn get_attributes(path: &Path) -> Result<u32>;
    fn set_attributes(path: &Path, attrs: u32) -> Result<()>;
    fn set_hidden(path: &Path, hidden: bool) -> Result<()>;
    fn is_hidden(path: &Path) -> Result<bool>;
    fn set_system(path: &Path, system: bool) -> Result<()>;
    
    // Folder appearance
    fn set_folder_icon(path: &Path, icon_path: &Path, icon_index: i32) -> Result<()>;
    
    // NTFS alternate data streams
    fn get_ads(path: &Path, stream_name: &str) -> Result<Vec<u8>>;
    fn set_ads(path: &Path, stream_name: &str, data: &[u8]) -> Result<()>;
    fn delete_ads(path: &Path, stream_name: &str) -> Result<()>;
}
```

#### Cross-Platform Abstraction

```rust
pub struct FileAttributes {
    readonly: bool,
    hidden: bool,
    system: bool,    // Windows only
    archive: bool,   // Windows only
}

impl FileAttributes {
    fn get(path: &Path) -> Result<Self>;
    fn apply(&self, path: &Path) -> Result<()>;
}

pub fn set_folder_appearance(path: &Path, color: Option<&str>, icon: Option<&Path>) -> Result<()>;
pub fn set_permissions(path: &Path, mode: Option<u32>, attrs: Option<FileAttributes>) -> Result<()>;
```

---

### 5. Tools Module (`src/tools.rs`)

**Purpose:** MCP tool definitions and request handlers.

#### Tool State

```rust
pub struct ToolState {
    file_manager: FileManager,
    archive_manager: RwLock<ArchiveManager>,
}
```

#### Tool List (19 tools)

| Tool Name | Category | Description |
|-----------|----------|-------------|
| `ufm_read` | Read | Read file contents (text or base64) |
| `ufm_stat` | Read | Get detailed file metadata |
| `ufm_list` | Read | List directory with filtering/sorting |
| `ufm_exists` | Read | Check if path exists |
| `ufm_search` | Read | Search by glob pattern |
| `ufm_write` | Write | Write content to file |
| `ufm_mkdir` | Write | Create directory |
| `ufm_delete` | Write | Delete file or directory |
| `ufm_rename` | Write | Move or rename |
| `ufm_copy` | Write | Copy file or directory |
| `ufm_set_modified` | Metadata | Set modification time |
| `ufm_set_readonly` | Metadata | Set/clear readonly flag |
| `ufm_set_permissions` | Metadata | Set Unix mode or Windows attrs |
| `ufm_batch_set_modified` | Metadata | Batch modify timestamps |
| `ufm_batch_set_readonly` | Metadata | Batch set readonly |
| `ufm_archive_list` | Archive | List archive contents |
| `ufm_archive_read` | Archive | Read file from archive |
| `ufm_archive_extract` | Archive | Extract to disk |
| `ufm_archive_create` | Archive | Create new archive |

#### Tool Schemas

Each tool needs a JSON schema. Example for `ufm_read`:

```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the file to read"
    },
    "encoding": {
      "type": "string",
      "description": "Text encoding (auto-detected if not specified)"
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
      "description": "Return content as base64"
    }
  },
  "required": ["path"]
}
```

See the `src/tools.rs` file for complete schemas for all 19 tools.

---

### 6. Main Module (`src/main.rs`)

**Purpose:** Entry point, config loading, MCP server setup.

#### Configuration Structure

```rust
struct Config {
    name: String,           // Server name
    version: String,        // Server version
    security: SecurityConfig,
    logging: LoggingConfig,
}

struct SecurityConfig {
    allowed_roots: Vec<PathBuf>,
    denied_paths: Vec<PathBuf>,
    denied_patterns: Vec<String>,
    allow_writes: bool,
    allow_deletes: bool,
    allow_chmod: bool,
    max_read_size: u64,
    max_recursion_depth: u32,
}

struct LoggingConfig {
    level: String,          // error, warn, info, debug, trace
    file: Option<PathBuf>,  // Optional log file
}
```

#### Config File Format (TOML)

```toml
name = "UFM"
version = "0.1.0"

[security]
allowed_roots = ["/home/user/Documents", "/home/user/Projects"]
denied_paths = []
denied_patterns = ["**/node_modules/*"]
allow_writes = true
allow_deletes = true
allow_chmod = true
max_read_size = 104857600
max_recursion_depth = 50

[logging]
level = "info"
```

#### CLI Arguments

```
ufm [OPTIONS]

Options:
  -c, --config <PATH>   Path to configuration file
      --init            Generate default configuration file
  -v, --verbose         Enable verbose logging
  -h, --help            Show help
  -V, --version         Show version
```

#### Config Search Paths

1. Path specified with `--config`
2. `./ufm.toml` (current directory)
3. `~/.config/ufm/config.toml` (XDG config dir)
4. Default (home directory access)

---

## Dependencies

```toml
[dependencies]
# MCP Protocol
mcp-server = "0.2"
mcp-core = "0.2"

# Async runtime
tokio = { version = "1.40", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# File system
walkdir = "2.5"
fs_extra = "1.3"
filetime = "0.2"
same-file = "1.0"

# Archives
zip = "2.1"
flate2 = "1.0"
tar = "0.4"

# Cross-platform
chrono = { version = "0.4", features = ["serde"] }
dirs = "5.0"

# Path handling
glob = "0.3"
regex = "1.10"
normpath = "1.2"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Content detection
infer = "0.16"
encoding_rs = "0.8"

# Config
toml = "0.8"
clap = { version = "4.5", features = ["derive"] }
async-trait = "0.1"
base64 = "0.22"

# Unix-specific
[target.'cfg(unix)'.dependencies]
xattr = "1.3"
nix = { version = "0.29", features = ["fs", "user"] }

# Windows-specific
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Storage_FileSystem",
    "Win32_Foundation",
    "Win32_Security",
]}
```

---

## Build & Distribution

### Build Commands

```bash
# Development
cargo build

# Release (optimized, stripped)
cargo build --release

# Cross-compile for Windows (from Linux)
cargo build --release --target x86_64-pc-windows-gnu

# Cross-compile for Linux (from Windows/WSL)
cargo build --release --target x86_64-unknown-linux-gnu
```

### Release Profile

```toml
[profile.release]
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
strip = true         # Remove symbols
panic = "abort"      # Smaller binary
```

### Claude Desktop Integration

**Linux/Mac** (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ufm": {
      "command": "/usr/local/bin/ufm",
      "args": ["--config", "/home/user/.config/ufm/config.toml"]
    }
  }
}
```

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ufm": {
      "command": "C:\\Program Files\\UFM\\ufm.exe",
      "args": []
    }
  }
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    // Security tests
    #[test] fn test_path_traversal_blocked();
    #[test] fn test_sandbox_enforcement();
    #[test] fn test_denied_patterns();
    
    // Operations tests
    #[test] fn test_read_write_roundtrip();
    #[test] fn test_directory_listing();
    #[test] fn test_file_metadata();
    
    // Archive tests
    #[test] fn test_zip_create_and_read();
    #[test] fn test_virtual_path_parsing();
    #[test] fn test_tar_gz_extraction();
}
```

### Integration Tests

```rust
// tests/integration.rs
#[tokio::test]
async fn test_mcp_tool_calls();

#[tokio::test]
async fn test_batch_operations();

#[tokio::test]
async fn test_archive_virtual_navigation();
```

---

## Future Enhancements (Out of Scope for v0.1)

1. **Remote File Access**
   - Access files on other machines via Tailscale
   - Feature flag: `--features remote`
   - Would require authentication layer

2. **File Watching**
   - `ufm_watch` tool for change notifications
   - Use `notify` crate

3. **Additional Archive Formats**
   - 7z support (requires external library)
   - RAR support (licensing issues)

4. **Content Search**
   - `ufm_grep` for searching file contents
   - Regex support

5. **Checksums**
   - `ufm_checksum` for MD5/SHA256
   - Verification tools

---

## Error Handling Philosophy

1. **Never panic** - All errors returned as `Result<T, Error>`
2. **Descriptive errors** - Include path and operation in error messages
3. **Security errors** - Don't leak information about denied paths
4. **Graceful degradation** - Batch operations continue on individual failures

---

## Summary

UFM provides a comprehensive, secure, cross-platform file management solution for MCP clients. The design prioritizes:

- **Security**: Defense-in-depth with sandboxing, pattern blocking, and traversal protection
- **Usability**: Intuitive tools with sensible defaults
- **Portability**: Single binary works identically on Windows and Linux
- **Extensibility**: Clean module separation allows future enhancements

Claude Code should implement each module in order: security → operations → archive → platform → tools → main.
