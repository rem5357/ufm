# UFM Project Documentation

## Project Overview

**UFM (Universal File Manager)** is a cross-platform MCP (Model Context Protocol) server that provides comprehensive file management capabilities to Claude Desktop and other MCP clients. It enables AI assistants to safely interact with the filesystem through a sandboxed, permission-controlled interface.

### Core Value Proposition

- **Single Binary**: Zero runtime dependencies - just download and run
- **Cross-Platform**: Native support for Windows, Linux, and macOS
- **Security First**: Comprehensive sandboxing with configurable access controls
- **MCP Native**: Purpose-built for the Model Context Protocol
- **Archive Support**: Navigate ZIP/TAR files as virtual filesystems
- **High Performance**: Async I/O, spawn_blocking for heavy operations, optimized for Rust-to-Rust communication

## Project Status

**Version**: 0.11.0
**Build**: 27
**Status**: Active Development

## Development History

### Session 3: Crawl Reliability and Performance (2025-12-11)

#### Problems Encountered

1. **Claude Desktop Lock-ups During Crawl**
   - Issue: When crawling large directories with resume tokens, Claude Desktop would freeze
   - Symptoms: Multiple "Ufm crawl" requests shown, third request had empty body
   - Root cause investigation:
     - Initially suspected synchronous I/O blocking async runtime
     - Actually caused by Claude Desktop's "Exceeded max compactions per block" error
     - Claude Desktop was hitting internal context compaction limits from accumulated crawl data

2. **Position-Based Resume Token Fragility**
   - Old implementation used integer position in WalkDir iterator
   - Problem: Filesystem changes between crawls could cause position mismatch
   - WalkDir doesn't guarantee consistent ordering across runs

3. **Synchronous I/O Blocking Async Runtime**
   - `stdin.lock().lines()` was blocking the entire tokio runtime
   - Tool calls using WalkDir (synchronous) could block other operations

#### Solutions Implemented

1. **Async I/O for MCP Server** (`mcp.rs`)
   - Replaced synchronous `stdin.lock().lines()` with `tokio::io::BufReader` + async `read_line`
   - Added 5-minute timeout on stdin reads to prevent indefinite blocking
   - Added 60-second timeout on tool calls to prevent hanging tools
   - Proper EOF handling with graceful shutdown

2. **Spawn Blocking for Crawl Operations** (`tools.rs`)
   - Moved synchronous WalkDir crawl to `tokio::task::spawn_blocking`
   - Prevents crawl from blocking the async runtime
   - Other MCP requests can still be processed during long crawls

3. **Path-Based Resume Token** (`crawler.rs`)
   - New `ResumeToken` structure:
     ```rust
     struct ResumeToken {
         last_path: PathBuf,    // Last processed path
         root: PathBuf,         // Root directory for validation
         pattern_hash: u64,     // Detect skip pattern changes
         version: u8,           // Future compatibility
     }
     ```
   - Uses `sort_by_file_name()` for consistent ordering across runs
   - Validates token matches current crawl root and options
   - Gracefully handles stale tokens (deleted files)

4. **Optimized CrawlEntry Format** (`crawler.rs`)
   - Full metadata for Rust-to-Rust communication:
     ```rust
     struct CrawlEntry {
         path: PathBuf,           // Relative to root
         name: String,
         extension: Option<String>,
         size: u64,
         modified: i64,
         created: Option<i64>,    // Skipped if None
         is_dir: bool,
         is_hidden: bool,         // Skipped if false
         is_symlink: bool,        // Skipped if false
         mode: Option<u32>,       // Unix permissions
     }
     ```
   - Paths are relative to crawl root (saves bytes, cleaner output)
   - Optional fields use `skip_serializing_if` to reduce JSON size
   - `CrawlEntryMinimal` available for low-bandwidth scenarios

5. **File Logging Support** (`main.rs`)
   - Config option `logging.file` to write logs to file
   - Useful for debugging when running under Claude Desktop
   - Logs to both stderr and file when configured

6. **Defensive Argument Handling** (`tools.rs`)
   - Added check for empty/null arguments in `handle_crawl`
   - Returns clear error instead of potentially panicking

#### Lessons Learned

1. **Claude Desktop Context Limits**
   - Claude Desktop has internal limits on conversation compaction
   - Large tool responses accumulated across many calls can trigger "Exceeded max compactions per block"
   - This is a client-side limitation, not a server bug
   - For heavy operations, use dedicated Rust clients instead of Claude Desktop

2. **Async/Sync Boundary Management**
   - Synchronous filesystem operations (WalkDir) should use `spawn_blocking`
   - Don't mix blocking I/O with async runtime on main thread
   - Timeouts are essential for robustness

3. **Resume Token Design**
   - Path-based is more robust than position-based
   - Include validation data (root, options hash) in token
   - Handle gracefully when resume point is stale

### Session 2: Version Bump and Crawler Tools (2025-12-10)

- Bumped version to 0.11.0
- Added `ufm_crawl` tool for batched directory traversal
- Added `ufm_dir_check` tool for change detection
- Added `ufm_hash` tool for file hashing (xxHash, SHA256)
- Implemented resume token system for large crawls

### Session 1: Initial Setup and Build Issues (2025-12-09)

#### Problems Encountered

1. **Build System Lockup**
   - Cargo build process was hanging/locking up
   - Root cause: Stale incremental compilation artifacts and lock files in `target/` directory
   - Solution: `cargo clean` removed 5,868 files (2.7GB) of corrupted build state

2. **Clap Version Attribute Error**
   - Error: `#[command(version = full_version())]` failed because clap expected `&'static str`, not `String`
   - Solution: Changed to `#[command(version = env!("CARGO_PKG_VERSION"))]` using compile-time constant

3. **Build Script Configuration**
   - Build script (`build.rs`) reads from `BUILD` file to inject build number
   - Sets `UFM_BUILD_NUMBER` environment variable for compilation

## Architecture

### Module Structure

```
src/
├── main.rs          - CLI entry point, config loading, server initialization
├── lib.rs           - Library exports
├── mcp.rs           - MCP protocol implementation (async JSON-RPC over stdio)
├── tools.rs         - MCP tool definitions and handlers
├── operations.rs    - Core file operations (read, write, delete, etc.)
├── security.rs      - Path sandboxing and access control
├── platform.rs      - OS-specific functionality (permissions, xattrs, etc.)
├── archive.rs       - ZIP/TAR archive handling
└── crawler.rs       - Directory crawling with batching and resume support
```

### Key Design Decisions

1. **Direct MCP Implementation**
   - Implemented MCP protocol directly due to rapid API changes in SDK
   - Full control over protocol implementation
   - Async I/O with tokio for non-blocking operation

2. **Async Runtime**
   - Tokio with full features enabled
   - Async stdin/stdout for MCP communication
   - `spawn_blocking` for synchronous filesystem operations

3. **Security Model**
   - Multi-layered: sandboxing + pattern blocking + operation controls
   - Default-deny approach for sensitive paths
   - Configurable per-installation

4. **Crawl Architecture**
   - Batched results with resume tokens for large directories
   - Path-based resumption for robustness
   - Relative paths in output to reduce response size
   - Full metadata by default for Rust-to-Rust communication

## Current Features

### Implemented Tools

- **Read Operations**: `ufm_read`, `ufm_stat`, `ufm_list`, `ufm_exists`, `ufm_search`
- **Write Operations**: `ufm_write`, `ufm_mkdir`, `ufm_delete`, `ufm_rename`, `ufm_copy`
- **Metadata Operations**: `ufm_set_modified`, `ufm_set_readonly`, `ufm_set_permissions` (+ batch variants)
- **Archive Operations**: `ufm_archive_list`, `ufm_archive_read`, `ufm_archive_extract`, `ufm_archive_create`
- **Crawler Operations**: `ufm_crawl`, `ufm_dir_check`, `ufm_hash`

### Crawler Tools

#### `ufm_crawl`
Crawl directory tree returning file metadata in batches.

Parameters:
- `root` (required): Root directory to crawl
- `batch_size` (default 500): Entries per batch (10-2000)
- `resume_token`: Token from previous incomplete crawl
- `include_hidden` (default false): Include hidden files
- `skip_patterns`: Glob patterns to skip (e.g., `**/node_modules/*`)
- `max_depth`: Maximum directory depth
- `dirs_only` (default false): Return only directories

Response includes:
- `root`: Absolute path of crawl root
- `entries`: Array of file/directory entries (paths relative to root)
- `resume_token`: Token to continue if not complete
- `progress`: Statistics (files_scanned, dirs_scanned, bytes_total)
- `complete`: Boolean indicating if crawl finished
- `directories_seen`: Directory metadata for change detection
- `errors`: Non-fatal errors encountered

#### `ufm_dir_check`
Quick check if directories have changed since last crawl without reading all files.

#### `ufm_hash`
Compute file hashes for duplicate detection (xxHash for speed, SHA256 for cryptographic use).

### Platform-Specific Features

- **Unix**: xattrs, chmod/chown, symbolic link handling
- **Windows**: File attributes (hidden, system, archive), ACL support (partial)
- **Cross-platform**: Folder colors/icons (macOS/Linux/Windows)

## Configuration

### Config File Locations

1. `./ufm.toml` (current directory)
2. `~/.config/ufm/config.toml`
3. Custom path via `--config` flag

### Example Configuration

```toml
name = "UFM"
version = "0.11.0"

[security]
allowed_roots = []  # Empty = user's home directory
denied_paths = []
denied_patterns = ["**/.git/*", "**/node_modules/*"]
allow_writes = true
allow_deletes = true
allow_chmod = true
max_read_size = 104857600  # 100MB
max_recursion_depth = 50

[logging]
level = "info"  # error, warn, info, debug, trace
# file = "/tmp/ufm.log"  # Uncomment to log to file
```

### Debug Configuration

For debugging, use `ufm.debug.toml`:
```toml
[logging]
level = "debug"
file = "/tmp/ufm.log"
```

Run with: `ufm --config ufm.debug.toml`

## Known Issues and Technical Debt

### Claude Desktop Limitations

- "Exceeded max compactions per block" error when accumulating large responses
- Workaround: Use smaller batch sizes or dedicated Rust clients for heavy crawls
- Not a UFM bug - Claude Desktop context management limitation

### Compiler Warnings

- Unused imports in operations.rs
- Feature flag mismatch for xattr (should be cfg(unix))
- Dead code from partial implementations
- These don't affect functionality, cleanup planned for 1.0

## Future Enhancements

### High Priority

- [ ] Binary serialization support (bincode/MessagePack) for Rust-to-Rust
- [ ] Streaming output mode for real-time results
- [ ] Compression options (lz4/zstd) for data streams
- [ ] USM client/server architecture integration

### Medium Priority

- [ ] Test suite improvements
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Performance benchmarks
- [ ] Plugin system for custom tools

### Low Priority

- [ ] Remote file access (WebDAV, SFTP)
- [ ] File watching capabilities
- [ ] Trash/recycle bin support
- [ ] Thumbnail generation

## Build and Version Management

### Current System

- **Version**: Managed in Cargo.toml (0.11.0)
- **Build Number**: Stored in `BUILD` file (currently: 27)
- **Build Script**: `build.rs` reads BUILD file and sets `UFM_BUILD_NUMBER` env var
- **Display**: `full_version()` returns "0.11.0 (build 27)"

### Building

```bash
cargo build --release
```

Binary location: `target/release/ufm`

### Testing

```bash
cargo test
```

## Security Considerations

### Current Protections

- Path normalization prevents `..` traversal
- Glob pattern blocking for sensitive files
- Configurable root directory sandboxing
- Per-operation permission flags
- Size limits to prevent DoS
- Timeout protection on all operations

### Future Security Work

- [ ] Audit logging for all file operations
- [ ] Rate limiting per tool
- [ ] Cryptographic verification of archives

## License

MIT License - See LICENSE file for details

---

**Last Updated**: 2025-12-11
**Maintainer**: Robert
**Repository**: https://github.com/rem5357/ufm
