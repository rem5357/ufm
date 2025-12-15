# UFM Project Documentation

## Project Overview

**UFM (Universal File Manager)** is a cross-platform MCP (Model Context Protocol) server that provides comprehensive file management capabilities to Claude Desktop and other MCP clients. It enables AI assistants to safely interact with the filesystem through a sandboxed, permission-controlled interface.

### Core Value Proposition

- **Single Binary**: Zero runtime dependencies - just download and run
- **Cross-Platform**: Native support for Windows, Linux, and macOS
- **Security First**: Comprehensive sandboxing with configurable access controls
- **MCP Native**: Purpose-built for the Model Context Protocol
- **P2P Networking**: Seamless file operations across machines via zero-config mDNS discovery
- **Archive Support**: Navigate ZIP/TAR files as virtual filesystems
- **Auto-Update**: Self-updating with crash recovery and systemd integration

## Project Status

**Version**: 0.50.0
**Build**: 145
**Status**: Active Development
**Last Updated**: 2025-12-15

### Current Nodes
- **Goldshire** (Linux): 192.168.86.112:9847 - Home server daemon
- **Falcon** (Windows): Claude Desktop MCP client

---

## Development History

### Session 7: Streaming Transfers (2025-12-15)

#### Summary
Implemented streaming pull transfers for files and directories. Eliminates base64 memory bloat - large files now stream in 64KB chunks with constant memory usage.

#### What Was Accomplished

1. **Streaming File Pull**
   - New `StreamPullRequest` message type
   - Remote streams file via `StreamStart` → `StreamData` chunks → `StreamEnd`
   - Client receives and writes chunks directly to disk
   - Memory usage: ~64KB constant (vs 1.33x file size for base64)

2. **Directory Streaming with Tar**
   - New `StreamPullDirectoryRequest` message type
   - Remote builds tar archive, compresses with zstd, streams chunks
   - Client receives tar, decompresses, extracts to destination
   - `ufm_transfer` now accepts `recursive: true` for directories

3. **Protocol Changes**
   - Added `StreamPullRequest { transfer_id, path, compression }`
   - Added `StreamPullDirectoryRequest { transfer_id, path, compression }`

4. **New PeerManager Methods**
   - `pull_file_from_peer()` - streaming file download
   - `pull_directory_from_peer()` - streaming directory download as tar

#### Test Results
- File pull: 278 MB (Songs1.zip) streamed successfully
- Directory pull: 321 MB (Songs1 folder) as compressed tar, extracted on Falcon

#### Build History
- Build 145: Streaming pull transfers for files and directories

---

### Session 6: Service Management & CLI Commands (2025-12-14, continued)

#### What Was Accomplished

1. **Systemd Service Improvements**
   - Enhanced crash recovery with `Restart=on-failure` and backoff (5s to 60s)
   - Added `StartLimitIntervalSec=60` and `StartLimitBurst=5` to prevent rapid restart loops
   - Security hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`

2. **New CLI Commands**
   - `ufm --restart` - Restart the UFM systemd service
   - `ufm --stop` - Stop the UFM systemd service
   - `ufm --status` - Show service status
   - Works from anywhere (uses systemctl)

#### Build History
- Build 139: Service management CLI commands

---

### Session 5: mDNS Zero-Config Discovery (2025-12-14)

#### Summary
Implemented full zero-config peer discovery via mDNS/DNS-SD on both Linux and Windows. Bootstrap nodes are now optional - UFM nodes automatically discover each other on the local network.

#### What Was Accomplished

1. **Linux mDNS Registration Fix (Build 126)**
   - **Bug**: UFM logged "mDNS service registered" but service wasn't visible via `avahi-browse`
   - **Root Cause**: The `mdns_sd` crate creates its own mDNS socket which conflicts with avahi-daemon (already bound to UDP port 5353)
   - **Fix**: On Linux, spawn `avahi-publish` subprocess for service registration
     - Added `#[cfg(target_os = "linux")] avahi_process: Option<std::process::Child>` field
     - Fallback to mdns_sd if avahi-publish not available
     - Keep mdns_sd for browsing

2. **Windows mDNS Registration (Build 131)**
   - Uses `dns-sd -R` (Bonjour) for service registration
   - Added `#[cfg(target_os = "windows")] dnssd_process: Option<std::process::Child>`
   - Uses `CREATE_NO_WINDOW` flag (0x08000000) to prevent console popups

3. **Windows mDNS Browsing (Build 133)**
   - **Problem**: mdns_sd crate couldn't browse when Bonjour service is running
   - **Fix**: Implemented native dns-sd browsing:
     - `discover_dnssd_browse()` - spawns `dns-sd -B _ufm._tcp local` to find services
     - `lookup_dnssd_service()` - spawns `dns-sd -L <name> _ufm._tcp local` to get details
     - Parses hostname, port, TXT records (uuid, version, os)
     - Resolves hostname to IP addresses using `ToSocketAddrs`

4. **Config Updates (Build 134)**
   - Bootstrap nodes now documented as optional
   - `NetworkConfig::desktop()` and `laptop()` take `Option<SocketAddr>` instead of requiring bootstrap

#### Lessons Learned

1. **Native mDNS Services Conflict with Rust Crates**
   - Both avahi-daemon (Linux) and Bonjour (Windows) bind to UDP port 5353
   - Rust crates like `mdns_sd` create their own sockets, causing conflicts
   - Solution: Use native tools (`avahi-publish`, `dns-sd`) via subprocess for registration
   - Browsing can sometimes work with the crate, but native tools are more reliable

2. **Platform-Specific Compilation**
   - Use `#[cfg(target_os = "linux")]` and `#[cfg(target_os = "windows")]` for platform code
   - Windows process creation needs `CREATE_NO_WINDOW` flag to avoid popup windows
   - Use `tokio::task::spawn_blocking` for synchronous DNS operations in async context

3. **dns-sd Command Output Parsing**
   - Browse format: `"Timestamp A/R Flags if Domain Service_Type Instance_Name"`
   - Lookup format: Multi-line with hostname info and TXT records
   - Must handle `.local` suffix in hostnames

#### Build History
- Build 118: Added mDNS debug logging
- Build 126: avahi-publish integration for Linux
- Build 131: Windows dns-sd registration
- Build 133: Windows dns-sd browsing
- Build 134: Config cleanup, bootstrap now optional

---

### Session 4: P2P Networking & Transfer Debugging (2025-12-13)

#### Summary
Debugged and fixed multiple issues with P2P networking between UFM nodes. Successfully implemented remote archive creation and improved transfer functionality.

#### What Was Accomplished

1. **Remote Archive Creation (Build 106)**
   - Added `node` parameter to all archive tools
   - Added `maybe_route_remote()` calls to archive handlers
   - Can now create zip files on remote nodes via MCP tools

2. **Transfer Pull Fix (Build 109)**
   - **Bug**: Pull transfers returned "Node not found: id 1"
   - **Cause**: `handle_transfer` was including `"node": args["source_node"]` in remote_args
   - **Fix**: Removed node parameter from remote_args

3. **Security Path Normalization (Build 112)**
   - **Bug**: Windows paths rejected as "outside allowed roots" due to format differences
   - **Fix**: Added `normalize_root()` and case-insensitive comparison on Windows

4. **Status Endpoint Improvements (Build 115)**
   - Added `username`, `home_dir`, `downloads_dir` to `ufm_status` response
   - Clients can query paths instead of guessing

#### Lessons Learned

1. **Node parameter stripping**: When routing to remote nodes, strip the `node` parameter to prevent routing loops
2. **Path normalization is critical**: Both checked path AND allowed roots must be normalized
3. **Don't assume usernames**: Expose paths via status/info endpoints
4. **Bincode + serde_json::Value don't mix**: Use `params_json: String` and serialize JSON separately

#### Build History
- Build 106: Remote archive tools with node parameter
- Build 109: Transfer pull node routing fix
- Build 112: Security path normalization
- Build 115: Status endpoint with username/home_dir/downloads_dir

---

### Session 3: P2P Networking and Auto-Update System (2025-12-12)

#### Major Features Implemented

1. **P2P Networking Infrastructure**
   - mDNS service discovery for local network peer detection
   - Node identity system with UUID and human-readable names
   - Peer connection management with handshake protocol
   - Binary message protocol with compression support (gzip, zstd)
   - Transfer manager for file streaming between nodes

2. **Auto-Update System**
   - Automatic update checking on startup
   - Periodic background update checks (hourly check, daily download)
   - Platform-specific binary downloads (Windows `.exe`, Linux binary)
   - SHA256 checksum verification before applying updates
   - Atomic binary replacement with backup creation

3. **Daemon Mode**
   - `--daemon` flag for headless server operation
   - Runs P2P network only (no MCP server)
   - Auto-applies updates and restarts via systemd

#### Critical Problems Solved

1. **exec() Runs Old Binary from Memory Cache**
   - Linux caches running executables in memory even after file replacement
   - Solution: Exit and let systemd restart the service

2. **Infinite Update Loop**
   - Build number is compiled into binary; replaced binary reports old build number
   - Solution: Checksum-based update detection instead of build number comparison

#### Lessons Learned

1. **Linux Executable Memory Caching**: Cannot use `exec()` to reload replaced binary - must fully exit
2. **Build Numbers vs Checksums**: Checksums are authoritative for update detection
3. **systemd Integration**: `Restart=always` with `RestartSec=N` is ideal for self-updating daemons

---

### Session 2: Crawl Reliability and Performance (2025-12-11)

#### Problems Solved

1. **Claude Desktop Lock-ups During Crawl**
   - Caused by "Exceeded max compactions per block" error
   - Solution: Use smaller batch sizes or dedicated Rust clients

2. **Position-Based Resume Token Fragility**
   - Solution: Path-based resume tokens with validation

3. **Synchronous I/O Blocking Async Runtime**
   - Solution: Async I/O for MCP server, `spawn_blocking` for crawl operations

---

### Session 1: Initial Setup and Build Issues (2025-12-09 - 2025-12-10)

- Initial project setup
- Build system configuration with BUILD file for version tracking
- Added crawler tools: `ufm_crawl`, `ufm_dir_check`, `ufm_hash`

---

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
├── crawler.rs       - Directory crawling with batching and resume support
├── update.rs        - Auto-update system
└── network/
    ├── mod.rs       - Network module exports
    ├── config.rs    - Network configuration
    ├── discovery.rs - mDNS/DNS-SD peer discovery
    ├── identity.rs  - Node identity management
    ├── peer.rs      - Peer connection management
    ├── protocol.rs  - Binary message protocol
    ├── router.rs    - Request routing
    └── transfer.rs  - File transfer management
```

### Key Design Decisions

1. **Direct MCP Implementation** - Full control over protocol, async I/O with tokio
2. **Platform-Native mDNS** - Use OS tools (avahi-publish, dns-sd) instead of pure Rust for reliability
3. **Checksum-Based Updates** - More reliable than build number comparison
4. **Security Model** - Multi-layered: sandboxing + pattern blocking + operation controls

---

## Current Features

### Implemented Tools

- **Read Operations**: `ufm_read`, `ufm_stat`, `ufm_list`, `ufm_exists`, `ufm_search`
- **Write Operations**: `ufm_write`, `ufm_mkdir`, `ufm_delete`, `ufm_rename`, `ufm_copy`
- **Metadata Operations**: `ufm_set_modified`, `ufm_set_readonly`, `ufm_set_permissions`
- **Archive Operations**: `ufm_archive_list`, `ufm_archive_read`, `ufm_archive_extract`, `ufm_archive_create`
- **Crawler Operations**: `ufm_crawl`, `ufm_dir_check`, `ufm_hash`
- **Network Operations**: `ufm_status`, `ufm_discover`, `ufm_transfer`

### CLI Commands

```bash
ufm                    # Start MCP server (default)
ufm --daemon           # Run as P2P daemon only
ufm --network          # Enable P2P networking
ufm --config path.toml # Use custom config
ufm --init             # Generate default config
ufm --check-update     # Check for updates
ufm --update           # Download and apply update
ufm --restart          # Restart systemd service (Linux)
ufm --stop             # Stop systemd service (Linux)
ufm --status           # Show service status (Linux)
```

---

## Outstanding TODOs

### High Priority
- [x] **Pull transfers still use base64**: ~~Should implement streaming pull like push~~ DONE (build 145) - streaming pull for files and directories

### Medium Priority
- [ ] **Remote-to-remote transfers**: Currently returns "not yet implemented"
- [ ] **Transfer progress/status**: `handle_transfer_status` is a placeholder
- [ ] **Security config UX**: Users must manually edit config.toml to add paths

### Low Priority
- [ ] Clean up unused code warnings (67 warnings in build)
- [ ] `TransferManager` methods are implemented but unused (streaming uses `stream_file_to_peer` directly)
- [ ] Test auto-update on Windows (helper script approach)

---

## Configuration

### Config File Locations

1. `./ufm.toml` (current directory)
2. `~/.config/ufm/config.toml`
3. Custom path via `--config` flag

### Example Configuration

```toml
name = "UFM"
version = "0.50.0"

[security]
allowed_roots = []  # Empty = user's home directory
denied_paths = []
denied_patterns = ["**/.git/*", "**/node_modules/*"]
allow_writes = true
allow_deletes = true

[network]
bootstrap_nodes = []  # Optional - mDNS provides zero-config discovery

[logging]
level = "info"
```

---

## Deployment

### Update Server Structure

The update server (`http://goldshire:8080/ufm/`) hosts:
- `version.json` - Version metadata with checksums
- `ufm.exe` - Windows binary
- `ufm-linux-x86_64` - Linux binary

### Build and Deploy

```bash
./dist/build-release.sh  # Build both platforms, update checksums
cp dist/release/* /var/www/ufm/  # Deploy to web server
```

### Systemd Service

```bash
sudo cp dist/ufm.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ufm
sudo systemctl start ufm
```

---

## License

MIT License - See LICENSE file for details

---

**Maintainer**: Robert
**Repository**: https://github.com/rem5357/ufm
