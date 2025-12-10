# UFM - Universal File Manager

A cross-platform MCP (Model Context Protocol) server for comprehensive file management. UFM provides Claude Desktop and other MCP clients with the ability to read, write, search, and manage files on your computer.

## Features

- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Single Binary**: No runtime dependencies - just download and run
- **Security First**: Sandboxed file access with configurable allowed directories
- **Archive Support**: Navigate ZIP and TAR files as if they were directories
- **Batch Operations**: Modify timestamps and permissions on multiple files at once
- **MCP Native**: Designed specifically for Claude Desktop and MCP clients

## Installation

### From Releases

Download the latest release for your platform from the releases page.

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/ufm.git
cd ufm

# Build for release
cargo build --release

# The binary will be at target/release/ufm (or ufm.exe on Windows)
```

### Cross-Compilation

```bash
# For Windows (from Linux)
cargo build --release --target x86_64-pc-windows-gnu

# For Linux (from Windows with WSL)
cargo build --release --target x86_64-unknown-linux-gnu
```

## Configuration

### Generate Default Config

```bash
ufm --init
```

This creates `ufm.toml` with default settings.

### Configuration Options

```toml
# Server identification
name = "UFM"
version = "0.1.0"

[security]
# Directories UFM is allowed to access (empty = home directory)
allowed_roots = [
    "/home/user/Documents",
    "/home/user/Projects"
]

# Paths that are always blocked
denied_paths = []

# Glob patterns for files to block
denied_patterns = [
    "**/.env",
    "**/*.key",
    "**/secrets/*"
]

# Permission controls
allow_writes = true
allow_deletes = true
allow_chmod = true

# Limits
max_read_size = 104857600  # 100MB
max_recursion_depth = 50

[logging]
level = "info"  # error, warn, info, debug, trace
# file = "/var/log/ufm.log"  # Optional log file
```

## Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ufm": {
      "command": "/path/to/ufm",
      "args": ["--config", "/path/to/ufm.toml"]
    }
  }
}
```

### Windows

```json
{
  "mcpServers": {
    "ufm": {
      "command": "C:\\Users\\YourName\\tools\\ufm.exe",
      "args": []
    }
  }
}
```

## Available Tools

### Read Operations

| Tool | Description |
|------|-------------|
| `ufm_read` | Read file contents (text or base64) |
| `ufm_stat` | Get detailed file metadata |
| `ufm_list` | List directory contents with filtering |
| `ufm_exists` | Check if a path exists |
| `ufm_search` | Search for files by glob pattern |

### Write Operations

| Tool | Description |
|------|-------------|
| `ufm_write` | Write content to a file |
| `ufm_mkdir` | Create directories |
| `ufm_delete` | Delete files or directories |
| `ufm_rename` | Move or rename files |
| `ufm_copy` | Copy files or directories |

### Metadata Operations

| Tool | Description |
|------|-------------|
| `ufm_set_modified` | Change file modification time |
| `ufm_set_readonly` | Set/clear readonly flag |
| `ufm_set_permissions` | Set Unix mode or Windows attributes |
| `ufm_batch_set_modified` | Batch modify timestamps |
| `ufm_batch_set_readonly` | Batch set readonly flag |

### Archive Operations

| Tool | Description |
|------|-------------|
| `ufm_archive_list` | List archive contents |
| `ufm_archive_read` | Read file from archive |
| `ufm_archive_extract` | Extract file to disk |
| `ufm_archive_create` | Create new archive |

## Usage Examples

### Reading Files

```
"Read the contents of /home/user/notes.txt"
→ Uses ufm_read

"Show me the metadata for document.pdf"
→ Uses ufm_stat
```

### Working with Archives

```
"List what's inside backup.zip"
→ Uses ufm_archive_list

"Read the README from project.tar.gz"
→ Uses ufm_archive_read with internal_path
```

### Batch Operations

```
"Set all .log files in /var/log to readonly"
→ Uses ufm_search + ufm_batch_set_readonly

"Backdate all files in the release folder to January 1st"
→ Uses ufm_search + ufm_batch_set_modified
```

## Security Model

UFM implements defense-in-depth security:

1. **Sandboxing**: Only configured directories are accessible
2. **Path Traversal Protection**: `..` attacks are blocked
3. **Sensitive File Blocking**: Default patterns block `.env`, SSH keys, etc.
4. **Operation Controls**: Writes, deletes, and chmod can be independently disabled
5. **Size Limits**: Prevents memory exhaustion from large files

### Default Blocked Patterns

- `/etc/shadow`, `/etc/passwd`, `/etc/sudoers*`
- `**/.ssh/id_*`, `**/.gnupg/*`
- `**/.env`, `**/.env.*`
- `**/*.pem`, `**/*.key`
- `**/credentials*`, `**/secrets*`

## Building for Distribution

### Windows Installer

```bash
cargo install cargo-wix
cargo wix init
cargo wix
```

### Linux Packages

```bash
cargo install cargo-deb
cargo deb
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md first.
