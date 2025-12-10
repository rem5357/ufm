# UFM Project Documentation

## Project Overview

**UFM (Universal File Manager)** is a cross-platform MCP (Model Context Protocol) server that provides comprehensive file management capabilities to Claude Desktop and other MCP clients. It enables AI assistants to safely interact with the filesystem through a sandboxed, permission-controlled interface.

### Core Value Proposition

- **Single Binary**: Zero runtime dependencies - just download and run
- **Cross-Platform**: Native support for Windows, Linux, and macOS
- **Security First**: Comprehensive sandboxing with configurable access controls
- **MCP Native**: Purpose-built for the Model Context Protocol
- **Archive Support**: Navigate ZIP/TAR files as virtual filesystems

## Project Status

**Version**: 0.1.0
**Build**: 1
**Status**: Active Development

## Development History

### Session 1: Initial Setup and Build Issues (2025-12-09)

#### Problems Encountered

1. **Build System Lockup**
   - Cargo build process was hanging/locking up
   - Root cause: Stale incremental compilation artifacts and lock files in `target/` directory
   - Solution: `cargo clean` removed 5,868 files (2.7GB) of corrupted build state

2. **Clap Version Attribute Error**
   - Error: `#[command(version = full_version())]` failed because clap expected `&'static str`, not `String`
   - The `full_version()` function returned a dynamically generated `String` with build number
   - Initial attempt to use `#[command(long_version = full_version())]` failed with same error
   - Solution: Changed to `#[command(version = env!("CARGO_PKG_VERSION"))]` using compile-time constant
   - The `full_version()` function is still used in logging at runtime

3. **Build Script Configuration**
   - Build script (`build.rs`) reads from `BUILD` file to inject build number
   - Sets `UFM_BUILD_NUMBER` environment variable for compilation
   - Properly configured with `cargo:rerun-if-changed=BUILD`

#### Lessons Learned

1. **Cargo Incremental Compilation Can Corrupt**
   - When builds lock up or behave strangely, `cargo clean` should be the first troubleshooting step
   - Lock files in `target/debug/incremental/` can persist and cause issues
   - Consider adding `cargo clean` to CI/CD pipelines between major changes

2. **Clap Macro Limitations**
   - Clap's derive macros require compile-time constants for attributes
   - Runtime string generation must happen outside the derive macro
   - Alternative: Override version in `Command::new()` instead of derive macro
   - Future consideration: Use `const_format` crate for compile-time string concatenation

3. **Build Script Best Practices**
   - The `build.rs` pattern for version management works well
   - Need to add auto-increment logic to prevent manual updates
   - Should integrate with git hooks for automatic bumping

4. **Compiler Warnings Are Valuable**
   - 36 warnings generated (unused imports, dead code, etc.)
   - These indicate incomplete implementation but not broken code
   - Should be addressed before 1.0 release but safe to ignore during development

## Architecture

### Module Structure

```
src/
├── main.rs          - CLI entry point, config loading, server initialization
├── lib.rs           - Library exports
├── mcp.rs           - MCP protocol implementation (JSON-RPC over stdio)
├── tools.rs         - MCP tool definitions and handlers
├── operations.rs    - Core file operations (read, write, delete, etc.)
├── security.rs      - Path sandboxing and access control
├── platform.rs      - OS-specific functionality (permissions, xattrs, etc.)
├── archive.rs       - ZIP/TAR archive handling
└── crawler.rs       - File search and traversal
```

### Key Design Decisions

1. **Direct MCP Implementation**
   - Initially considered using `rust-mcp-sdk`
   - Decision: Implement MCP protocol directly due to rapid API changes in SDK
   - Benefit: Full control over protocol implementation

2. **Async Runtime**
   - Tokio with full features enabled
   - Async operations for future remote file access support

3. **Security Model**
   - Multi-layered: sandboxing + pattern blocking + operation controls
   - Default-deny approach for sensitive paths
   - Configurable per-installation

## Current Features

### Implemented Tools

- **Read Operations**: read, stat, list, exists, search
- **Write Operations**: write, mkdir, delete, rename, copy
- **Metadata Operations**: set_modified, set_readonly, set_permissions (+ batch variants)
- **Archive Operations**: archive_list, archive_read, archive_extract, archive_create

### Platform-Specific Features

- **Unix**: xattrs, chmod/chown, symbolic link handling
- **Windows**: File attributes (hidden, system, archive), ACL support (partial)
- **Cross-platform**: Folder colors/icons (macOS/Linux/Windows)

## Known Issues and Technical Debt

### Compiler Warnings (36 total)

1. **Unused Imports** (src/operations.rs:6)
   - `BufReader` and `BufWriter` imported but not used
   - Quick fix: Remove or add `#[allow(unused_imports)]`

2. **Feature Flag Mismatch** (src/platform.rs)
   - 5 warnings about `feature = "xattr"` not existing in Cargo.toml
   - Current: xattr is a target-specific dependency
   - Fix needed: Add `xattr` feature flag to Cargo.toml or change code to use `#[cfg(unix)]`

3. **Dead Code** (multiple files)
   - Archive manager cache never used
   - Several error variants never constructed
   - Platform-specific functions implemented but not exposed to MCP tools
   - Action: Either use the code or remove it before 1.0

4. **Unused Variables**
   - `icon` parameter in `set_folder_appearance` (intentional, partial implementation)

## TODO List

### High Priority

- [ ] Implement automatic build number increment on each build
- [ ] Update console startup to display "UFM v0.1.0 (build 1)"
- [ ] Set up GitHub repository and push initial code
- [ ] Add .gitignore for Rust projects
- [ ] Create initial git commit with proper message

### Medium Priority

- [ ] Fix xattr feature flag warnings (add to Cargo.toml or change cfg)
- [ ] Remove unused imports from operations.rs
- [ ] Decide on archive cache: implement or remove
- [ ] Test suite for core operations
- [ ] Integration tests for MCP protocol
- [ ] CI/CD pipeline (GitHub Actions)

### Low Priority

- [ ] Implement Windows icon setting in `set_folder_appearance`
- [ ] Add more archive formats (7z, rar - if licenses permit)
- [ ] Remote file access feature (WebDAV, SFTP)
- [ ] File watching capabilities
- [ ] Trash/recycle bin support instead of permanent delete
- [ ] Documentation improvements
- [ ] Performance benchmarks
- [ ] Add `--version` flag handler that shows build number

### Future Enhancements

- [ ] Plugin system for custom tools
- [ ] File content indexing for fast search
- [ ] Thumbnail generation for images
- [ ] File type detection improvements
- [ ] Compression level options for archives
- [ ] Progress callbacks for long operations
- [ ] Atomic file operations
- [ ] Transaction support (rollback on failure)

## Build and Version Management

### Current System

- **Version**: Managed in Cargo.toml (0.1.0)
- **Build Number**: Stored in `BUILD` file (currently: 1)
- **Build Script**: `build.rs` reads BUILD file and sets `UFM_BUILD_NUMBER` env var
- **Display**: `full_version()` returns "0.1.0 (build 1)"

### Planned Improvements

1. Auto-increment BUILD file on each successful compilation
2. Git hooks to bump build on commit
3. Semantic versioning automation
4. Release tagging integration

## Security Considerations

### Current Protections

- Path normalization prevents `..` traversal
- Glob pattern blocking for sensitive files
- Configurable root directory sandboxing
- Per-operation permission flags
- Size limits to prevent DoS

### Future Security Work

- [ ] Audit logging for all file operations
- [ ] Rate limiting per tool
- [ ] Cryptographic verification of archives
- [ ] Filesystem encryption integration
- [ ] Security policy templates for different use cases

## Contributing Guidelines

### Code Style

- Follow Rust standard conventions (rustfmt)
- Run `cargo clippy` before committing
- Document public APIs with doc comments
- Keep functions focused and small

### Pull Request Process

1. Create feature branch from main
2. Implement changes with tests
3. Update documentation
4. Run full test suite
5. Submit PR with clear description

### Testing Requirements

- Unit tests for all public functions
- Integration tests for MCP tools
- Platform-specific tests must pass on target OS
- No compiler warnings in release builds

## License

MIT License - See LICENSE file for details

---

**Last Updated**: 2025-12-09
**Maintainer**: Robert
**Repository**: https://github.com/rem5357/ufm
