# UFM Design Addendum - Crawler Support for USM

**Date:** December 2024  
**Related To:** USM (Universal Search Manager) Integration

---

## Overview

This addendum extends UFM with tools optimized for bulk metadata extraction, enabling efficient indexing by USM and similar applications.

---

## New Tools (3 additions)

### 1. `ufm_crawl` - Streaming Metadata Extraction

**Purpose:** Efficiently extract metadata from large directory trees in batches, optimized for database ingestion.

#### Schema

```json
{
  "type": "object",
  "properties": {
    "root": {
      "type": "string",
      "description": "Root directory to crawl"
    },
    "batch_size": {
      "type": "integer",
      "default": 1000,
      "description": "Number of entries per batch (100-10000)"
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
      "default": [],
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
}
```

#### Response

```json
{
  "entries": [
    {
      "path": "/home/user/documents/report.pdf",
      "parent": "/home/user/documents",
      "name": "report.pdf",
      "stem": "report",
      "extension": "pdf",
      "size": 1048576,
      "modified": 1702300800,
      "created": 1702200000,
      "is_dir": false,
      "is_hidden": false,
      "is_symlink": false,
      "mode": 644
    }
  ],
  "directories_seen": [
    {
      "path": "/home/user/documents",
      "modified": 1702300000,
      "child_count": 47
    }
  ],
  "resume_token": "eyJwYXRoIjoiL2hvbWUvdXNlci9kb2N1bWVudHMvc3ViZGlyIiwicG9zIjo0NzAwfQ==",
  "progress": {
    "files_scanned": 5000,
    "dirs_scanned": 230,
    "bytes_total": 15032385536,
    "errors": 3
  },
  "complete": false,
  "errors": [
    {"path": "/home/user/documents/locked.db", "error": "Permission denied"}
  ]
}
```

#### Implementation Notes

```rust
pub struct CrawlState {
    root: PathBuf,
    walker: IntoIter,           // walkdir iterator
    batch_size: usize,
    skip_patterns: Vec<Pattern>,
    include_hidden: bool,
    dirs_only: bool,
    
    // Progress tracking
    files_scanned: u64,
    dirs_scanned: u64,
    bytes_total: u64,
    errors: Vec<CrawlError>,
    
    // For directory change detection
    dir_metadata: Vec<DirMeta>,
}

pub struct DirMeta {
    path: PathBuf,
    modified: i64,      // Unix timestamp
    child_count: u32,   // Direct children only
}

// Resume token is base64-encoded JSON containing:
// - Current directory path
// - Position within directory
// - Hash of skip_patterns (to detect config changes)
```

**Key optimizations:**
- Uses `walkdir` with `contents_first(false)` for predictable ordering
- Collects directory metadata for USM's change detection
- Batches to avoid memory bloat on huge trees
- Resume token allows interruption/continuation
- Errors collected but don't stop crawl

---

### 2. `ufm_dir_check` - Fast Directory Change Detection

**Purpose:** Quickly check if directories have changed since last crawl without reading all files.

#### Schema

```json
{
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
}
```

#### Response

```json
{
  "results": [
    {
      "path": "/home/user/documents",
      "status": "unchanged"
    },
    {
      "path": "/home/user/downloads",
      "status": "changed",
      "current_mtime": 1702400000,
      "current_children": 52
    },
    {
      "path": "/home/user/deleted_folder",
      "status": "missing"
    }
  ],
  "summary": {
    "checked": 100,
    "unchanged": 85,
    "changed": 12,
    "missing": 3
  }
}
```

**Implementation:** Simple stat() calls - very fast, can check thousands of directories per second.

---

### 3. `ufm_hash_sample` - Fast File Comparison

**Purpose:** Generate a fast "fingerprint" hash for duplicate detection without reading entire files.

#### Schema

```json
{
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
}
```

#### Response

```json
{
  "hashes": [
    {
      "path": "/home/user/video.mp4",
      "hash": "a1b2c3d4e5f6",
      "algorithm": "sample",
      "bytes_read": 12288
    },
    {
      "path": "/home/user/video_copy.mp4",
      "hash": "a1b2c3d4e5f6",
      "algorithm": "sample",
      "bytes_read": 12288
    }
  ],
  "errors": []
}
```

#### Sample Hash Strategy

```rust
fn sample_hash(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    
    let mut hasher = XxHash64::default();
    let mut buffer = [0u8; 4096];
    
    // Always hash file size (different sizes = definitely different)
    hasher.write_u64(size);
    
    if size <= 12288 {
        // Small file: hash entire thing
        file.read_to_end(&mut buffer)?;
        hasher.write(&buffer);
    } else {
        // Large file: sample start, middle, end
        
        // First 4KB
        file.read_exact(&mut buffer)?;
        hasher.write(&buffer);
        
        // Middle 4KB
        file.seek(SeekFrom::Start(size / 2 - 2048))?;
        file.read_exact(&mut buffer)?;
        hasher.write(&buffer);
        
        // Last 4KB
        file.seek(SeekFrom::End(-4096))?;
        file.read_exact(&mut buffer)?;
        hasher.write(&buffer);
    }
    
    Ok(hasher.finish().to_le_bytes().to_vec())
}
```

**Why this works:**
- Different sizes = different files (instant reject)
- First 4KB catches different headers (documents, media)
- Middle 4KB catches content differences
- Last 4KB catches different endings (trailers, checksums)
- Only reads 12KB regardless of file size
- False positive rate is extremely low in practice

---

## Updated Dependency List

Add to `Cargo.toml`:

```toml
# Fast hashing
xxhash-rust = { version = "0.8", features = ["xxh64"] }

# Optional full hashing
sha2 = "0.10"
```

---

## Integration with USM

### Workflow: Initial Index Build

```
USM                                    UFM
 │                                      │
 ├─── usm_crawl_start ──────────────────┤
 │    {"root": "C:\\"}                  │
 │                                      │
 │    ┌─────────────────────────────────┤
 │    │ ufm_crawl                       │
 │    │ {"root": "C:\\", batch: 1000}   │
 │    ├─────────────────────────────────►
 │    │                                 │
 │◄───┼─── batch 1 (1000 entries) ──────┤
 │    │                                 │
 │    │ (USM inserts into SQLite)       │
 │    │                                 │
 │    ├─── ufm_crawl (resume_token) ────►
 │◄───┼─── batch 2 (1000 entries) ──────┤
 │    │                                 │
 │    │    ... repeat until complete    │
 │    │                                 │
 │◄───┼─── final batch, complete: true ─┤
 │    └─────────────────────────────────┤
 │                                      │
 └──────────────────────────────────────┘
```

### Workflow: Incremental Update

```
USM                                    UFM
 │                                      │
 ├─── (load cached dir metadata) ───────┤
 │                                      │
 ├─── ufm_dir_check ────────────────────►
 │    [100 directories with expected    │
 │     mtime and child counts]          │
 │                                      │
 │◄─── results: 12 changed, 3 missing ──┤
 │                                      │
 │    (For each changed directory:)     │
 ├─── ufm_crawl {"root": changed_dir} ──►
 │◄─── entries in that dir ─────────────┤
 │                                      │
 │    (Update SQLite with changes)      │
 │                                      │
 └──────────────────────────────────────┘
```

### Workflow: Duplicate Verification

```
USM                                    UFM
 │                                      │
 │ (USM finds size-matched groups       │
 │  in database)                        │
 │                                      │
 ├─── ufm_hash_sample ──────────────────►
 │    {"paths": [suspected duplicates]} │
 │                                      │
 │◄─── hashes for each file ────────────┤
 │                                      │
 │ (USM groups by matching hash)        │
 │                                      │
 │ (If user wants certainty:)           │
 ├─── ufm_hash_sample ──────────────────►
 │    {"paths": [...], "algorithm":     │
 │     "full", "hash_type": "sha256"}   │
 │                                      │
 │◄─── full file hashes ────────────────┤
 │                                      │
 └──────────────────────────────────────┘
```

---

## Summary of UFM Changes

| Addition | Type | Purpose |
|----------|------|---------|
| `ufm_crawl` | Tool | Bulk metadata extraction with batching |
| `ufm_dir_check` | Tool | Fast directory change detection |
| `ufm_hash_sample` | Tool | Quick file fingerprinting |
| `xxhash-rust` | Dependency | Fast non-cryptographic hashing |
| `sha2` | Dependency | Full file verification (optional) |

Total UFM tools: **22** (was 19)
