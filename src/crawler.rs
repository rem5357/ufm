//! Crawler module for UFM
//!
//! Provides efficient bulk metadata extraction for indexing by USM and similar applications.
//! Includes:
//! - `ufm_crawl` - Streaming metadata extraction with batching
//! - `ufm_dir_check` - Fast directory change detection
//! - `ufm_hash_sample` - Fast file fingerprinting for duplicate detection

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;
use walkdir::{WalkDir, DirEntry as WalkDirEntry};
use xxhash_rust::xxh64::Xxh64;

use crate::security::{SecurityPolicy, SecurityError};

#[derive(Error, Debug)]
pub enum CrawlError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    #[error("Path not found: {0}")]
    NotFound(PathBuf),

    #[error("Invalid resume token")]
    InvalidResumeToken,

    #[error("Glob pattern error: {0}")]
    PatternError(String),
}

pub type Result<T> = std::result::Result<T, CrawlError>;

/// A single file entry from the crawl - full metadata for Rust-to-Rust communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlEntry {
    pub path: PathBuf,
    pub name: String,
    pub extension: Option<String>,
    pub size: u64,
    pub modified: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    pub is_dir: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_hidden: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_symlink: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

/// Minimal entry format for Claude Desktop / low-bandwidth scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlEntryMinimal {
    pub path: PathBuf,
    pub size: u64,
    pub modified: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_dir: bool,
}

/// Directory metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirMeta {
    pub path: PathBuf,
    pub modified: i64,
    pub child_count: u32,
}

/// Progress information for a crawl
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlProgress {
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub bytes_total: u64,
    pub errors: u32,
}

/// Error that occurred during crawl (non-fatal)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlErrorEntry {
    pub path: PathBuf,
    pub error: String,
}

/// Result of a crawl operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    /// Root path - entries have paths relative to this
    pub root: PathBuf,
    /// File/directory entries (paths are relative to root)
    pub entries: Vec<CrawlEntry>,
    /// Token to continue crawl if not complete
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Progress statistics
    pub progress: CrawlProgress,
    /// True if crawl is complete
    pub complete: bool,
    /// Directory metadata (only included if useful for change detection)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories_seen: Vec<DirMeta>,
    /// Errors encountered (non-fatal)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<CrawlErrorEntry>,
}

/// Options for crawling
#[derive(Debug, Clone)]
pub struct CrawlOptions {
    pub batch_size: usize,
    pub include_hidden: bool,
    pub skip_patterns: Vec<Pattern>,
    pub max_depth: Option<usize>,
    pub dirs_only: bool,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            include_hidden: false,
            skip_patterns: Vec::new(),
            max_depth: None,
            dirs_only: false,
        }
    }
}

/// Resume token data (serialized to base64)
///
/// Uses path-based resumption for robustness: we track the last processed path
/// and skip entries until we find it, then continue from there. This is more
/// reliable than position-based tracking since filesystem order can change.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeToken {
    /// The last path that was fully processed
    last_path: PathBuf,
    /// Root directory (to validate token matches current crawl)
    root: PathBuf,
    /// Hash of skip patterns (to detect config changes)
    pattern_hash: u64,
    /// Version marker for future compatibility
    version: u8,
}

/// Result of directory check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirCheckResult {
    pub path: PathBuf,
    pub status: DirStatus,
    pub current_mtime: Option<i64>,
    pub current_children: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirStatus {
    Unchanged,
    Changed,
    Missing,
}

/// Summary of directory check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirCheckSummary {
    pub checked: u32,
    pub unchanged: u32,
    pub changed: u32,
    pub missing: u32,
}

/// Input for directory check
#[derive(Debug, Clone, Deserialize)]
pub struct DirCheckInput {
    pub path: PathBuf,
    pub expected_mtime: i64,
    pub expected_children: Option<u32>,
}

/// Result of hash operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    pub path: PathBuf,
    pub hash: String,
    pub algorithm: String,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sample,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    XxHash,
    Sha256,
}

/// Crawler manager
#[derive(Clone)]
pub struct Crawler {
    policy: SecurityPolicy,
}

impl Crawler {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self { policy }
    }

    /// Crawl a directory tree, returning batched results
    ///
    /// Uses path-based resumption for robustness. When a resume_token is provided,
    /// the crawler will skip entries until it finds the last processed path, then
    /// continue from there.
    pub fn crawl(
        &self,
        root: &Path,
        options: &CrawlOptions,
        resume_token: Option<&str>,
    ) -> Result<CrawlResult> {
        let safe_root = self.policy.validate_path(root)?;

        if !safe_root.exists() {
            return Err(CrawlError::NotFound(safe_root));
        }

        // Parse resume token if provided
        let resume_after_path = if let Some(token) = resume_token {
            let decoded = STANDARD.decode(token)
                .map_err(|_| CrawlError::InvalidResumeToken)?;
            let parsed: ResumeToken = serde_json::from_slice(&decoded)
                .map_err(|_| CrawlError::InvalidResumeToken)?;

            // Validate the token is for the same root
            if parsed.root != safe_root {
                tracing::warn!(
                    "Resume token root mismatch: expected {:?}, got {:?}",
                    safe_root,
                    parsed.root
                );
                return Err(CrawlError::InvalidResumeToken);
            }

            // Check pattern hash matches
            let current_hash = hash_patterns(&options.skip_patterns);
            if parsed.pattern_hash != current_hash {
                tracing::warn!(
                    "Resume token pattern hash mismatch: crawl options changed"
                );
                return Err(CrawlError::InvalidResumeToken);
            }

            tracing::debug!("Resuming crawl after path: {:?}", parsed.last_path);
            Some(parsed.last_path)
        } else {
            None
        };

        let max_depth = options.max_depth
            .unwrap_or(self.policy.max_recursion_depth() as usize);

        // Use sort_by_file_name for consistent ordering across runs
        let walker = WalkDir::new(&safe_root)
            .max_depth(max_depth)
            .follow_links(false)
            .contents_first(false)
            .sort_by_file_name();

        let mut entries = Vec::with_capacity(options.batch_size);
        let mut directories_seen = Vec::new();
        let mut errors = Vec::new();
        let mut progress = CrawlProgress {
            files_scanned: 0,
            dirs_scanned: 0,
            bytes_total: 0,
            errors: 0,
        };

        let mut complete = true;
        let mut last_path = PathBuf::new();
        let mut found_resume_point = resume_after_path.is_none();
        let mut skipped_count: u64 = 0;

        for entry_result in walker {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    progress.errors += 1;
                    errors.push(CrawlErrorEntry {
                        path: e.path().map(|p| p.to_path_buf()).unwrap_or_default(),
                        error: e.to_string(),
                    });
                    continue;
                }
            };

            let path = entry.path();

            // Skip root itself
            if path == safe_root {
                continue;
            }

            // If we're resuming, skip until we find the resume point
            if !found_resume_point {
                if let Some(ref resume_path) = resume_after_path {
                    if path == resume_path.as_path() {
                        found_resume_point = true;
                        tracing::debug!(
                            "Found resume point at {:?}, skipped {} entries",
                            path,
                            skipped_count
                        );
                    } else {
                        skipped_count += 1;
                    }
                    continue;
                }
            }

            // Check skip patterns
            if self.matches_skip_patterns(path, &options.skip_patterns) {
                continue;
            }

            // Check hidden
            if !options.include_hidden && is_hidden(path) {
                continue;
            }

            // Get metadata
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    progress.errors += 1;
                    errors.push(CrawlErrorEntry {
                        path: path.to_path_buf(),
                        error: e.to_string(),
                    });
                    continue;
                }
            };

            let is_dir = metadata.is_dir();

            if is_dir {
                progress.dirs_scanned += 1;

                // Collect directory metadata for change detection
                let child_count = count_children(path);
                let modified = metadata.modified()
                    .map(|t| t.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0))
                    .unwrap_or(0);

                directories_seen.push(DirMeta {
                    path: path.to_path_buf(),
                    modified,
                    child_count,
                });

                if options.dirs_only {
                    // Add directory as an entry too
                    if let Some(crawl_entry) = self.create_entry(&entry, &metadata, &safe_root) {
                        entries.push(crawl_entry);
                    }
                }
            } else {
                progress.files_scanned += 1;
                progress.bytes_total += metadata.len();

                if !options.dirs_only {
                    if let Some(crawl_entry) = self.create_entry(&entry, &metadata, &safe_root) {
                        entries.push(crawl_entry);
                    }
                }
            }

            last_path = path.to_path_buf();

            // Check if we've hit batch size
            if entries.len() >= options.batch_size {
                complete = false;
                break;
            }
        }

        // If we never found the resume point, the token is stale
        if !found_resume_point && resume_after_path.is_some() {
            tracing::warn!(
                "Resume point not found - file may have been deleted. Starting from beginning would be needed."
            );
            // Don't error - just report as complete with what we have
            // The caller can decide to start fresh
        }

        // Generate resume token if not complete
        let resume_token = if !complete && !last_path.as_os_str().is_empty() {
            let token = ResumeToken {
                last_path: last_path.clone(),
                root: safe_root.clone(),
                pattern_hash: hash_patterns(&options.skip_patterns),
                version: 1,
            };
            let json = serde_json::to_vec(&token).unwrap_or_default();
            Some(STANDARD.encode(&json))
        } else {
            None
        };

        tracing::debug!(
            "Crawl batch complete: {} entries, {} dirs, complete={}",
            entries.len(),
            directories_seen.len(),
            complete
        );

        Ok(CrawlResult {
            root: safe_root,
            entries,
            resume_token,
            progress,
            complete,
            directories_seen,
            errors,
        })
    }

    /// Check if directories have changed since last crawl
    pub fn dir_check(&self, directories: &[DirCheckInput]) -> Result<(Vec<DirCheckResult>, DirCheckSummary)> {
        let mut results = Vec::with_capacity(directories.len());
        let mut summary = DirCheckSummary {
            checked: 0,
            unchanged: 0,
            changed: 0,
            missing: 0,
        };

        for dir in directories {
            summary.checked += 1;

            // Validate path security
            let safe_path = match self.policy.validate_path(&dir.path) {
                Ok(p) => p,
                Err(_) => {
                    // Treat security errors as missing
                    summary.missing += 1;
                    results.push(DirCheckResult {
                        path: dir.path.clone(),
                        status: DirStatus::Missing,
                        current_mtime: None,
                        current_children: None,
                    });
                    continue;
                }
            };

            if !safe_path.exists() {
                summary.missing += 1;
                results.push(DirCheckResult {
                    path: dir.path.clone(),
                    status: DirStatus::Missing,
                    current_mtime: None,
                    current_children: None,
                });
                continue;
            }

            let metadata = match fs::metadata(&safe_path) {
                Ok(m) => m,
                Err(_) => {
                    summary.missing += 1;
                    results.push(DirCheckResult {
                        path: dir.path.clone(),
                        status: DirStatus::Missing,
                        current_mtime: None,
                        current_children: None,
                    });
                    continue;
                }
            };

            let current_mtime = metadata.modified()
                .map(|t| t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0))
                .unwrap_or(0);

            let current_children = count_children(&safe_path);

            // Check if changed
            let mtime_changed = current_mtime != dir.expected_mtime;
            let children_changed = dir.expected_children
                .map(|ec| ec != current_children)
                .unwrap_or(false);

            if mtime_changed || children_changed {
                summary.changed += 1;
                results.push(DirCheckResult {
                    path: dir.path.clone(),
                    status: DirStatus::Changed,
                    current_mtime: Some(current_mtime),
                    current_children: Some(current_children),
                });
            } else {
                summary.unchanged += 1;
                results.push(DirCheckResult {
                    path: dir.path.clone(),
                    status: DirStatus::Unchanged,
                    current_mtime: None,
                    current_children: None,
                });
            }
        }

        Ok((results, summary))
    }

    /// Generate file hashes for duplicate detection
    pub fn hash_sample(
        &self,
        paths: &[PathBuf],
        algorithm: HashAlgorithm,
        hash_type: HashType,
    ) -> Result<Vec<std::result::Result<HashResult, CrawlErrorEntry>>> {
        let mut results = Vec::with_capacity(paths.len());

        for path in paths {
            let safe_path = match self.policy.validate_path(path) {
                Ok(p) => p,
                Err(e) => {
                    results.push(Err(CrawlErrorEntry {
                        path: path.clone(),
                        error: e.to_string(),
                    }));
                    continue;
                }
            };

            match self.compute_hash(&safe_path, algorithm, hash_type) {
                Ok(result) => results.push(Ok(result)),
                Err(e) => results.push(Err(CrawlErrorEntry {
                    path: path.clone(),
                    error: e.to_string(),
                })),
            }
        }

        Ok(results)
    }

    fn compute_hash(
        &self,
        path: &Path,
        algorithm: HashAlgorithm,
        hash_type: HashType,
    ) -> Result<HashResult> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        let (hash, bytes_read) = match algorithm {
            HashAlgorithm::Sample => self.sample_hash(&mut file, size, hash_type)?,
            HashAlgorithm::Full => self.full_hash(&mut file, size, hash_type)?,
        };

        let algorithm_str = match algorithm {
            HashAlgorithm::Sample => "sample",
            HashAlgorithm::Full => "full",
        };

        Ok(HashResult {
            path: path.to_path_buf(),
            hash,
            algorithm: algorithm_str.to_string(),
            bytes_read,
        })
    }

    fn sample_hash(
        &self,
        file: &mut File,
        size: u64,
        hash_type: HashType,
    ) -> Result<(String, u64)> {
        const SAMPLE_SIZE: usize = 4096;
        let mut buffer = [0u8; SAMPLE_SIZE];
        let mut bytes_read = 0u64;

        match hash_type {
            HashType::XxHash => {
                let mut hasher = Xxh64::new(0);

                // Always hash file size
                hasher.update(&size.to_le_bytes());

                if size <= (SAMPLE_SIZE * 3) as u64 {
                    // Small file: hash entire thing
                    let mut all_data = Vec::new();
                    file.read_to_end(&mut all_data)?;
                    bytes_read = all_data.len() as u64;
                    hasher.update(&all_data);
                } else {
                    // Large file: sample start, middle, end

                    // First 4KB
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);

                    // Middle 4KB
                    file.seek(SeekFrom::Start(size / 2 - (SAMPLE_SIZE / 2) as u64))?;
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);

                    // Last 4KB
                    file.seek(SeekFrom::End(-(SAMPLE_SIZE as i64)))?;
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);
                }

                Ok((format!("{:016x}", hasher.digest()), bytes_read))
            }
            HashType::Sha256 => {
                let mut hasher = Sha256::new();

                // Always hash file size
                hasher.update(&size.to_le_bytes());

                if size <= (SAMPLE_SIZE * 3) as u64 {
                    let mut all_data = Vec::new();
                    file.read_to_end(&mut all_data)?;
                    bytes_read = all_data.len() as u64;
                    hasher.update(&all_data);
                } else {
                    // First 4KB
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);

                    // Middle 4KB
                    file.seek(SeekFrom::Start(size / 2 - (SAMPLE_SIZE / 2) as u64))?;
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);

                    // Last 4KB
                    file.seek(SeekFrom::End(-(SAMPLE_SIZE as i64)))?;
                    let n = file.read(&mut buffer)?;
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);
                }

                let result = hasher.finalize();
                Ok((hex::encode(result), bytes_read))
            }
        }
    }

    fn full_hash(
        &self,
        file: &mut File,
        _size: u64,
        hash_type: HashType,
    ) -> Result<(String, u64)> {
        let mut buffer = [0u8; 65536]; // 64KB buffer
        let mut bytes_read = 0u64;

        match hash_type {
            HashType::XxHash => {
                let mut hasher = Xxh64::new(0);

                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);
                }

                Ok((format!("{:016x}", hasher.digest()), bytes_read))
            }
            HashType::Sha256 => {
                let mut hasher = Sha256::new();

                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    bytes_read += n as u64;
                    hasher.update(&buffer[..n]);
                }

                let result = hasher.finalize();
                Ok((hex::encode(result), bytes_read))
            }
        }
    }

    fn create_entry(&self, entry: &WalkDirEntry, metadata: &fs::Metadata, root: &Path) -> Option<CrawlEntry> {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Use relative path from root
        let rel_path = path.strip_prefix(root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| path.to_path_buf());

        let extension = path.extension()
            .map(|e| e.to_string_lossy().to_string());

        let modified = metadata.modified()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0))
            .unwrap_or(0);

        let created = metadata.created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        };

        #[cfg(not(unix))]
        let mode = None;

        Some(CrawlEntry {
            path: rel_path,
            name,
            extension,
            size: metadata.len(),
            modified,
            created,
            is_dir: metadata.is_dir(),
            is_hidden: is_hidden(path),
            is_symlink: metadata.is_symlink(),
            mode,
        })
    }

    fn create_entry_minimal(&self, entry: &WalkDirEntry, metadata: &fs::Metadata, root: &Path) -> Option<CrawlEntryMinimal> {
        let path = entry.path();

        let rel_path = path.strip_prefix(root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| path.to_path_buf());

        let modified = metadata.modified()
            .map(|t| t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0))
            .unwrap_or(0);

        Some(CrawlEntryMinimal {
            path: rel_path,
            size: metadata.len(),
            modified,
            is_dir: metadata.is_dir(),
        })
    }

    fn matches_skip_patterns(&self, path: &Path, patterns: &[Pattern]) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in patterns {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        false
    }
}

// Helper functions

fn is_hidden(path: &Path) -> bool {
    let name = path.file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    if name.starts_with('.') {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(path) {
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            return meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0;
        }
    }

    false
}

fn count_children(path: &Path) -> u32 {
    fs::read_dir(path)
        .map(|entries| entries.count() as u32)
        .unwrap_or(0)
}

fn hash_patterns(patterns: &[Pattern]) -> u64 {
    let mut hasher = Xxh64::new(0);
    for pattern in patterns {
        hasher.update(pattern.as_str().as_bytes());
    }
    hasher.digest()
}

// We need hex encoding for SHA256
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_crawl_basic() {
        let temp = tempdir().unwrap();

        // Create test structure
        fs::write(temp.path().join("file1.txt"), "hello").unwrap();
        fs::write(temp.path().join("file2.txt"), "world").unwrap();
        fs::create_dir(temp.path().join("subdir")).unwrap();
        fs::write(temp.path().join("subdir/file3.txt"), "nested").unwrap();

        let policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        let crawler = Crawler::new(policy);

        let result = crawler.crawl(temp.path(), &CrawlOptions::default(), None).unwrap();

        assert!(result.complete);
        assert_eq!(result.entries.len(), 3); // 3 files
        assert!(!result.directories_seen.is_empty());
    }

    #[test]
    fn test_dir_check() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("file.txt"), "test").unwrap();

        let policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        let crawler = Crawler::new(policy);

        let metadata = fs::metadata(temp.path()).unwrap();
        let mtime = metadata.modified().unwrap()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_secs() as i64;

        let dirs = vec![DirCheckInput {
            path: temp.path().to_path_buf(),
            expected_mtime: mtime,
            expected_children: Some(1),
        }];

        let (results, summary) = crawler.dir_check(&dirs).unwrap();

        assert_eq!(summary.unchanged, 1);
        assert_eq!(results[0].status, DirStatus::Unchanged);
    }

    #[test]
    fn test_hash_sample() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap();

        let policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        let crawler = Crawler::new(policy);

        let results = crawler.hash_sample(
            &[file_path.clone()],
            HashAlgorithm::Sample,
            HashType::XxHash,
        ).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());

        let hash_result = results[0].as_ref().unwrap();
        assert!(!hash_result.hash.is_empty());
        assert_eq!(hash_result.algorithm, "sample");
    }
}
