//! Core file operations for UFM
//!
//! Provides cross-platform file operations with consistent behavior.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use filetime::{FileTime, set_file_mtime, set_file_atime};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use walkdir::WalkDir;

use crate::security::{SecurityPolicy, SecurityError};

#[derive(Error, Debug)]
pub enum FileError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),
    
    #[error("File not found: {0}")]
    NotFound(PathBuf),
    
    #[error("Already exists: {0}")]
    AlreadyExists(PathBuf),
    
    #[error("Not a directory: {0}")]
    NotADirectory(PathBuf),
    
    #[error("Not a file: {0}")]
    NotAFile(PathBuf),
    
    #[error("File too large: {0} bytes (max: {1})")]
    FileTooLarge(u64, u64),
    
    #[error("Encoding error: {0}")]
    Encoding(String),
    
    #[error("Path error: {0}")]
    PathError(String),
}

pub type Result<T> = std::result::Result<T, FileError>;

/// File metadata with cross-platform support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub name: String,
    pub extension: Option<String>,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub readonly: bool,
    pub hidden: bool,
    pub permissions: FilePermissions,
    pub mime_type: Option<String>,
}

/// Cross-platform file permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    /// Unix-style mode (e.g., 0o755)
    pub mode: Option<u32>,
    /// Readable
    pub readable: bool,
    /// Writable
    pub writable: bool,
    /// Executable (Unix) / runnable (Windows)
    pub executable: bool,
}

/// Directory entry for listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

/// Options for listing directories
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub recursive: bool,
    pub max_depth: Option<u32>,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub pattern: Option<String>,
    pub sort_by: SortBy,
    pub sort_ascending: bool,
}

#[derive(Debug, Clone, Default)]
pub enum SortBy {
    #[default]
    Name,
    Size,
    Modified,
    Extension,
}

/// Options for reading files
#[derive(Debug, Clone, Default)]
pub struct ReadOptions {
    pub encoding: Option<String>,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub as_base64: bool,
}

/// Options for writing files
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    pub create: bool,
    pub append: bool,
    pub truncate: bool,
    pub encoding: Option<String>,
    pub from_base64: bool,
}

/// Options for copying files
#[derive(Debug, Clone, Default)]
pub struct CopyOptions {
    pub overwrite: bool,
    pub recursive: bool,
    pub preserve_metadata: bool,
}

/// Result of a batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub errors: Vec<BatchError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchError {
    pub path: PathBuf,
    pub error: String,
}

/// Core file manager
pub struct FileManager {
    policy: SecurityPolicy,
}

impl FileManager {
    /// Create a new file manager with the given security policy
    pub fn new(policy: SecurityPolicy) -> Self {
        Self { policy }
    }
    
    /// Read file contents as string
    pub fn read_string(&self, path: &Path, options: &ReadOptions) -> Result<String> {
        let safe_path = self.policy.validate_path(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        if !safe_path.is_file() {
            return Err(FileError::NotAFile(safe_path));
        }
        
        // Check file size
        let metadata = fs::metadata(&safe_path)?;
        let max_size = self.policy.max_read_size();
        if metadata.len() > max_size {
            return Err(FileError::FileTooLarge(metadata.len(), max_size));
        }
        
        let mut file = File::open(&safe_path)?;
        
        // Handle offset
        if let Some(offset) = options.offset {
            use std::io::Seek;
            file.seek(io::SeekFrom::Start(offset))?;
        }
        
        // Read content
        let mut buffer = if let Some(length) = options.length {
            vec![0u8; length as usize]
        } else {
            Vec::new()
        };
        
        let bytes_read = if options.length.is_some() {
            file.read(&mut buffer)?
        } else {
            file.read_to_end(&mut buffer)?
        };
        
        buffer.truncate(bytes_read);
        
        // Handle encoding
        let content = if options.as_base64 {
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.encode(&buffer)
        } else {
            // Try to detect and convert encoding
            let (decoded, _, had_errors) = encoding_rs::UTF_8.decode(&buffer);
            if had_errors {
                // Try other encodings
                let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(&buffer);
                decoded.into_owned()
            } else {
                decoded.into_owned()
            }
        };
        
        Ok(content)
    }
    
    /// Read file contents as bytes
    pub fn read_bytes(&self, path: &Path, options: &ReadOptions) -> Result<Vec<u8>> {
        let safe_path = self.policy.validate_path(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        if !safe_path.is_file() {
            return Err(FileError::NotAFile(safe_path));
        }
        
        let metadata = fs::metadata(&safe_path)?;
        let max_size = self.policy.max_read_size();
        if metadata.len() > max_size {
            return Err(FileError::FileTooLarge(metadata.len(), max_size));
        }
        
        let mut file = File::open(&safe_path)?;
        
        if let Some(offset) = options.offset {
            use std::io::Seek;
            file.seek(io::SeekFrom::Start(offset))?;
        }
        
        let mut buffer = if let Some(length) = options.length {
            vec![0u8; length as usize]
        } else {
            Vec::new()
        };
        
        let bytes_read = if options.length.is_some() {
            file.read(&mut buffer)?
        } else {
            file.read_to_end(&mut buffer)?
        };
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    
    /// Write string content to file
    pub fn write_string(&self, path: &Path, content: &str, options: &WriteOptions) -> Result<u64> {
        let safe_path = self.policy.validate_write(path)?;
        
        let bytes = if options.from_base64 {
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.decode(content)
                .map_err(|e| FileError::Encoding(e.to_string()))?
        } else {
            content.as_bytes().to_vec()
        };
        
        self.write_bytes_internal(&safe_path, &bytes, options)
    }
    
    /// Write bytes to file
    pub fn write_bytes(&self, path: &Path, content: &[u8], options: &WriteOptions) -> Result<u64> {
        let safe_path = self.policy.validate_write(path)?;
        self.write_bytes_internal(&safe_path, content, options)
    }
    
    fn write_bytes_internal(&self, path: &Path, content: &[u8], options: &WriteOptions) -> Result<u64> {
        let mut open_options = OpenOptions::new();
        
        if options.append {
            open_options.append(true);
        } else {
            open_options.write(true);
        }
        
        if options.create {
            open_options.create(true);
        }
        
        if options.truncate {
            open_options.truncate(true);
        }
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() && options.create {
                fs::create_dir_all(parent)?;
            }
        }
        
        let mut file = open_options.open(path)?;
        file.write_all(content)?;
        file.flush()?;
        
        Ok(content.len() as u64)
    }
    
    /// Get file/directory metadata
    pub fn stat(&self, path: &Path) -> Result<FileMetadata> {
        let safe_path = self.policy.validate_path(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        let metadata = fs::symlink_metadata(&safe_path)?;
        
        // Detect mime type for files
        let mime_type = if metadata.is_file() {
            infer::get_from_path(&safe_path)
                .ok()
                .flatten()
                .map(|t| t.mime_type().to_string())
        } else {
            None
        };
        
        Ok(FileMetadata {
            path: safe_path.clone(),
            name: safe_path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            extension: safe_path.extension()
                .map(|e| e.to_string_lossy().to_string()),
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
            is_symlink: metadata.is_symlink(),
            size: metadata.len(),
            created: metadata.created().ok().map(system_time_to_datetime),
            modified: metadata.modified().ok().map(system_time_to_datetime),
            accessed: metadata.accessed().ok().map(system_time_to_datetime),
            readonly: metadata.permissions().readonly(),
            hidden: is_hidden(&safe_path),
            permissions: get_permissions(&metadata),
            mime_type,
        })
    }
    
    /// List directory contents
    pub fn list(&self, path: &Path, options: &ListOptions) -> Result<Vec<DirEntry>> {
        let safe_path = self.policy.validate_path(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        if !safe_path.is_dir() {
            return Err(FileError::NotADirectory(safe_path));
        }
        
        let max_depth = options.max_depth
            .unwrap_or(self.policy.max_recursion_depth())
            .min(self.policy.max_recursion_depth());
        
        let walker = if options.recursive {
            WalkDir::new(&safe_path)
                .max_depth(max_depth as usize)
                .follow_links(options.follow_symlinks && self.policy.follow_symlinks())
        } else {
            WalkDir::new(&safe_path)
                .max_depth(1)
                .follow_links(options.follow_symlinks && self.policy.follow_symlinks())
        };
        
        let pattern = options.pattern.as_ref()
            .and_then(|p| glob::Pattern::new(p).ok());
        
        let mut entries: Vec<DirEntry> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != safe_path)  // Skip root
            .filter(|e| {
                if !options.include_hidden && is_hidden(e.path()) {
                    return false;
                }
                if let Some(ref pat) = pattern {
                    let name = e.file_name().to_string_lossy();
                    if !pat.matches(&name) {
                        return false;
                    }
                }
                true
            })
            .filter_map(|e| {
                let metadata = e.metadata().ok()?;
                Some(DirEntry {
                    name: e.file_name().to_string_lossy().to_string(),
                    path: e.path().to_path_buf(),
                    is_file: metadata.is_file(),
                    is_dir: metadata.is_dir(),
                    is_symlink: e.path_is_symlink(),
                    size: metadata.len(),
                    modified: metadata.modified().ok().map(system_time_to_datetime),
                })
            })
            .collect();
        
        // Sort entries
        match options.sort_by {
            SortBy::Name => entries.sort_by(|a, b| a.name.cmp(&b.name)),
            SortBy::Size => entries.sort_by(|a, b| a.size.cmp(&b.size)),
            SortBy::Modified => entries.sort_by(|a, b| a.modified.cmp(&b.modified)),
            SortBy::Extension => entries.sort_by(|a, b| {
                let ext_a = Path::new(&a.name).extension();
                let ext_b = Path::new(&b.name).extension();
                ext_a.cmp(&ext_b)
            }),
        }
        
        if !options.sort_ascending {
            entries.reverse();
        }
        
        Ok(entries)
    }
    
    /// Create a directory
    pub fn mkdir(&self, path: &Path, recursive: bool) -> Result<()> {
        let safe_path = self.policy.validate_write(path)?;
        
        if safe_path.exists() {
            return Err(FileError::AlreadyExists(safe_path));
        }
        
        if recursive {
            fs::create_dir_all(&safe_path)?;
        } else {
            fs::create_dir(&safe_path)?;
        }
        
        Ok(())
    }
    
    /// Delete a file or directory
    pub fn delete(&self, path: &Path, recursive: bool) -> Result<()> {
        let safe_path = self.policy.validate_delete(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        if safe_path.is_dir() {
            if recursive {
                fs::remove_dir_all(&safe_path)?;
            } else {
                fs::remove_dir(&safe_path)?;
            }
        } else {
            fs::remove_file(&safe_path)?;
        }
        
        Ok(())
    }
    
    /// Move/rename a file or directory
    pub fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let safe_from = self.policy.validate_write(from)?;
        let safe_to = self.policy.validate_write(to)?;
        
        if !safe_from.exists() {
            return Err(FileError::NotFound(safe_from));
        }
        
        fs::rename(&safe_from, &safe_to)?;
        Ok(())
    }
    
    /// Copy a file or directory
    pub fn copy(&self, from: &Path, to: &Path, options: &CopyOptions) -> Result<u64> {
        let safe_from = self.policy.validate_path(from)?;
        let safe_to = self.policy.validate_write(to)?;
        
        if !safe_from.exists() {
            return Err(FileError::NotFound(safe_from));
        }
        
        if safe_to.exists() && !options.overwrite {
            return Err(FileError::AlreadyExists(safe_to));
        }
        
        if safe_from.is_file() {
            let bytes = fs::copy(&safe_from, &safe_to)?;
            
            if options.preserve_metadata {
                let metadata = fs::metadata(&safe_from)?;
                if let Ok(mtime) = metadata.modified() {
                    let _ = set_file_mtime(&safe_to, FileTime::from_system_time(mtime));
                }
                if let Ok(atime) = metadata.accessed() {
                    let _ = set_file_atime(&safe_to, FileTime::from_system_time(atime));
                }
            }
            
            Ok(bytes)
        } else if options.recursive {
            // Use fs_extra for recursive directory copy
            let mut copy_options = fs_extra::dir::CopyOptions::new();
            copy_options.overwrite = options.overwrite;
            copy_options.copy_inside = true;
            
            fs_extra::dir::copy(&safe_from, &safe_to, &copy_options)
                .map_err(|e| FileError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))
        } else {
            Err(FileError::NotAFile(safe_from))
        }
    }
    
    /// Set file modification time
    pub fn set_modified(&self, path: &Path, time: DateTime<Utc>) -> Result<()> {
        let safe_path = self.policy.validate_write(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        let system_time = datetime_to_system_time(time);
        set_file_mtime(&safe_path, FileTime::from_system_time(system_time))?;
        
        Ok(())
    }
    
    /// Set file access time
    pub fn set_accessed(&self, path: &Path, time: DateTime<Utc>) -> Result<()> {
        let safe_path = self.policy.validate_write(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        let system_time = datetime_to_system_time(time);
        set_file_atime(&safe_path, FileTime::from_system_time(system_time))?;
        
        Ok(())
    }
    
    /// Batch set modification time
    pub fn batch_set_modified(&self, paths: &[PathBuf], time: DateTime<Utc>) -> BatchResult {
        let mut result = BatchResult {
            total: paths.len(),
            succeeded: 0,
            failed: 0,
            errors: Vec::new(),
        };
        
        for path in paths {
            match self.set_modified(path, time) {
                Ok(_) => result.succeeded += 1,
                Err(e) => {
                    result.failed += 1;
                    result.errors.push(BatchError {
                        path: path.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        result
    }
    
    /// Set readonly flag
    pub fn set_readonly(&self, path: &Path, readonly: bool) -> Result<()> {
        let safe_path = self.policy.validate_chmod(path)?;
        
        if !safe_path.exists() {
            return Err(FileError::NotFound(safe_path));
        }
        
        let metadata = fs::metadata(&safe_path)?;
        let mut permissions = metadata.permissions();
        permissions.set_readonly(readonly);
        fs::set_permissions(&safe_path, permissions)?;
        
        Ok(())
    }
    
    /// Batch set readonly flag
    pub fn batch_set_readonly(&self, paths: &[PathBuf], readonly: bool) -> BatchResult {
        let mut result = BatchResult {
            total: paths.len(),
            succeeded: 0,
            failed: 0,
            errors: Vec::new(),
        };
        
        for path in paths {
            match self.set_readonly(path, readonly) {
                Ok(_) => result.succeeded += 1,
                Err(e) => {
                    result.failed += 1;
                    result.errors.push(BatchError {
                        path: path.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        result
    }
    
    /// Check if path exists
    pub fn exists(&self, path: &Path) -> Result<bool> {
        let safe_path = self.policy.validate_path(path)?;
        Ok(safe_path.exists())
    }
    
    /// Search for files matching criteria
    pub fn search(&self, root: &Path, pattern: &str, options: &ListOptions) -> Result<Vec<DirEntry>> {
        let mut search_options = options.clone();
        search_options.recursive = true;
        search_options.pattern = Some(pattern.to_string());
        
        self.list(root, &search_options)
    }
}

// Helper functions

fn system_time_to_datetime(st: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(st)
}

fn datetime_to_system_time(dt: DateTime<Utc>) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp() as u64)
}

fn is_hidden(path: &Path) -> bool {
    let name = path.file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    
    // Unix hidden files start with .
    if name.starts_with('.') {
        return true;
    }
    
    // Windows hidden attribute
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

fn get_permissions(metadata: &fs::Metadata) -> FilePermissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        FilePermissions {
            mode: Some(mode),
            readable: mode & 0o400 != 0,
            writable: mode & 0o200 != 0,
            executable: mode & 0o100 != 0,
        }
    }
    
    #[cfg(windows)]
    {
        FilePermissions {
            mode: None,
            readable: true,  // If we can read metadata, we can read
            writable: !metadata.permissions().readonly(),
            executable: false,  // Windows determines this differently
        }
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        FilePermissions {
            mode: None,
            readable: true,
            writable: !metadata.permissions().readonly(),
            executable: false,
        }
    }
}
