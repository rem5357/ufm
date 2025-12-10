//! Archive module for UFM
//!
//! Provides read/write access to ZIP and TAR archives,
//! with virtual directory navigation (treating archives as folders).

use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, BufReader};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArchiveError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    
    #[error("Archive not found: {0}")]
    NotFound(PathBuf),
    
    #[error("Entry not found in archive: {0}")]
    EntryNotFound(String),
    
    #[error("Unsupported archive format: {0}")]
    UnsupportedFormat(String),
    
    #[error("Archive is read-only")]
    ReadOnly,
    
    #[error("Invalid archive path: {0}")]
    InvalidPath(String),
}

pub type Result<T> = std::result::Result<T, ArchiveError>;

/// Represents an entry within an archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub modified: Option<DateTime<Utc>>,
    pub crc32: Option<u32>,
    pub compression_method: Option<String>,
}

/// Archive format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    TarGz,
    Tar,
    Unknown,
}

impl ArchiveFormat {
    /// Detect archive format from file extension
    pub fn from_extension(path: &Path) -> Self {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());
        
        match ext.as_deref() {
            Some("zip") | Some("jar") | Some("war") | Some("ear") => Self::Zip,
            Some("gz") | Some("tgz") => {
                // Check if it's .tar.gz
                let stem = path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if stem.ends_with(".tar") || path.to_string_lossy().contains(".tar.") {
                    Self::TarGz
                } else {
                    Self::Unknown
                }
            }
            Some("tar") => Self::Tar,
            _ => Self::Unknown,
        }
    }
    
    /// Detect archive format from magic bytes
    pub fn from_magic(data: &[u8]) -> Self {
        if data.len() < 4 {
            return Self::Unknown;
        }
        
        // ZIP magic: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
        if data[0] == 0x50 && data[1] == 0x4B {
            return Self::Zip;
        }
        
        // GZIP magic: \x1f\x8b
        if data[0] == 0x1f && data[1] == 0x8b {
            return Self::TarGz;
        }
        
        // TAR magic: "ustar" at offset 257
        if data.len() > 262 && &data[257..262] == b"ustar" {
            return Self::Tar;
        }
        
        Self::Unknown
    }
}

/// Virtual path within an archive
/// Format: archive_path::internal_path
/// Example: /home/user/file.zip::folder/document.txt
#[derive(Debug, Clone)]
pub struct VirtualPath {
    pub archive_path: PathBuf,
    pub internal_path: String,
}

impl VirtualPath {
    /// Parse a virtual path
    pub fn parse(path: &str) -> Option<Self> {
        if let Some(idx) = path.find("::") {
            Some(Self {
                archive_path: PathBuf::from(&path[..idx]),
                internal_path: path[idx + 2..].to_string(),
            })
        } else {
            None
        }
    }
    
    /// Create a virtual path
    pub fn new(archive: PathBuf, internal: &str) -> Self {
        Self {
            archive_path: archive,
            internal_path: internal.to_string(),
        }
    }
    
    /// Convert to string representation
    pub fn to_string(&self) -> String {
        format!("{}::{}", self.archive_path.display(), self.internal_path)
    }
    
    /// Check if this is a root path within the archive
    pub fn is_root(&self) -> bool {
        self.internal_path.is_empty() || self.internal_path == "/"
    }
}

/// Archive manager for handling different archive formats
pub struct ArchiveManager {
    /// Cache of open archives for performance
    cache: HashMap<PathBuf, CachedArchive>,
}

struct CachedArchive {
    format: ArchiveFormat,
    entries: Vec<ArchiveEntry>,
    last_accessed: std::time::Instant,
}

impl ArchiveManager {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    
    /// Check if a path is an archive
    pub fn is_archive(path: &Path) -> bool {
        ArchiveFormat::from_extension(path) != ArchiveFormat::Unknown
    }
    
    /// Check if a path contains an archive reference (virtual path)
    pub fn is_virtual_path(path: &str) -> bool {
        path.contains("::")
    }
    
    /// List contents of an archive
    pub fn list(&mut self, archive_path: &Path, internal_path: &str) -> Result<Vec<ArchiveEntry>> {
        if !archive_path.exists() {
            return Err(ArchiveError::NotFound(archive_path.to_path_buf()));
        }
        
        let format = ArchiveFormat::from_extension(archive_path);
        
        match format {
            ArchiveFormat::Zip => self.list_zip(archive_path, internal_path),
            ArchiveFormat::Tar | ArchiveFormat::TarGz => self.list_tar(archive_path, internal_path, format == ArchiveFormat::TarGz),
            ArchiveFormat::Unknown => Err(ArchiveError::UnsupportedFormat(
                archive_path.to_string_lossy().to_string()
            )),
        }
    }
    
    /// Read a file from an archive
    pub fn read(&self, archive_path: &Path, internal_path: &str) -> Result<Vec<u8>> {
        if !archive_path.exists() {
            return Err(ArchiveError::NotFound(archive_path.to_path_buf()));
        }
        
        let format = ArchiveFormat::from_extension(archive_path);
        
        match format {
            ArchiveFormat::Zip => self.read_zip(archive_path, internal_path),
            ArchiveFormat::Tar | ArchiveFormat::TarGz => self.read_tar(archive_path, internal_path, format == ArchiveFormat::TarGz),
            ArchiveFormat::Unknown => Err(ArchiveError::UnsupportedFormat(
                archive_path.to_string_lossy().to_string()
            )),
        }
    }
    
    /// Extract a file or directory from an archive
    pub fn extract(&self, archive_path: &Path, internal_path: &str, dest: &Path) -> Result<()> {
        let content = self.read(archive_path, internal_path)?;
        
        // Ensure parent directory exists
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        
        fs::write(dest, content)?;
        Ok(())
    }
    
    /// Add a file to an archive (ZIP only for now)
    pub fn add(&self, archive_path: &Path, internal_path: &str, content: &[u8]) -> Result<()> {
        let format = ArchiveFormat::from_extension(archive_path);
        
        match format {
            ArchiveFormat::Zip => self.add_to_zip(archive_path, internal_path, content),
            _ => Err(ArchiveError::ReadOnly),
        }
    }
    
    /// Create a new archive with files
    pub fn create<P: AsRef<Path>>(&self, archive_path: &Path, files: &[(P, &str)]) -> Result<()> {
        let format = ArchiveFormat::from_extension(archive_path);
        
        match format {
            ArchiveFormat::Zip => self.create_zip(archive_path, files),
            ArchiveFormat::Tar => self.create_tar(archive_path, files, false),
            ArchiveFormat::TarGz => self.create_tar(archive_path, files, true),
            ArchiveFormat::Unknown => Err(ArchiveError::UnsupportedFormat(
                archive_path.to_string_lossy().to_string()
            )),
        }
    }
    
    // ZIP operations
    
    fn list_zip(&self, archive_path: &Path, internal_path: &str) -> Result<Vec<ArchiveEntry>> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let mut archive = zip::ZipArchive::new(reader)?;
        
        let prefix = if internal_path.is_empty() || internal_path == "/" {
            String::new()
        } else {
            let mut p = internal_path.trim_start_matches('/').to_string();
            if !p.ends_with('/') {
                p.push('/');
            }
            p
        };
        
        let mut entries = Vec::new();
        let mut seen_dirs = std::collections::HashSet::new();
        
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name().to_string();
            
            // Filter by prefix
            if !prefix.is_empty() && !name.starts_with(&prefix) {
                continue;
            }
            
            // Get the relative path within this directory
            let relative = name.strip_prefix(&prefix).unwrap_or(&name);
            
            // Skip empty entries
            if relative.is_empty() {
                continue;
            }
            
            // Only include direct children (not nested)
            let parts: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }
            
            let entry_name = parts[0].to_string();
            let is_dir = parts.len() > 1 || file.is_dir();
            
            // Skip if we've already seen this directory
            if is_dir && seen_dirs.contains(&entry_name) {
                continue;
            }
            
            if is_dir {
                seen_dirs.insert(entry_name.clone());
            }
            
            let entry = ArchiveEntry {
                name: entry_name.clone(),
                path: if prefix.is_empty() {
                    entry_name
                } else {
                    format!("{}{}", prefix, entry_name)
                },
                is_file: !is_dir,
                is_dir,
                size: file.size(),
                compressed_size: Some(file.compressed_size()),
                modified: file.last_modified()
                    .and_then(|dt| {
                        chrono::NaiveDate::from_ymd_opt(
                            dt.year() as i32,
                            dt.month() as u32,
                            dt.day() as u32,
                        )
                        .and_then(|d| d.and_hms_opt(
                            dt.hour() as u32,
                            dt.minute() as u32,
                            dt.second() as u32,
                        ))
                        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
                    }),
                crc32: Some(file.crc32()),
                compression_method: Some(format!("{:?}", file.compression())),
            };
            
            entries.push(entry);
        }
        
        Ok(entries)
    }
    
    fn read_zip(&self, archive_path: &Path, internal_path: &str) -> Result<Vec<u8>> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let mut archive = zip::ZipArchive::new(reader)?;
        
        let path = internal_path.trim_start_matches('/');
        
        let mut file = archive.by_name(path)
            .map_err(|_| ArchiveError::EntryNotFound(internal_path.to_string()))?;
        
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        
        Ok(content)
    }
    
    fn add_to_zip(&self, archive_path: &Path, internal_path: &str, content: &[u8]) -> Result<()> {
        // Read existing archive
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let mut archive = zip::ZipArchive::new(reader)?;
        
        // Create a temporary file for the new archive
        let temp_path = archive_path.with_extension("zip.tmp");
        let temp_file = File::create(&temp_path)?;
        let mut writer = zip::ZipWriter::new(temp_file);
        
        // Copy existing entries
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            
            // Skip if this is the file we're replacing
            if name == internal_path {
                continue;
            }
            
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(file.compression());
            
            if file.is_dir() {
                writer.add_directory(&name, options)?;
            } else {
                writer.start_file(&name, options)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                writer.write_all(&buffer)?;
            }
        }
        
        // Add the new file
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file(internal_path, options)?;
        writer.write_all(content)?;
        
        writer.finish()?;
        
        // Replace original with new
        fs::rename(&temp_path, archive_path)?;
        
        Ok(())
    }
    
    fn create_zip<P: AsRef<Path>>(&self, archive_path: &Path, files: &[(P, &str)]) -> Result<()> {
        let file = File::create(archive_path)?;
        let mut writer = zip::ZipWriter::new(file);
        
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        
        for (source_path, internal_path) in files {
            let source = source_path.as_ref();
            
            if source.is_dir() {
                // Add directory recursively
                self.add_directory_to_zip(&mut writer, source, internal_path, &options)?;
            } else {
                writer.start_file(*internal_path, options)?;
                let content = fs::read(source)?;
                writer.write_all(&content)?;
            }
        }
        
        writer.finish()?;
        Ok(())
    }
    
    fn add_directory_to_zip<W: Write + Seek>(
        &self,
        writer: &mut zip::ZipWriter<W>,
        dir: &Path,
        base_path: &str,
        options: &zip::write::SimpleFileOptions,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            
            let internal = if base_path.is_empty() {
                name_str.to_string()
            } else {
                format!("{}/{}", base_path, name_str)
            };
            
            if path.is_dir() {
                writer.add_directory(&format!("{}/", internal), *options)?;
                self.add_directory_to_zip(writer, &path, &internal, options)?;
            } else {
                writer.start_file(&internal, *options)?;
                let content = fs::read(&path)?;
                writer.write_all(&content)?;
            }
        }
        
        Ok(())
    }
    
    // TAR operations
    
    fn list_tar(&self, archive_path: &Path, internal_path: &str, gzipped: bool) -> Result<Vec<ArchiveEntry>> {
        let file = File::open(archive_path)?;
        
        let entries = if gzipped {
            let decoder = flate2::read::GzDecoder::new(file);
            self.list_tar_reader(decoder, internal_path)?
        } else {
            self.list_tar_reader(file, internal_path)?
        };
        
        Ok(entries)
    }
    
    fn list_tar_reader<R: Read>(&self, reader: R, internal_path: &str) -> Result<Vec<ArchiveEntry>> {
        let mut archive = tar::Archive::new(reader);
        
        let prefix = if internal_path.is_empty() || internal_path == "/" {
            String::new()
        } else {
            let mut p = internal_path.trim_start_matches('/').to_string();
            if !p.ends_with('/') {
                p.push('/');
            }
            p
        };
        
        let mut entries = Vec::new();
        let mut seen_dirs = std::collections::HashSet::new();
        
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;
            let name = path.to_string_lossy().to_string();
            
            // Filter by prefix
            if !prefix.is_empty() && !name.starts_with(&prefix) {
                continue;
            }
            
            let relative = name.strip_prefix(&prefix).unwrap_or(&name);
            if relative.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }
            
            let entry_name = parts[0].to_string();
            let is_dir = parts.len() > 1 || entry.header().entry_type().is_dir();
            
            if is_dir && seen_dirs.contains(&entry_name) {
                continue;
            }
            
            if is_dir {
                seen_dirs.insert(entry_name.clone());
            }
            
            let header = entry.header();
            
            let archive_entry = ArchiveEntry {
                name: entry_name.clone(),
                path: if prefix.is_empty() {
                    entry_name
                } else {
                    format!("{}{}", prefix, entry_name)
                },
                is_file: !is_dir,
                is_dir,
                size: header.size()?,
                compressed_size: None,
                modified: header.mtime().ok().map(|ts| {
                    DateTime::<Utc>::from_timestamp(ts as i64, 0)
                        .unwrap_or_else(|| Utc::now())
                }),
                crc32: None,
                compression_method: None,
            };
            
            entries.push(archive_entry);
        }
        
        Ok(entries)
    }
    
    fn read_tar(&self, archive_path: &Path, internal_path: &str, gzipped: bool) -> Result<Vec<u8>> {
        let file = File::open(archive_path)?;
        
        if gzipped {
            let decoder = flate2::read::GzDecoder::new(file);
            self.read_tar_reader(decoder, internal_path)
        } else {
            self.read_tar_reader(file, internal_path)
        }
    }
    
    fn read_tar_reader<R: Read>(&self, reader: R, internal_path: &str) -> Result<Vec<u8>> {
        let mut archive = tar::Archive::new(reader);
        let path = internal_path.trim_start_matches('/');
        
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().to_string();
            
            if entry_path.trim_end_matches('/') == path.trim_end_matches('/') {
                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;
                return Ok(content);
            }
        }
        
        Err(ArchiveError::EntryNotFound(internal_path.to_string()))
    }
    
    fn create_tar<P: AsRef<Path>>(&self, archive_path: &Path, files: &[(P, &str)], gzipped: bool) -> Result<()> {
        let file = File::create(archive_path)?;
        
        if gzipped {
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            self.create_tar_writer(encoder, files)?;
        } else {
            self.create_tar_writer(file, files)?;
        }
        
        Ok(())
    }
    
    fn create_tar_writer<W: Write, P: AsRef<Path>>(&self, writer: W, files: &[(P, &str)]) -> Result<()> {
        let mut builder = tar::Builder::new(writer);
        
        for (source_path, internal_path) in files {
            let source = source_path.as_ref();
            
            if source.is_dir() {
                builder.append_dir_all(internal_path, source)?;
            } else {
                let mut file = File::open(source)?;
                builder.append_file(internal_path, &mut file)?;
            }
        }
        
        builder.finish()?;
        Ok(())
    }
}

impl Default for ArchiveManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_archive_format_detection() {
        assert_eq!(ArchiveFormat::from_extension(Path::new("test.zip")), ArchiveFormat::Zip);
        assert_eq!(ArchiveFormat::from_extension(Path::new("test.jar")), ArchiveFormat::Zip);
        assert_eq!(ArchiveFormat::from_extension(Path::new("test.tar")), ArchiveFormat::Tar);
        assert_eq!(ArchiveFormat::from_extension(Path::new("test.tar.gz")), ArchiveFormat::TarGz);
        assert_eq!(ArchiveFormat::from_extension(Path::new("test.tgz")), ArchiveFormat::Unknown); // .tgz needs special handling
    }
    
    #[test]
    fn test_virtual_path_parsing() {
        let vp = VirtualPath::parse("/home/user/archive.zip::folder/file.txt").unwrap();
        assert_eq!(vp.archive_path, PathBuf::from("/home/user/archive.zip"));
        assert_eq!(vp.internal_path, "folder/file.txt");
        
        assert!(VirtualPath::parse("/home/user/regular.txt").is_none());
    }
    
    #[test]
    fn test_create_and_read_zip() {
        let temp = tempdir().unwrap();
        
        // Create a test file
        let test_file = temp.path().join("test.txt");
        fs::write(&test_file, "Hello, World!").unwrap();
        
        // Create archive
        let archive_path = temp.path().join("test.zip");
        let manager = ArchiveManager::new();
        manager.create(&archive_path, &[(&test_file, "test.txt")]).unwrap();
        
        // Read back
        let content = manager.read(&archive_path, "test.txt").unwrap();
        assert_eq!(content, b"Hello, World!");
    }
}
