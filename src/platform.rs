//! Platform-specific operations for UFM
//!
//! Handles platform-specific features like:
//! - Unix permissions (chmod)
//! - Windows attributes and ACLs
//! - Extended attributes (xattr)
//! - Folder colors and metadata

use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Operation not supported on this platform")]
    NotSupported,
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Invalid mode: {0}")]
    InvalidMode(String),
}

pub type Result<T> = std::result::Result<T, PlatformError>;

// ============================================================================
// Unix-specific implementations
// ============================================================================

#[cfg(unix)]
pub mod unix {
    use super::*;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    
    /// Set Unix file permissions (chmod)
    pub fn chmod(path: &Path, mode: u32) -> Result<()> {
        let permissions = Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
    
    /// Get Unix file permissions
    pub fn get_mode(path: &Path) -> Result<u32> {
        let metadata = fs::metadata(path)?;
        Ok(metadata.permissions().mode())
    }
    
    /// Change file owner (requires root)
    pub fn chown(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        use nix::unistd::{Uid, Gid, chown as nix_chown};
        
        let uid = uid.map(Uid::from_raw);
        let gid = gid.map(Gid::from_raw);
        
        nix_chown(path, uid, gid)
            .map_err(|e| PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                e.to_string()
            )))?;
        
        Ok(())
    }
    
    /// Get file owner info
    pub fn get_owner(path: &Path) -> Result<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        
        let metadata = fs::metadata(path)?;
        Ok((metadata.uid(), metadata.gid()))
    }
    
    /// Set extended attribute
    #[cfg(feature = "xattr")]
    pub fn set_xattr(path: &Path, name: &str, value: &[u8]) -> Result<()> {
        xattr::set(path, name, value)
            .map_err(|e| PlatformError::Io(e))?;
        Ok(())
    }
    
    /// Get extended attribute
    #[cfg(feature = "xattr")]
    pub fn get_xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
        match xattr::get(path, name) {
            Ok(value) => Ok(value),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PlatformError::Io(e)),
        }
    }
    
    /// List extended attributes
    #[cfg(feature = "xattr")]
    pub fn list_xattr(path: &Path) -> Result<Vec<String>> {
        let attrs = xattr::list(path)
            .map_err(|e| PlatformError::Io(e))?
            .filter_map(|a| a.to_str().map(|s| s.to_string()))
            .collect();
        Ok(attrs)
    }
    
    /// Remove extended attribute
    #[cfg(feature = "xattr")]
    pub fn remove_xattr(path: &Path, name: &str) -> Result<()> {
        xattr::remove(path, name)
            .map_err(|e| PlatformError::Io(e))?;
        Ok(())
    }
    
    /// Set folder color via GNOME/KDE metadata
    /// This uses the .directory file for KDE and GIO attributes for GNOME
    pub fn set_folder_color(path: &Path, color: &str) -> Result<()> {
        if !path.is_dir() {
            return Err(PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path is not a directory"
            )));
        }
        
        // KDE approach: write .directory file
        let dot_directory = path.join(".directory");
        let content = format!(
            "[Desktop Entry]\nIcon=folder-{}\n",
            color.to_lowercase()
        );
        std::fs::write(&dot_directory, content)?;
        
        // GNOME approach: set metadata attribute (if gio is available)
        #[cfg(feature = "xattr")]
        {
            let attr_name = "metadata::custom-icon-name";
            let icon_name = format!("folder-{}", color.to_lowercase());
            let _ = set_xattr(path, attr_name, icon_name.as_bytes());
        }
        
        Ok(())
    }
    
    /// Get folder color
    pub fn get_folder_color(path: &Path) -> Result<Option<String>> {
        // Try KDE .directory file
        let dot_directory = path.join(".directory");
        if dot_directory.exists() {
            let content = std::fs::read_to_string(&dot_directory)?;
            for line in content.lines() {
                if line.starts_with("Icon=folder-") {
                    let color = line.strip_prefix("Icon=folder-").unwrap_or("");
                    if !color.is_empty() {
                        return Ok(Some(color.to_string()));
                    }
                }
            }
        }
        
        Ok(None)
    }
}

// ============================================================================
// Windows-specific implementations
// ============================================================================

#[cfg(windows)]
pub mod win {
    use super::*;
    use std::fs;
    use std::os::windows::fs::MetadataExt;

    // Windows file attributes
    pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
    pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
    pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
    pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;

    /// Get Windows file attributes
    pub fn get_attributes(path: &Path) -> Result<u32> {
        let metadata = fs::metadata(path)?;
        Ok(metadata.file_attributes())
    }

    /// Set Windows file attributes
    pub fn set_attributes(path: &Path, attrs: u32) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            use ::windows::Win32::Storage::FileSystem::SetFileAttributesW;
            use ::windows::core::PCWSTR;

            SetFileAttributesW(
                PCWSTR(wide_path.as_ptr()),
                ::windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(attrs),
            ).map_err(|e| PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string()
            )))?;
        }

        Ok(())
    }
    
    /// Set hidden attribute
    pub fn set_hidden(path: &Path, hidden: bool) -> Result<()> {
        let current = get_attributes(path)?;
        let new_attrs = if hidden {
            current | FILE_ATTRIBUTE_HIDDEN
        } else {
            current & !FILE_ATTRIBUTE_HIDDEN
        };
        set_attributes(path, new_attrs)
    }
    
    /// Check if file is hidden
    pub fn is_hidden(path: &Path) -> Result<bool> {
        let attrs = get_attributes(path)?;
        Ok(attrs & FILE_ATTRIBUTE_HIDDEN != 0)
    }
    
    /// Set system attribute
    pub fn set_system(path: &Path, system: bool) -> Result<()> {
        let current = get_attributes(path)?;
        let new_attrs = if system {
            current | FILE_ATTRIBUTE_SYSTEM
        } else {
            current & !FILE_ATTRIBUTE_SYSTEM
        };
        set_attributes(path, new_attrs)
    }
    
    /// Set folder icon via desktop.ini
    pub fn set_folder_icon(path: &Path, icon_path: &Path, icon_index: i32) -> Result<()> {
        if !path.is_dir() {
            return Err(PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path is not a directory"
            )));
        }
        
        // Create desktop.ini content
        let content = format!(
            "[.ShellClassInfo]\r\nIconResource={},{}\r\n",
            icon_path.display(),
            icon_index
        );
        
        let desktop_ini = path.join("desktop.ini");
        
        // Make sure we can write to it (remove hidden/system if exists)
        if desktop_ini.exists() {
            let _ = set_attributes(&desktop_ini, FILE_ATTRIBUTE_ARCHIVE);
        }
        
        fs::write(&desktop_ini, content)?;
        
        // Set desktop.ini attributes: hidden and system
        set_attributes(&desktop_ini, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)?;
        
        // Mark folder as having custom settings
        let folder_attrs = get_attributes(path)?;
        // FILE_ATTRIBUTE_READONLY tells Explorer to read desktop.ini
        set_attributes(path, folder_attrs | FILE_ATTRIBUTE_READONLY)?;
        
        Ok(())
    }
    
    /// Set folder color (Windows doesn't natively support this, but we can use icons)
    pub fn set_folder_color(path: &Path, color: &str) -> Result<()> {
        // Windows doesn't have native folder colors like macOS/Linux
        // We could use custom icons or leave it as not supported
        // For now, we'll just log and return success
        tracing::info!("Folder colors not natively supported on Windows, using icon workaround");
        
        // You could extend this to use a set of colored folder icons
        // stored in a known location
        Err(PlatformError::NotSupported)
    }
    
    /// Get NTFS alternate data stream
    pub fn get_ads(path: &Path, stream_name: &str) -> Result<Vec<u8>> {
        let ads_path = format!("{}:{}", path.display(), stream_name);
        let content = fs::read(&ads_path)?;
        Ok(content)
    }
    
    /// Set NTFS alternate data stream
    pub fn set_ads(path: &Path, stream_name: &str, data: &[u8]) -> Result<()> {
        let ads_path = format!("{}:{}", path.display(), stream_name);
        fs::write(&ads_path, data)?;
        Ok(())
    }
    
    /// Delete NTFS alternate data stream
    pub fn delete_ads(path: &Path, stream_name: &str) -> Result<()> {
        let ads_path = format!("{}:{}", path.display(), stream_name);
        fs::remove_file(&ads_path)?;
        Ok(())
    }
}

// ============================================================================
// Cross-platform abstractions
// ============================================================================

/// Cross-platform file attributes
#[derive(Debug, Clone, Default)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,  // Windows only
    pub archive: bool, // Windows only
}

impl FileAttributes {
    /// Get attributes for a path
    pub fn get(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path)?;
            let mode = metadata.permissions().mode();
            let name = path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            
            Ok(Self {
                readonly: mode & 0o222 == 0,  // No write bits
                hidden: name.starts_with('.'),
                system: false,
                archive: false,
            })
        }
        
        #[cfg(windows)]
        {
            let attrs = win::get_attributes(path)?;
            Ok(Self {
                readonly: attrs & win::FILE_ATTRIBUTE_READONLY != 0,
                hidden: attrs & win::FILE_ATTRIBUTE_HIDDEN != 0,
                system: attrs & win::FILE_ATTRIBUTE_SYSTEM != 0,
                archive: attrs & win::FILE_ATTRIBUTE_ARCHIVE != 0,
            })
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self::default())
        }
    }
    
    /// Apply attributes to a path
    pub fn apply(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            
            let metadata = std::fs::metadata(path)?;
            let mut mode = metadata.permissions().mode();
            
            if self.readonly {
                mode &= !0o222;  // Remove write bits
            } else {
                mode |= 0o200;  // Add owner write
            }
            
            let permissions = Permissions::from_mode(mode);
            std::fs::set_permissions(path, permissions)?;
            
            // Handle hidden on Unix (rename with dot prefix)
            // This is destructive so we skip it here
            // Would need to be handled at a higher level
        }
        
        #[cfg(windows)]
        {
            let mut attrs = 0u32;
            if self.readonly { attrs |= win::FILE_ATTRIBUTE_READONLY; }
            if self.hidden { attrs |= win::FILE_ATTRIBUTE_HIDDEN; }
            if self.system { attrs |= win::FILE_ATTRIBUTE_SYSTEM; }
            if self.archive { attrs |= win::FILE_ATTRIBUTE_ARCHIVE; }

            win::set_attributes(path, attrs)?;
        }
        
        Ok(())
    }
}

/// Set folder appearance (color/icon) in a cross-platform way
pub fn set_folder_appearance(path: &Path, color: Option<&str>, icon: Option<&Path>) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(c) = color {
            unix::set_folder_color(path, c)?;
        }
        Ok(())
    }
    
    #[cfg(windows)]
    {
        if let Some(icon_path) = icon {
            win::set_folder_icon(path, icon_path, 0)?;
        }
        if color.is_some() {
            // Windows doesn't support native folder colors
            tracing::warn!("Folder colors not supported on Windows");
        }
        Ok(())
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        Err(PlatformError::NotSupported)
    }
}

/// Set file permissions in a cross-platform way
pub fn set_permissions(path: &Path, mode: Option<u32>, attrs: Option<FileAttributes>) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(m) = mode {
            unix::chmod(path, m)?;
        }
    }
    
    #[cfg(windows)]
    {
        // Mode is ignored on Windows
        let _ = mode;
    }
    
    if let Some(a) = attrs {
        a.apply(path)?;
    }
    
    Ok(())
}
