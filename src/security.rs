//! Security module for UFM
//! 
//! Handles path sandboxing, permission validation, and security policies.
//! This is critical - we don't want MCP clients accessing arbitrary system files.

use std::path::{Path, PathBuf};
use std::collections::HashSet;
use thiserror::Error;
use normpath::PathExt;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Path '{0}' is outside allowed roots")]
    PathOutsideSandbox(PathBuf),
    
    #[error("Path '{0}' is explicitly denied")]
    PathDenied(PathBuf),
    
    #[error("Operation '{0}' not permitted on path '{1}'")]
    OperationDenied(String, PathBuf),
    
    #[error("Path traversal attempt detected: '{0}'")]
    PathTraversal(String),
    
    #[error("Failed to canonicalize path: {0}")]
    CanonicalizationFailed(#[from] std::io::Error),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Security policy for file operations
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Allowed root directories - all access must be within these
    allowed_roots: Vec<PathBuf>,
    
    /// Explicitly denied paths (even if within allowed roots)
    denied_paths: HashSet<PathBuf>,
    
    /// Denied path patterns (glob-style)
    denied_patterns: Vec<String>,
    
    /// Whether to allow write operations
    allow_writes: bool,
    
    /// Whether to allow delete operations
    allow_deletes: bool,
    
    /// Whether to allow permission changes
    allow_chmod: bool,
    
    /// Whether to follow symlinks (security risk if true)
    follow_symlinks: bool,
    
    /// Maximum file size for read operations (prevents memory exhaustion)
    max_read_size: u64,
    
    /// Maximum directory depth for recursive operations
    max_recursion_depth: u32,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_roots: Vec::new(),
            denied_paths: HashSet::new(),
            denied_patterns: Self::default_denied_patterns(),
            allow_writes: true,
            allow_deletes: true,
            allow_chmod: true,
            follow_symlinks: false,  // Safe default
            max_read_size: 100 * 1024 * 1024,  // 100MB default
            max_recursion_depth: 50,
        }
    }
}

impl SecurityPolicy {
    /// Create a new security policy with specified allowed roots
    pub fn new(allowed_roots: Vec<PathBuf>) -> Self {
        Self {
            allowed_roots,
            ..Default::default()
        }
    }
    
    /// Create a permissive policy (for trusted environments)
    /// Still blocks system-critical paths
    pub fn permissive() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            allowed_roots: vec![home],
            ..Default::default()
        }
    }
    
    /// Create a restrictive policy for a specific directory
    pub fn sandboxed(root: PathBuf) -> Self {
        Self {
            allowed_roots: vec![root],
            allow_chmod: false,
            follow_symlinks: false,
            ..Default::default()
        }
    }
    
    /// Default patterns that should always be denied
    fn default_denied_patterns() -> Vec<String> {
        vec![
            // Unix system directories
            "/etc/shadow".to_string(),
            "/etc/passwd".to_string(),
            "/etc/sudoers*".to_string(),
            "/root/.ssh/*".to_string(),
            "**/.ssh/id_*".to_string(),
            "**/.gnupg/*".to_string(),
            
            // Windows system
            "C:\\Windows\\System32\\config\\*".to_string(),
            "**/ntuser.dat*".to_string(),
            
            // Common sensitive files
            "**/.env".to_string(),
            "**/.env.*".to_string(),
            "**/credentials*".to_string(),
            "**/secrets*".to_string(),
            "**/*.pem".to_string(),
            "**/*.key".to_string(),
            "**/id_rsa*".to_string(),
            "**/id_ed25519*".to_string(),
        ]
    }
    
    /// Add an allowed root directory
    pub fn add_allowed_root(&mut self, root: PathBuf) {
        self.allowed_roots.push(root);
    }
    
    /// Add a denied path
    pub fn add_denied_path(&mut self, path: PathBuf) {
        self.denied_paths.insert(path);
    }
    
    /// Add a denied pattern
    pub fn add_denied_pattern(&mut self, pattern: String) {
        self.denied_patterns.push(pattern);
    }
    
    /// Set write permission
    pub fn set_allow_writes(&mut self, allow: bool) {
        self.allow_writes = allow;
    }
    
    /// Set delete permission
    pub fn set_allow_deletes(&mut self, allow: bool) {
        self.allow_deletes = allow;
    }
    
    /// Validate that a path is safe to access
    pub fn validate_path(&self, path: &Path) -> Result<PathBuf, SecurityError> {
        // First, normalize the path to prevent traversal attacks
        let normalized = self.normalize_path(path)?;
        
        // Check if path is within allowed roots
        if !self.is_within_allowed_roots(&normalized) {
            return Err(SecurityError::PathOutsideSandbox(normalized));
        }
        
        // Check explicit denials
        if self.denied_paths.contains(&normalized) {
            return Err(SecurityError::PathDenied(normalized));
        }
        
        // Check denied patterns
        if self.matches_denied_pattern(&normalized) {
            return Err(SecurityError::PathDenied(normalized));
        }
        
        Ok(normalized)
    }
    
    /// Validate a path for write operations
    pub fn validate_write(&self, path: &Path) -> Result<PathBuf, SecurityError> {
        if !self.allow_writes {
            return Err(SecurityError::OperationDenied(
                "write".to_string(),
                path.to_path_buf(),
            ));
        }
        self.validate_path(path)
    }
    
    /// Validate a path for delete operations
    pub fn validate_delete(&self, path: &Path) -> Result<PathBuf, SecurityError> {
        if !self.allow_deletes {
            return Err(SecurityError::OperationDenied(
                "delete".to_string(),
                path.to_path_buf(),
            ));
        }
        self.validate_path(path)
    }
    
    /// Validate a path for chmod operations
    pub fn validate_chmod(&self, path: &Path) -> Result<PathBuf, SecurityError> {
        if !self.allow_chmod {
            return Err(SecurityError::OperationDenied(
                "chmod".to_string(),
                path.to_path_buf(),
            ));
        }
        self.validate_path(path)
    }
    
    /// Normalize a path, resolving any .. or . components safely
    fn normalize_path(&self, path: &Path) -> Result<PathBuf, SecurityError> {
        // Check for obvious traversal attempts before normalization
        let path_str = path.to_string_lossy();
        if path_str.contains("..") {
            // We'll still try to normalize, but flag it
            tracing::warn!("Path contains '..': {}", path_str);
        }
        
        // Try to normalize the path
        // If the path exists, we can canonicalize it
        if path.exists() {
            if self.follow_symlinks {
                path.canonicalize().map_err(SecurityError::CanonicalizationFailed)
            } else {
                // Normalize without following symlinks
                path.normalize()
                    .map(|p| p.into_path_buf())
                    .map_err(|e| SecurityError::InvalidPath(e.to_string()))
            }
        } else {
            // For non-existent paths, normalize what we can
            // and ensure parent exists and is valid
            let parent = path.parent().ok_or_else(|| {
                SecurityError::InvalidPath("Path has no parent".to_string())
            })?;
            
            if parent.exists() {
                let normalized_parent = if self.follow_symlinks {
                    parent.canonicalize()?
                } else {
                    parent.normalize()
                        .map(|p| p.into_path_buf())
                        .map_err(|e| SecurityError::InvalidPath(e.to_string()))?
                };
                
                let filename = path.file_name().ok_or_else(|| {
                    SecurityError::InvalidPath("Path has no filename".to_string())
                })?;
                
                Ok(normalized_parent.join(filename))
            } else {
                // Neither path nor parent exists - just clean up the path
                Ok(clean_path(path))
            }
        }
    }
    
    /// Check if path is within any allowed root
    fn is_within_allowed_roots(&self, path: &Path) -> bool {
        if self.allowed_roots.is_empty() {
            // No roots specified = nothing allowed
            return false;
        }
        
        self.allowed_roots.iter().any(|root| {
            path.starts_with(root)
        })
    }
    
    /// Check if path matches any denied pattern
    fn matches_denied_pattern(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        for pattern in &self.denied_patterns {
            if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                if glob_pattern.matches(&path_str) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Get maximum read size
    pub fn max_read_size(&self) -> u64 {
        self.max_read_size
    }
    
    /// Get maximum recursion depth
    pub fn max_recursion_depth(&self) -> u32 {
        self.max_recursion_depth
    }
    
    /// Check if symlinks should be followed
    pub fn follow_symlinks(&self) -> bool {
        self.follow_symlinks
    }
}

/// Clean a path without filesystem access
fn clean_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Go up if we can
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::CurDir => {
                // Skip current dir
            }
            _ => {
                components.push(component);
            }
        }
    }
    
    components.iter().collect()
}

/// Helper to get common safe directories
pub mod safe_dirs {
    use std::path::PathBuf;
    
    pub fn home() -> Option<PathBuf> {
        dirs::home_dir()
    }
    
    pub fn documents() -> Option<PathBuf> {
        dirs::document_dir()
    }
    
    pub fn downloads() -> Option<PathBuf> {
        dirs::download_dir()
    }
    
    pub fn desktop() -> Option<PathBuf> {
        dirs::desktop_dir()
    }
    
    pub fn pictures() -> Option<PathBuf> {
        dirs::picture_dir()
    }
    
    pub fn music() -> Option<PathBuf> {
        dirs::audio_dir()
    }
    
    pub fn videos() -> Option<PathBuf> {
        dirs::video_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    #[test]
    fn test_sandboxed_policy() {
        let temp = tempdir().unwrap();
        let policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        
        // Should allow paths within sandbox
        let valid_path = temp.path().join("test.txt");
        fs::write(&valid_path, "test").unwrap();
        assert!(policy.validate_path(&valid_path).is_ok());
        
        // Should deny paths outside sandbox
        let outside_path = PathBuf::from("/etc/passwd");
        assert!(policy.validate_path(&outside_path).is_err());
    }
    
    #[test]
    fn test_path_traversal_blocked() {
        let temp = tempdir().unwrap();
        let policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        
        // Attempt traversal
        let traversal_path = temp.path().join("subdir").join("..").join("..").join("etc").join("passwd");
        assert!(policy.validate_path(&traversal_path).is_err());
    }
    
    #[test]
    fn test_denied_patterns() {
        let temp = tempdir().unwrap();
        let mut policy = SecurityPolicy::sandboxed(temp.path().to_path_buf());
        
        // Create a .env file
        let env_file = temp.path().join(".env");
        fs::write(&env_file, "SECRET=value").unwrap();
        
        // Should be denied by default pattern
        assert!(policy.validate_path(&env_file).is_err());
    }
}
