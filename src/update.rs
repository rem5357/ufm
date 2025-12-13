//! Auto-update functionality for UFM
//!
//! Checks for updates from a configured server and can self-update.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Update server configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Base URL for update server (e.g., "http://goldshire:8080/ufm")
    pub server_url: String,

    /// Whether auto-update is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Check interval in hours (0 = manual only)
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u32,
}

fn default_true() -> bool {
    true
}

fn default_check_interval() -> u32 {
    24 // Check daily
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            server_url: "http://goldshire:8080/ufm".to_string(),
            enabled: true,
            check_interval_hours: 24,
        }
    }
}

/// Version information from the update server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Latest version string
    pub version: String,

    /// Build number
    pub build: u32,

    /// Download URL for the binary
    pub download_url: String,

    /// SHA256 checksum of the binary
    pub checksum: String,

    /// Release notes (optional)
    pub release_notes: Option<String>,

    /// Minimum required version (for breaking changes)
    pub min_version: Option<String>,
}

/// Update check result
#[derive(Clone, Debug)]
pub enum UpdateStatus {
    /// Current version is up to date
    UpToDate,

    /// Update available
    UpdateAvailable(VersionInfo),

    /// Could not check for updates
    CheckFailed(String),
}

/// Check for available updates
pub async fn check_for_update(config: &UpdateConfig) -> UpdateStatus {
    if !config.enabled {
        return UpdateStatus::UpToDate;
    }

    let version_url = format!("{}/version.json", config.server_url);

    match reqwest::get(&version_url).await {
        Ok(response) => {
            match response.json::<VersionInfo>().await {
                Ok(remote_version) => {
                    let current_version = env!("CARGO_PKG_VERSION");
                    let current_build: u32 = env!("UFM_BUILD_NUMBER")
                        .parse()
                        .unwrap_or(0);

                    // Compare versions
                    if remote_version.build > current_build {
                        UpdateStatus::UpdateAvailable(remote_version)
                    } else {
                        UpdateStatus::UpToDate
                    }
                }
                Err(e) => UpdateStatus::CheckFailed(format!("Failed to parse version info: {}", e)),
            }
        }
        Err(e) => UpdateStatus::CheckFailed(format!("Failed to connect to update server: {}", e)),
    }
}

/// Download and apply an update
pub async fn apply_update(version_info: &VersionInfo) -> anyhow::Result<()> {
    use std::env;
    use std::fs;

    tracing::info!("Downloading update from {}", version_info.download_url);

    // Download the new binary
    let response = reqwest::get(&version_info.download_url).await?;
    let bytes = response.bytes().await?;

    // Verify checksum
    let actual_checksum = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        format!("{:x}", hasher.finalize())
    };

    if actual_checksum != version_info.checksum {
        anyhow::bail!(
            "Checksum mismatch: expected {}, got {}",
            version_info.checksum,
            actual_checksum
        );
    }

    tracing::info!("Checksum verified, applying update...");

    // Get current executable path
    let current_exe = env::current_exe()?;
    let exe_dir = current_exe.parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get executable directory"))?;

    // Create backup
    let backup_path = exe_dir.join("ufm.exe.bak");
    if current_exe.exists() {
        fs::copy(&current_exe, &backup_path)?;
        tracing::info!("Created backup at {}", backup_path.display());
    }

    // On Windows, we can't replace a running executable directly
    // We need to use a helper script or schedule the replacement
    #[cfg(windows)]
    {
        // Write new binary to a temporary location
        let new_exe_path = exe_dir.join("ufm_new.exe");
        fs::write(&new_exe_path, &bytes)?;

        // Create a batch script to replace the executable after we exit
        let update_script = exe_dir.join("update.bat");
        let script_content = format!(
            r#"@echo off
timeout /t 2 /nobreak >nul
move /y "{}" "{}"
del "{}"
del "%~f0"
"#,
            new_exe_path.display(),
            current_exe.display(),
            backup_path.display()
        );
        fs::write(&update_script, script_content)?;

        tracing::info!("Update prepared. Restart UFM to complete the update.");
        tracing::info!("Run the update script manually if automatic update fails: {}", update_script.display());

        // Try to run the script detached
        std::process::Command::new("cmd")
            .args(["/C", "start", "/B", update_script.to_string_lossy().as_ref()])
            .spawn()
            .ok();
    }

    #[cfg(unix)]
    {
        // On Unix, we can replace the executable directly if we have permissions
        let new_exe_path = exe_dir.join("ufm_new");
        fs::write(&new_exe_path, &bytes)?;

        // Set executable permission
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&new_exe_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&new_exe_path, perms)?;
        }

        // Atomic replace
        fs::rename(&new_exe_path, &current_exe)?;
        tracing::info!("Update applied successfully. Restart UFM to use the new version.");
    }

    Ok(())
}

/// Get the last update check time
pub fn get_last_check_time() -> Option<std::time::SystemTime> {
    let check_file = get_update_state_path();
    check_file.metadata().ok().and_then(|m| m.modified().ok())
}

/// Record that we checked for updates
pub fn record_update_check() {
    let check_file = get_update_state_path();
    if let Some(parent) = check_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&check_file, chrono::Utc::now().to_rfc3339());
}

/// Should we check for updates now?
pub fn should_check_now(config: &UpdateConfig) -> bool {
    if !config.enabled || config.check_interval_hours == 0 {
        return false;
    }

    let last_check = get_last_check_time();
    match last_check {
        Some(time) => {
            let elapsed = time.elapsed().unwrap_or_default();
            let interval = std::time::Duration::from_secs(
                config.check_interval_hours as u64 * 3600
            );
            elapsed >= interval
        }
        None => true, // Never checked before
    }
}

fn get_update_state_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ufm")
        .join("last_update_check")
}
