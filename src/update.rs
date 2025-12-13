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

    /// Download URL for the Windows binary
    pub download_url: String,

    /// SHA256 checksum of the Windows binary
    pub checksum: String,

    /// Download URL for the Linux binary
    #[serde(default)]
    pub linux_download_url: Option<String>,

    /// SHA256 checksum of the Linux binary
    #[serde(default)]
    pub linux_checksum: Option<String>,

    /// Release notes (optional)
    pub release_notes: Option<String>,

    /// Minimum required version (for breaking changes)
    pub min_version: Option<String>,
}

impl VersionInfo {
    /// Get the download URL for the current platform
    pub fn platform_download_url(&self) -> &str {
        #[cfg(windows)]
        {
            &self.download_url
        }
        #[cfg(unix)]
        {
            self.linux_download_url.as_deref().unwrap_or(&self.download_url)
        }
    }

    /// Get the checksum for the current platform
    pub fn platform_checksum(&self) -> &str {
        #[cfg(windows)]
        {
            &self.checksum
        }
        #[cfg(unix)]
        {
            self.linux_checksum.as_deref().unwrap_or(&self.checksum)
        }
    }
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
                    // First, check if the current binary's checksum matches the remote
                    // This is more reliable than build numbers since the binary might have been
                    // updated but still have an old build number compiled in
                    if let Ok(current_checksum) = get_current_binary_checksum() {
                        let remote_checksum = remote_version.platform_checksum();
                        if current_checksum == remote_checksum {
                            tracing::debug!("Binary checksum matches remote, already up to date");
                            return UpdateStatus::UpToDate;
                        }
                        tracing::debug!(
                            "Checksum mismatch: local={}, remote={}",
                            &current_checksum[..16],
                            &remote_checksum[..16]
                        );
                    }

                    // Fall back to build number comparison
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

/// Get the SHA256 checksum of the currently running binary
fn get_current_binary_checksum() -> anyhow::Result<String> {
    use sha2::{Sha256, Digest};
    use std::fs;
    use std::env;

    let current_exe = env::current_exe()?;
    let bytes = fs::read(&current_exe)?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Download and apply an update
pub async fn apply_update(version_info: &VersionInfo) -> anyhow::Result<()> {
    use std::env;
    use std::fs;

    let download_url = version_info.platform_download_url();
    let expected_checksum = version_info.platform_checksum();

    tracing::info!("Downloading update from {}", download_url);

    // Download the new binary
    let response = reqwest::get(download_url).await?;
    let bytes = response.bytes().await?;

    // Verify checksum
    let actual_checksum = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        format!("{:x}", hasher.finalize())
    };

    if actual_checksum != expected_checksum {
        anyhow::bail!(
            "Checksum mismatch: expected {}, got {}",
            expected_checksum,
            actual_checksum
        );
    }

    tracing::info!("Checksum verified, applying update...");

    // Get current executable path
    let current_exe = env::current_exe()?;
    let exe_dir = current_exe.parent()
        .ok_or_else(|| anyhow::anyhow!("Could not get executable directory"))?;

    // Create backup with platform-appropriate name
    #[cfg(windows)]
    let backup_path = exe_dir.join("ufm.exe.bak");
    #[cfg(unix)]
    let backup_path = exe_dir.join("ufm.bak");

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

/// Check for updates on startup and auto-apply if running as daemon
pub async fn check_on_startup(config: &UpdateConfig, auto_apply: bool) {
    if !config.enabled {
        return;
    }

    // Only check if enough time has passed since last check
    if !should_check_now(config) {
        tracing::debug!("Skipping startup update check (checked recently)");
        return;
    }

    tracing::info!("Checking for updates...");

    match check_for_update(config).await {
        UpdateStatus::UpToDate => {
            tracing::info!("UFM is up to date");
        }
        UpdateStatus::UpdateAvailable(info) => {
            tracing::warn!(
                "Update available: v{} (build {})",
                info.version,
                info.build
            );
            if let Some(notes) = &info.release_notes {
                tracing::info!("Release notes: {}", notes);
            }

            // Auto-apply if requested (daemon mode)
            if auto_apply {
                tracing::info!("Auto-applying update...");
                match apply_update(&info).await {
                    Ok(()) => {
                        tracing::info!("Update applied! Restarting...");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        restart_self();
                    }
                    Err(e) => {
                        tracing::error!("Auto-update failed: {}", e);
                    }
                }
            } else {
                tracing::info!("Run 'ufm --update' to install.");
            }
        }
        UpdateStatus::CheckFailed(err) => {
            tracing::debug!("Update check failed: {}", err);
        }
    }

    record_update_check();
}

/// Spawn a background task that periodically checks for updates
pub fn spawn_update_checker(config: UpdateConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Wait a bit before first check to let the app start up
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        loop {
            // Check if it's time to check for updates
            if should_check_now(&config) {
                tracing::debug!("Running periodic update check");

                match check_for_update(&config).await {
                    UpdateStatus::UpToDate => {
                        tracing::debug!("Periodic check: UFM is up to date");
                    }
                    UpdateStatus::UpdateAvailable(info) => {
                        tracing::warn!(
                            "Update available: v{} (build {}). Run 'ufm --update' or restart to auto-update.",
                            info.version,
                            info.build
                        );

                        // Auto-apply update in daemon mode
                        #[cfg(unix)]
                        {
                            tracing::info!("Auto-applying update...");
                            match apply_update(&info).await {
                                Ok(()) => {
                                    tracing::info!("Update applied! Restarting...");
                                    // Give a moment for logs to flush
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    // Restart the process
                                    restart_self();
                                }
                                Err(e) => {
                                    tracing::error!("Auto-update failed: {}", e);
                                }
                            }
                        }
                    }
                    UpdateStatus::CheckFailed(err) => {
                        tracing::debug!("Periodic update check failed: {}", err);
                    }
                }

                record_update_check();
            }

            // Sleep for an hour, then check again if interval has passed
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    })
}

/// Restart the current process
/// On Linux with systemd, we exit and let systemd restart us with the new binary
/// Using exec() doesn't work because Linux caches the old binary in memory
#[cfg(unix)]
fn restart_self() {
    tracing::info!("Exiting for restart (systemd will restart with new binary)");
    // Exit with code 0 - systemd's Restart=on-failure will restart us
    // Actually use exit code 42 as a "restart requested" signal
    std::process::exit(0);
}

#[cfg(windows)]
fn restart_self() {
    // On Windows, we can't easily replace ourselves while running
    // The update script handles this
    tracing::info!("Please restart UFM to complete the update");
}
