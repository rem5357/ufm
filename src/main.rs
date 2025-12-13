//! UFM - Universal File Manager
//!
//! A cross-platform MCP server for file management operations.
//!
//! Usage:
//!   ufm                    # Start with default config
//!   ufm --config path.toml # Start with custom config
//!   ufm --init             # Generate default config file
//!   ufm --help             # Show help

mod archive;
mod crawler;
mod mcp;
mod network;
mod operations;
mod platform;
mod security;
mod tools;
mod update;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::mcp::run_stdio_server;
use crate::network::{NetworkConfig, NetworkService};
use crate::security::SecurityPolicy;
use crate::tools::UfmServer;

/// Build number from BUILD file
const BUILD_NUMBER: &str = env!("UFM_BUILD_NUMBER");

/// Full version string including build number
fn full_version() -> String {
    format!("{} (build {})", env!("CARGO_PKG_VERSION"), BUILD_NUMBER)
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "ufm")]
#[command(author = "Robert")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Universal File Manager - Cross-platform MCP file management")]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Generate a default configuration file
    #[arg(long)]
    init: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Enable P2P networking for cross-machine file operations
    #[arg(long)]
    network: bool,

    /// P2P listen port (default: 9847)
    #[arg(long, default_value = "9847")]
    port: u16,

    /// Custom node name for P2P network (defaults to hostname)
    #[arg(long)]
    node_name: Option<String>,

    /// Check for updates and exit
    #[arg(long)]
    check_update: bool,

    /// Download and apply available update
    #[arg(long)]
    update: bool,

    /// Run as a daemon (P2P network only, no MCP server)
    /// Use this on headless servers that don't run Claude Desktop
    #[arg(long)]
    daemon: bool,
}

/// Configuration for UFM
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// Server name shown to MCP clients
    #[serde(default = "default_name")]
    name: String,

    /// Server version
    #[serde(default = "default_version")]
    version: String,

    /// Security settings
    #[serde(default)]
    security: SecurityConfig,

    /// Logging settings
    #[serde(default)]
    logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityConfig {
    /// Allowed root directories (empty = user's home directory)
    #[serde(default)]
    allowed_roots: Vec<PathBuf>,

    /// Explicitly denied paths
    #[serde(default)]
    denied_paths: Vec<PathBuf>,

    /// Denied path patterns (glob)
    #[serde(default)]
    denied_patterns: Vec<String>,

    /// Allow write operations
    #[serde(default = "default_true")]
    allow_writes: bool,

    /// Allow delete operations
    #[serde(default = "default_true")]
    allow_deletes: bool,

    /// Allow permission changes
    #[serde(default = "default_true")]
    allow_chmod: bool,

    /// Maximum file size to read (bytes)
    #[serde(default = "default_max_read_size")]
    max_read_size: u64,

    /// Maximum recursion depth
    #[serde(default = "default_max_depth")]
    max_recursion_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    #[serde(default = "default_log_level")]
    level: String,

    /// Log to file
    #[serde(default)]
    file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_roots: Vec::new(),
            denied_paths: Vec::new(),
            denied_patterns: Vec::new(),
            allow_writes: true,
            allow_deletes: true,
            allow_chmod: true,
            max_read_size: default_max_read_size(),
            max_recursion_depth: default_max_depth(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: default_name(),
            version: default_version(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

fn default_name() -> String {
    "UFM".to_string()
}
fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
fn default_true() -> bool {
    true
}
fn default_max_read_size() -> u64 {
    100 * 1024 * 1024
} // 100MB
fn default_max_depth() -> u32 {
    50
}
fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Load configuration from file
    fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    fn save(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Convert to security policy
    fn to_security_policy(&self) -> SecurityPolicy {
        let mut policy = if self.security.allowed_roots.is_empty() {
            SecurityPolicy::permissive()
        } else {
            SecurityPolicy::new(self.security.allowed_roots.clone())
        };

        for path in &self.security.denied_paths {
            policy.add_denied_path(path.clone());
        }

        for pattern in &self.security.denied_patterns {
            policy.add_denied_pattern(pattern.clone());
        }

        policy.set_allow_writes(self.security.allow_writes);
        policy.set_allow_deletes(self.security.allow_deletes);

        policy
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Handle --init flag
    if args.init {
        let config_path = PathBuf::from("ufm.toml");
        let config = Config::default();
        config.save(&config_path)?;
        println!(
            "Created default configuration at: {}",
            config_path.display()
        );
        println!("\nEdit this file to customize allowed directories and security settings.");
        return Ok(());
    }

    // Handle --check-update flag
    if args.check_update {
        println!("UFM v{}", full_version());
        println!("Checking for updates...");
        let update_config = update::UpdateConfig::default();
        match update::check_for_update(&update_config).await {
            update::UpdateStatus::UpToDate => {
                println!("You are running the latest version.");
            }
            update::UpdateStatus::UpdateAvailable(info) => {
                println!("Update available: v{} (build {})", info.version, info.build);
                if let Some(notes) = &info.release_notes {
                    println!("Release notes: {}", notes);
                }
                println!("\nRun 'ufm --update' to download and install the update.");
            }
            update::UpdateStatus::CheckFailed(err) => {
                eprintln!("Failed to check for updates: {}", err);
            }
        }
        return Ok(());
    }

    // Handle --update flag
    if args.update {
        println!("UFM v{}", full_version());
        println!("Checking for updates...");
        let update_config = update::UpdateConfig::default();
        match update::check_for_update(&update_config).await {
            update::UpdateStatus::UpToDate => {
                println!("You are already running the latest version.");
            }
            update::UpdateStatus::UpdateAvailable(info) => {
                println!("Downloading update: v{} (build {})", info.version, info.build);
                match update::apply_update(&info).await {
                    Ok(()) => {
                        println!("Update downloaded successfully!");
                        println!("Please restart UFM to complete the update.");
                    }
                    Err(e) => {
                        eprintln!("Failed to apply update: {}", e);
                        return Err(e.into());
                    }
                }
            }
            update::UpdateStatus::CheckFailed(err) => {
                eprintln!("Failed to check for updates: {}", err);
            }
        }
        return Ok(());
    }

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        Config::load(config_path)?
    } else {
        // Try default locations
        let default_paths = vec![
            PathBuf::from("ufm.toml"),
            dirs::config_dir()
                .map(|p| p.join("ufm").join("config.toml"))
                .unwrap_or_default(),
        ];

        let mut loaded_config = None;
        for path in default_paths {
            if path.exists() {
                match Config::load(&path) {
                    Ok(c) => {
                        loaded_config = Some(c);
                        break;
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to load config from {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
            }
        }

        loaded_config.unwrap_or_default()
    };

    // Initialize logging
    let log_level = if args.verbose {
        "debug"
    } else {
        &config.logging.level
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    // If a log file is configured, write to both stderr and file
    if let Some(ref log_path) = config.logging.file {
        use tracing_subscriber::fmt::writer::MakeWriterExt;

        // Create log directory if needed
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Open log file in append mode
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .expect("Failed to open log file");

        let file_writer = std::sync::Mutex::new(file);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr.and(file_writer))
                    .with_ansi(false) // Disable colors for file output
            )
            .init();

        eprintln!("Logging to: {}", log_path.display());
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
    }

    tracing::info!("Starting UFM v{}", full_version());

    // Create the UFM server
    let policy = config.to_security_policy();

    let ufm_server = if args.network {
        // Initialize P2P networking
        tracing::info!("Initializing P2P networking on port {}", args.port);

        let mut network_config = NetworkConfig::default();
        network_config.enabled = true;
        network_config.listen_port = args.port;

        // Use custom node name if provided
        if let Some(name) = args.node_name {
            // We'll override the identity name after creation
            tracing::info!("Using custom node name: {}", name);
        }

        let network_service = match NetworkService::new(network_config).await {
            Ok(service) => {
                // Start the network service
                if let Err(e) = service.start().await {
                    tracing::error!("Failed to start network service: {}", e);
                    return Err(e.into());
                }
                tracing::info!("P2P network started - Node: {} ({})",
                    service.identity.name,
                    service.identity.uuid
                );
                Arc::new(service)
            }
            Err(e) => {
                tracing::error!("Failed to initialize network: {}", e);
                return Err(e.into());
            }
        };

        UfmServer::with_network(
            policy,
            config.name.clone(),
            config.version.clone(),
            BUILD_NUMBER.to_string(),
            network_service,
        )
    } else {
        UfmServer::new(
            policy,
            config.name.clone(),
            config.version.clone(),
            BUILD_NUMBER.to_string(),
        )
    };

    // Check for updates on startup
    // Auto-apply in daemon mode, just notify in MCP mode
    let update_config = update::UpdateConfig::default();
    update::check_on_startup(&update_config, args.daemon).await;

    // Spawn background update checker (only useful in daemon mode for periodic checks)
    let _update_handle = update::spawn_update_checker(update_config);

    // Daemon mode: run P2P network only, no MCP server
    if args.daemon {
        if !args.network {
            eprintln!("Error: --daemon requires --network flag");
            std::process::exit(1);
        }

        tracing::info!("Running in daemon mode (P2P network only)");
        println!("UFM daemon started - Node: {}",
            ufm_server.state.network.as_ref()
                .map(|n| n.identity.name.as_str())
                .unwrap_or("unknown"));
        println!("Listening for P2P connections on port {}", args.port);
        println!("Press Ctrl+C to stop");

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        tracing::info!("Shutdown signal received, stopping...");
        return Ok(());
    }

    tracing::info!("UFM ready, waiting for MCP client connection...");

    // Run the MCP server
    run_stdio_server(ufm_server).await?;

    Ok(())
}
