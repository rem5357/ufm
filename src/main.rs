//! UFM - Universal File Manager
//!
//! A cross-platform MCP server for file management operations with P2P networking.
//!
//! UFM runs as a single process that handles:
//! - MCP requests via stdio (for Claude Desktop)
//! - MCP requests via HTTP (localhost:9847/mcp)
//! - P2P connections from other UFM nodes (port 9847)
//!
//! Usage:
//!   ufm                    # Start UFM (all features enabled)
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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::mcp::{run_stdio_server, JsonRpcRequest, JsonRpcResponse, McpServerHandler};
use crate::network::{NetworkConfig, NetworkService};
use crate::security::SecurityPolicy;
use crate::tools::UfmServer;

/// Build number from BUILD file
const BUILD_NUMBER: &str = env!("UFM_BUILD_NUMBER");

/// Full version string including build number
fn full_version() -> String {
    format!("{} (build {})", env!("CARGO_PKG_VERSION"), BUILD_NUMBER)
}

/// Command line arguments (simplified)
#[derive(Parser, Debug)]
#[command(name = "ufm")]
#[command(author = "Robert")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Universal File Manager - Cross-platform MCP file management with P2P networking")]
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

    /// Restart the UFM systemd service (Linux only)
    #[arg(long)]
    restart: bool,

    /// Stop the UFM systemd service (Linux only)
    #[arg(long)]
    stop: bool,

    /// Show status of the UFM systemd service (Linux only)
    #[arg(long)]
    status: bool,

    /// Disable stdio MCP (useful when running as a service)
    #[arg(long)]
    no_stdio: bool,
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

    /// Network settings
    #[serde(default)]
    network: NetworkSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NetworkSettings {
    /// Bootstrap nodes for P2P discovery (e.g., ["192.168.1.100:9847"])
    #[serde(default)]
    bootstrap_nodes: Vec<String>,

    /// Only allow P2P connections from Tailscale network
    #[serde(default = "default_true")]
    tailscale_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityConfig {
    /// Allowed root directories (empty = user's home directory)
    #[serde(default, alias = "allowed_paths")]
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
            network: NetworkSettings::default(),
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

/// Handle systemd service control commands (Linux only)
#[cfg(target_os = "linux")]
fn handle_service_command(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let service_name = "ufm";

    if args.status {
        let status = Command::new("systemctl")
            .args(["status", service_name, "--no-pager"])
            .status()?;
        if !status.success() {
            // systemctl status returns non-zero if service isn't running
        }
        return Ok(());
    }

    if args.stop {
        println!("Stopping UFM service...");
        let status = Command::new("sudo")
            .args(["systemctl", "stop", service_name])
            .status()?;
        if status.success() {
            println!("UFM service stopped.");
        } else {
            eprintln!("Failed to stop UFM service. Try running with sudo.");
        }
        return Ok(());
    }

    if args.restart {
        println!("Restarting UFM service...");
        let status = Command::new("sudo")
            .args(["systemctl", "restart", service_name])
            .status()?;
        if status.success() {
            println!("UFM service restarted.");
            let _ = Command::new("systemctl")
                .args(["status", service_name, "--no-pager", "-n", "5"])
                .status();
        } else {
            eprintln!("Failed to restart UFM service. Try running with sudo.");
        }
        return Ok(());
    }

    Ok(())
}

// ============================================================================
// HTTP MCP Server
// ============================================================================

/// Shared state for HTTP server
struct HttpState {
    handler: Arc<UfmServer>,
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": full_version()
    }))
}

/// MCP endpoint - handles JSON-RPC requests
async fn mcp_handler(
    State(state): State<Arc<HttpState>>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = request.id.clone().unwrap_or(Value::Null);

    let response = match request.method.as_str() {
        "initialize" => {
            let result = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": state.handler.capabilities(),
                "serverInfo": state.handler.server_info(),
                "instructions": state.handler.instructions()
            });
            JsonRpcResponse::success(id, result)
        }
        "tools/list" => {
            let result = json!({
                "tools": state.handler.list_tools()
            });
            JsonRpcResponse::success(id, result)
        }
        "tools/call" => {
            let params = request.params.unwrap_or(json!({}));
            let name = params["name"].as_str().unwrap_or("");
            let arguments = params["arguments"].clone();

            let tool_result = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                state.handler.call_tool(name, arguments),
            )
            .await;

            match tool_result {
                Ok(result) => {
                    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or(json!({})))
                }
                Err(_) => JsonRpcResponse::success(
                    id,
                    serde_json::to_value(mcp::CallToolResult::error(format!(
                        "Tool '{}' timed out after 60 seconds",
                        name
                    )))
                    .unwrap_or(json!({})),
                ),
            }
        }
        "ping" => JsonRpcResponse::success(id, json!({})),
        _ => JsonRpcResponse::error(
            id,
            -32601,
            &format!("Method not found: {}", request.method),
        ),
    };

    Json(response)
}

/// Create the HTTP router
fn create_http_router(handler: Arc<UfmServer>) -> Router {
    let state = Arc::new(HttpState { handler });

    Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/mcp", post(mcp_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ============================================================================
// Main
// ============================================================================

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
                println!(
                    "Update available: v{} (build {})",
                    info.version, info.build
                );
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
                println!(
                    "Downloading update: v{} (build {})",
                    info.version, info.build
                );
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

    // Handle service control commands (Linux only)
    #[cfg(target_os = "linux")]
    {
        if args.restart || args.stop || args.status {
            return handle_service_command(&args);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if args.restart || args.stop || args.status {
            eprintln!(
                "Service commands (--restart, --stop, --status) are only available on Linux."
            );
            return Ok(());
        }
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

    if let Some(ref log_path) = config.logging.file {
        use tracing_subscriber::fmt::writer::MakeWriterExt;

        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

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
                    .with_ansi(false),
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

    // Create the UFM server with P2P networking (always enabled)
    let policy = config.to_security_policy();

    tracing::info!("Initializing P2P networking on port {}", args.port);

    let mut network_config = NetworkConfig::default();
    network_config.enabled = true;
    network_config.listen_port = args.port;
    network_config.security.tailscale_only = config.network.tailscale_only;

    if network_config.security.tailscale_only {
        tracing::info!(
            "Tailscale-only mode enabled - will only accept connections from Tailscale network"
        );
    }

    // Load bootstrap nodes from config
    for node_str in &config.network.bootstrap_nodes {
        match node_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                network_config.discovery.bootstrap_nodes.push(addr);
                tracing::info!("Added bootstrap node: {}", addr);
            }
            Err(e) => {
                tracing::warn!("Invalid bootstrap node '{}': {}", node_str, e);
            }
        }
    }

    // Use custom node name if provided
    if let Some(ref name) = args.node_name {
        tracing::info!("Using custom node name: {}", name);
    }

    let network_service = match NetworkService::new(network_config).await {
        Ok(service) => {
            if let Err(e) = service.start().await {
                tracing::error!("Failed to start network service: {}", e);
                return Err(e.into());
            }
            tracing::info!(
                "P2P network started - Node: {} ({})",
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

    let ufm_server = UfmServer::with_network(
        policy,
        config.name.clone(),
        config.version.clone(),
        BUILD_NUMBER.to_string(),
        network_service.clone(),
    );

    // Wire up the tool executor for handling incoming remote tool requests
    if let Some(ref network) = ufm_server.state.network {
        network
            .peers
            .set_tool_executor(ufm_server.tool_executor())
            .await;
        tracing::debug!("Tool executor wired up for remote tool requests");
    }

    // Check for updates on startup
    let update_config = update::UpdateConfig::default();
    update::check_on_startup(&update_config, args.no_stdio).await;

    // Spawn background update checker
    let _update_handle = update::spawn_update_checker(update_config);

    // Create shared server handle
    let ufm_server = Arc::new(ufm_server);

    // Start HTTP server for MCP requests
    let http_router = create_http_router(ufm_server.clone());
    let http_addr: SocketAddr = format!("127.0.0.1:{}", args.port).parse()?;

    tracing::info!("Starting HTTP MCP server on http://{}", http_addr);

    let http_server = axum::serve(
        tokio::net::TcpListener::bind(http_addr).await?,
        http_router,
    );

    // Print startup message to stderr (stdout is reserved for MCP JSON-RPC)
    let node_name = ufm_server
        .state
        .network
        .as_ref()
        .map(|n| n.identity.name.as_str())
        .unwrap_or("unknown");

    eprintln!("UFM v{} started", full_version());
    eprintln!("  Node: {}", node_name);
    eprintln!("  P2P:  port {}", args.port);
    eprintln!("  HTTP: http://127.0.0.1:{}/mcp", args.port);
    if !args.no_stdio {
        eprintln!("  MCP:  stdio (for Claude Desktop)");
    }
    eprintln!();

    if args.no_stdio {
        // Service mode: just run HTTP + P2P, no stdio
        tracing::info!("Running in service mode (no stdio)");

        tokio::select! {
            result = http_server => {
                if let Err(e) = result {
                    tracing::error!("HTTP server error: {}", e);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutdown signal received");
            }
        }
    } else {
        // Full mode: run HTTP + P2P + stdio MCP
        tracing::info!("UFM ready, accepting MCP connections via stdio and HTTP");

        // Clone for the stdio task
        let stdio_server = ufm_server.clone();

        tokio::select! {
            result = http_server => {
                if let Err(e) = result {
                    tracing::error!("HTTP server error: {}", e);
                }
            }
            result = run_stdio_server(stdio_server) => {
                if let Err(e) = result {
                    tracing::error!("Stdio MCP server error: {}", e);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutdown signal received");
            }
        }
    }

    tracing::info!("UFM shutting down");
    Ok(())
}
