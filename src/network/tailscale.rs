//! Tailscale network integration
//!
//! Provides functions to detect Tailscale IPs and ensure network operations
//! only happen over Tailscale connections for security.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io::{self, ErrorKind};
use tokio::net::{TcpListener, TcpStream};

/// Tailscale CGNAT address range: 100.64.0.0/10
const TAILSCALE_CGNAT_START: u32 = 0x64400000; // 100.64.0.0
const TAILSCALE_CGNAT_END: u32 = 0x67FFFFFF;   // 100.127.255.255

/// Check if an IP address is within Tailscale's CGNAT range
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let ip_u32 = u32::from(v4);
            ip_u32 >= TAILSCALE_CGNAT_START && ip_u32 <= TAILSCALE_CGNAT_END
        }
        IpAddr::V6(_) => false,
    }
}

/// Get the local Tailscale IP address
pub fn get_tailscale_ip() -> Option<IpAddr> {
    // Try to get from Tailscale CLI first (most reliable)
    if let Some(ip) = get_tailscale_ip_from_cli() {
        return Some(ip);
    }

    // Fall back to scanning interfaces
    get_tailscale_ip_from_interfaces()
}

fn get_tailscale_ip_from_cli() -> Option<IpAddr> {
    let output = std::process::Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let ip_str = String::from_utf8_lossy(&output.stdout);
    ip_str.trim().parse().ok()
}

fn get_tailscale_ip_from_interfaces() -> Option<IpAddr> {
    #[cfg(unix)]
    {
        use std::process::Command;

        // Try tailscale0 interface first (Linux)
        let output = Command::new("ip")
            .args(["addr", "show", "tailscale0"])
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_str = parts[1].split('/').next()?;
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            if is_tailscale_ip(ip) {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;

        // On Windows, scan all interfaces for Tailscale IP
        let output = Command::new("ipconfig").output().ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.contains("IPv4") || line.contains("IP Address") {
                    if let Some(ip_part) = line.split(':').nth(1) {
                        if let Ok(ip) = ip_part.trim().parse::<IpAddr>() {
                            if is_tailscale_ip(ip) {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Bind a TCP listener to the Tailscale interface only
pub async fn bind_tailscale_only(port: u16) -> io::Result<TcpListener> {
    let tailscale_ip = get_tailscale_ip().ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            "Tailscale IP not found. Is Tailscale running and connected?",
        )
    })?;

    let addr = SocketAddr::new(tailscale_ip, port);
    tracing::info!("Binding to Tailscale interface: {}", addr);
    TcpListener::bind(addr).await
}

/// Connect to a remote address, verifying it's a Tailscale address
pub async fn connect_tailscale_only(addr: SocketAddr) -> io::Result<TcpStream> {
    if !is_tailscale_ip(addr.ip()) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Connection to {} denied: not a Tailscale address", addr.ip()),
        ));
    }

    TcpStream::connect(addr).await
}

/// Verify that an incoming connection is from a Tailscale address
pub fn verify_tailscale_source(peer_addr: SocketAddr) -> io::Result<()> {
    if !is_tailscale_ip(peer_addr.ip()) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Connection from {} rejected: not a Tailscale address", peer_addr.ip()),
        ));
    }
    Ok(())
}

/// Check Tailscale connection status
pub fn check_tailscale_status() -> TailscaleStatus {
    let output = match std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return TailscaleStatus::NotInstalled,
    };

    if !output.status.success() {
        return TailscaleStatus::NotRunning;
    }

    let status: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(s) => s,
        Err(_) => return TailscaleStatus::Error("Failed to parse status".into()),
    };

    match status.get("BackendState").and_then(|s| s.as_str()) {
        Some("Running") => TailscaleStatus::Connected,
        Some("NeedsLogin") => TailscaleStatus::NeedsLogin,
        Some("Stopped") => TailscaleStatus::NotRunning,
        Some(other) => TailscaleStatus::Error(format!("Unknown state: {}", other)),
        None => TailscaleStatus::Error("No backend state".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleStatus {
    Connected,
    NotInstalled,
    NotRunning,
    NeedsLogin,
    Error(String),
}

impl TailscaleStatus {
    pub fn is_connected(&self) -> bool {
        matches!(self, TailscaleStatus::Connected)
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            TailscaleStatus::Connected => None,
            TailscaleStatus::NotInstalled => Some("Tailscale is not installed"),
            TailscaleStatus::NotRunning => Some("Tailscale daemon is not running"),
            TailscaleStatus::NeedsLogin => Some("Tailscale requires login"),
            TailscaleStatus::Error(msg) => Some(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailscale_ip_detection() {
        // Valid Tailscale IPs
        assert!(is_tailscale_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailscale_ip("100.100.50.25".parse().unwrap()));
        assert!(is_tailscale_ip("100.102.6.85".parse().unwrap()));
        assert!(is_tailscale_ip("100.127.255.254".parse().unwrap()));

        // Invalid - outside Tailscale range
        assert!(!is_tailscale_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_tailscale_ip("100.128.0.0".parse().unwrap()));
        assert!(!is_tailscale_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_tailscale_ip("192.168.86.35".parse().unwrap()));
        assert!(!is_tailscale_ip("10.0.0.1".parse().unwrap()));
    }
}
