//! Peer Discovery
//!
//! Automatic discovery of UFM peers via mDNS and bootstrap nodes.
//!
//! On Linux, we use avahi-publish for service registration (more reliable with avahi-daemon)
//! and mdns_sd for browsing. On other platforms, mdns_sd handles both.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use uuid::Uuid;

use super::config::DiscoveryConfig;
use super::identity::NodeIdentity;
use super::peer::PeerManager;
use super::protocol::{DiscoveredPeer, DiscoverySource, PeerMessage};

/// Check if an IP address is in the Tailscale CGNAT range (100.64.0.0/10)
/// Tailscale uses this range for secure encrypted connections.
/// Range: 100.64.0.0 - 100.127.255.255
fn is_tailscale_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 100.64.0.0/10 means first octet is 100, second octet is 64-127
            octets[0] == 100 && (octets[1] & 0xC0) == 64
        }
        std::net::IpAddr::V6(_) => false, // Tailscale doesn't use IPv6 for CGNAT
    }
}

/// Resolve a hostname via system DNS and return any Tailscale IPs found.
/// This leverages Tailscale's MagicDNS to get the Tailscale IP for a peer.
fn resolve_tailscale_ip(hostname: &str, port: u16) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;

    // Catch any panics during DNS resolution (Windows can be finicky)
    let result = std::panic::catch_unwind(|| {
        // Try various hostname formats that Tailscale DNS might resolve
        let hostnames_to_try = [
            hostname.to_lowercase(),                    // "falcon"
            format!("{}.local", hostname.to_lowercase()), // "falcon.local"
        ];

        for host in &hostnames_to_try {
            let addr_string = format!("{}:{}", host, port);
            if let Ok(addrs) = addr_string.to_socket_addrs() {
                let tailscale_addrs: Vec<SocketAddr> = addrs
                    .filter(|addr| is_tailscale_ip(&addr.ip()))
                    .collect();

                if !tailscale_addrs.is_empty() {
                    return tailscale_addrs;
                }
            }
        }

        Vec::new()
    });

    match result {
        Ok(addrs) => {
            if !addrs.is_empty() {
                tracing::debug!(
                    "DNS: Resolved {} to Tailscale IPs: {:?}",
                    hostname, addrs
                );
            }
            addrs
        }
        Err(_) => {
            tracing::warn!("DNS: Resolution panicked for {}", hostname);
            Vec::new()
        }
    }
}

/// Manages peer discovery via multiple methods
pub struct DiscoveryManager {
    identity: NodeIdentity,
    peer_manager: Arc<PeerManager>,
    config: DiscoveryConfig,
    mdns_daemon: Option<ServiceDaemon>,
    mdns_receiver: Option<mdns_sd::Receiver<ServiceEvent>>,
    /// Child process for avahi-publish on Linux
    #[cfg(target_os = "linux")]
    avahi_process: Option<std::process::Child>,
    /// Child process for dns-sd on Windows
    #[cfg(target_os = "windows")]
    dnssd_process: Option<std::process::Child>,
    running: bool,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new(
        identity: NodeIdentity,
        peer_manager: Arc<PeerManager>,
        config: DiscoveryConfig,
    ) -> Self {
        Self {
            identity,
            peer_manager,
            config,
            mdns_daemon: None,
            mdns_receiver: None,
            #[cfg(target_os = "linux")]
            avahi_process: None,
            #[cfg(target_os = "windows")]
            dnssd_process: None,
            running: false,
        }
    }

    /// Start discovery services
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Ok(());
        }

        self.running = true;

        // Start mDNS if enabled
        if self.config.mdns_enabled {
            self.start_mdns().await?;
        }

        // Start periodic discovery
        self.start_discovery_loop().await;

        Ok(())
    }

    /// Stop discovery services
    pub async fn stop(&mut self) {
        self.running = false;

        if let Some(daemon) = self.mdns_daemon.take() {
            let _ = daemon.shutdown();
        }

        // Kill avahi-publish process on Linux
        #[cfg(target_os = "linux")]
        if let Some(mut child) = self.avahi_process.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::debug!("Stopped avahi-publish process");
        }

        // Kill dns-sd process on Windows
        #[cfg(target_os = "windows")]
        if let Some(mut child) = self.dnssd_process.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::debug!("Stopped dns-sd process");
        }
    }

    /// Start mDNS service
    async fn start_mdns(&mut self) -> anyhow::Result<()> {
        // Clone values to avoid borrow issues
        let service_type = self.config.mdns_service_type.clone();
        let instance_name = self.identity.name.clone();
        let port = 9847u16; // TODO: Get from config

        // On Linux, use avahi-publish for registration (more reliable with avahi-daemon)
        // On Windows, use dns-sd for registration (more reliable with Bonjour)
        // On other platforms, use mdns_sd for both registration and browsing
        #[cfg(target_os = "linux")]
        {
            self.start_avahi_publish(&instance_name, port)?;
        }

        #[cfg(target_os = "windows")]
        {
            self.start_dnssd_register(&instance_name, port)?;
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            self.register_mdns_service(&service_type, &instance_name, port)?;
        }

        // Use mdns_sd for browsing on all platforms
        let daemon = ServiceDaemon::new()?;
        let receiver = daemon.browse(&service_type)?;
        tracing::info!("mDNS browse started for: {}", service_type);

        self.mdns_receiver = Some(receiver);
        self.mdns_daemon = Some(daemon);
        Ok(())
    }

    /// Start avahi-publish process on Linux
    #[cfg(target_os = "linux")]
    fn start_avahi_publish(&mut self, instance_name: &str, port: u16) -> anyhow::Result<()> {
        use std::process::{Command, Stdio};

        // Build TXT record arguments
        let uuid_txt = format!("uuid={}", self.identity.uuid);
        let version_txt = format!("version={}", self.identity.version);
        let os_txt = format!("os={}", self.identity.os);

        // avahi-publish -s <name> <type> <port> [txt records...]
        let child = Command::new("avahi-publish")
            .arg("-s")
            .arg(instance_name)
            .arg("_ufm._tcp")
            .arg(port.to_string())
            .arg(&uuid_txt)
            .arg(&version_txt)
            .arg(&os_txt)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(process) => {
                tracing::info!("mDNS service registered via avahi-publish: {}", instance_name);
                self.avahi_process = Some(process);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "avahi-publish not available ({}), falling back to mdns_sd",
                    e
                );
                // Fall back to mdns_sd registration
                let service_type = self.config.mdns_service_type.clone();
                self.register_mdns_service(&service_type, instance_name, port)
            }
        }
    }

    /// Start dns-sd process on Windows (Bonjour)
    #[cfg(target_os = "windows")]
    fn start_dnssd_register(&mut self, instance_name: &str, port: u16) -> anyhow::Result<()> {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        // Build TXT record arguments for dns-sd
        // dns-sd -R <name> <type> <domain> <port> [<txt>...]
        let uuid_txt = format!("uuid={}", self.identity.uuid);
        let version_txt = format!("version={}", self.identity.version);
        let os_txt = format!("os={}", self.identity.os);

        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let child = Command::new("dns-sd")
            .arg("-R")
            .arg(instance_name)
            .arg("_ufm._tcp")
            .arg("local")
            .arg(port.to_string())
            .arg(&uuid_txt)
            .arg(&version_txt)
            .arg(&os_txt)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();

        match child {
            Ok(process) => {
                tracing::info!("mDNS service registered via dns-sd: {}", instance_name);
                self.dnssd_process = Some(process);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "dns-sd not available ({}), falling back to mdns_sd",
                    e
                );
                // Fall back to mdns_sd registration
                let service_type = self.config.mdns_service_type.clone();
                self.register_mdns_service(&service_type, instance_name, port)
            }
        }
    }

    /// Register service using mdns_sd (used on macOS or as fallback)
    fn register_mdns_service(&mut self, service_type: &str, instance_name: &str, port: u16) -> anyhow::Result<()> {
        let daemon = ServiceDaemon::new()?;

        let mut properties = HashMap::new();
        properties.insert("uuid".to_string(), self.identity.uuid.to_string());
        properties.insert("version".to_string(), self.identity.version.clone());
        properties.insert("os".to_string(), self.identity.os.clone());

        // Get the actual hostname for mDNS
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| instance_name.to_string());
        let host_fullname = format!("{}.local.", hostname);

        tracing::debug!(
            "mDNS: Registering service type={} instance={} host={}",
            service_type, instance_name, host_fullname
        );

        let service = ServiceInfo::new(
            service_type,
            instance_name,
            &host_fullname,
            "",  // Empty to auto-detect IP addresses
            port,
            properties,
        )?;

        daemon.register(service)?;
        tracing::info!("mDNS service registered: {}", instance_name);

        // Store daemon - it will be replaced when we create the browse receiver
        self.mdns_daemon = Some(daemon);
        Ok(())
    }

    /// Start the periodic discovery loop
    async fn start_discovery_loop(&self) {
        let peer_manager = self.peer_manager.clone();
        let config = self.config.clone();
        let identity = self.identity.clone();
        #[cfg(not(target_os = "windows"))]
        let mdns_receiver = self.mdns_receiver.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.discovery_interval());

            loop {
                interval.tick().await;

                // mDNS discovery
                // On Windows, use dns-sd command (Bonjour)
                // On other platforms, use mdns_sd receiver
                #[cfg(target_os = "windows")]
                {
                    if config.mdns_enabled {
                        if let Ok(peers) = discover_dnssd_browse(&identity).await {
                            for peer in peers {
                                peer_manager.add_discovered_peer(peer).await;
                            }
                        }
                    }
                }

                #[cfg(not(target_os = "windows"))]
                {
                    if let Some(ref receiver) = mdns_receiver {
                        if let Ok(peers) = collect_mdns_peers(receiver, &identity).await {
                            for peer in peers {
                                peer_manager.add_discovered_peer(peer).await;
                            }
                        }
                    }
                }

                // Bootstrap discovery
                if !config.bootstrap_nodes.is_empty() {
                    if let Ok(peers) = discover_bootstrap(&config.bootstrap_nodes, &identity).await {
                        for peer in peers {
                            peer_manager.add_discovered_peer(peer).await;
                        }
                    }
                }
            }
        });
    }

    /// Trigger immediate discovery
    pub async fn discover_now(&self) -> Vec<DiscoveredPeer> {
        let mut all_peers = Vec::new();

        // mDNS discovery
        // On Windows, use dns-sd command (Bonjour)
        // On other platforms, use mdns_sd receiver
        #[cfg(target_os = "windows")]
        {
            if self.config.mdns_enabled {
                if let Ok(peers) = discover_dnssd_browse(&self.identity).await {
                    all_peers.extend(peers);
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref receiver) = self.mdns_receiver {
                if let Ok(peers) = collect_mdns_peers(receiver, &self.identity).await {
                    all_peers.extend(peers);
                }
            }
        }

        // Bootstrap
        if !self.config.bootstrap_nodes.is_empty() {
            if let Ok(peers) = discover_bootstrap(&self.config.bootstrap_nodes, &self.identity).await {
                all_peers.extend(peers);
            }
        }

        // Add to peer manager
        for peer in &all_peers {
            self.peer_manager.add_discovered_peer(peer.clone()).await;
        }

        all_peers
    }
}

/// Collect peers from an existing mDNS receiver (non-blocking drain)
async fn collect_mdns_peers(
    receiver: &mdns_sd::Receiver<ServiceEvent>,
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    let mut peers = Vec::new();

    // Drain any pending events from the receiver (non-blocking)
    // We use try_recv to avoid blocking, collecting what's available
    let timeout = Duration::from_secs(3);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(100), async {
            // Use a blocking task for the sync receiver
            tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(Duration::from_millis(50))
            })
            .await
        })
        .await
        {
            Ok(Ok(Ok(event))) => {
                // Log all mDNS events for debugging
                match &event {
                    ServiceEvent::SearchStarted(stype) => {
                        tracing::debug!("mDNS: Search started for {}", stype);
                    }
                    ServiceEvent::ServiceFound(stype, name) => {
                        tracing::info!("mDNS: Service found - {} ({})", name, stype);
                    }
                    ServiceEvent::ServiceResolved(info) => {
                        tracing::info!(
                            "mDNS: Service resolved - {} at {:?}",
                            info.get_fullname(),
                            info.get_addresses()
                        );
                    }
                    ServiceEvent::ServiceRemoved(stype, name) => {
                        tracing::debug!("mDNS: Service removed - {} ({})", name, stype);
                    }
                    ServiceEvent::SearchStopped(stype) => {
                        tracing::debug!("mDNS: Search stopped for {}", stype);
                    }
                }

                if let ServiceEvent::ServiceResolved(info) = event {
                    // Skip ourselves
                    let uuid_str = info
                        .get_property_val_str("uuid")
                        .unwrap_or_default();

                    if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                        if uuid == our_identity.uuid {
                            tracing::debug!("mDNS: Skipping self ({})", uuid);
                            continue;
                        }

                        // Get all addresses from mDNS
                        let all_addresses: Vec<_> = info.get_addresses().iter().collect();

                        // Filter to only Tailscale IPs (100.64.0.0/10 CGNAT range)
                        let addresses: Vec<SocketAddr> = all_addresses
                            .iter()
                            .filter(|ip| is_tailscale_ip(ip))
                            .map(|ip| SocketAddr::new(**ip, info.get_port()))
                            .collect();

                        let name = info.get_fullname().split('.').next()
                            .unwrap_or("unknown").to_string();

                        // If we have Tailscale IPs from mDNS, use them
                        let final_addresses = if !addresses.is_empty() {
                            tracing::info!(
                                "mDNS: Discovered peer {} ({}) at {:?} (filtered from {:?})",
                                name, uuid, addresses, all_addresses
                            );
                            addresses
                        } else {
                            // No Tailscale IPs in mDNS - try DNS resolution (Tailscale MagicDNS)
                            tracing::debug!(
                                "mDNS: No Tailscale IPs for {} in mDNS, trying DNS resolution",
                                name
                            );
                            let dns_addresses = resolve_tailscale_ip(&name, info.get_port());
                            if !dns_addresses.is_empty() {
                                tracing::info!(
                                    "mDNS: Discovered peer {} ({}) at {:?} via Tailscale DNS (mDNS had: {:?})",
                                    name, uuid, dns_addresses, all_addresses
                                );
                                dns_addresses
                            } else {
                                tracing::warn!(
                                    "mDNS: Service {} has no Tailscale IPs (mDNS: {:?}, DNS: none)",
                                    name, all_addresses
                                );
                                Vec::new()
                            }
                        };

                        if !final_addresses.is_empty() {
                            peers.push(DiscoveredPeer {
                                name,
                                uuid: Some(uuid),
                                addresses: final_addresses,
                                version: info
                                    .get_property_val_str("version")
                                    .map(|s| s.to_string()),
                                os: info.get_property_val_str("os").map(|s| s.to_string()),
                                source: DiscoverySource::Mdns,
                            });
                        }
                    } else {
                        tracing::warn!(
                            "mDNS: Could not parse UUID '{}' from {}",
                            uuid_str, info.get_fullname()
                        );
                    }
                }
            }
            _ => {
                // Timeout or other non-event - this is normal
                continue;
            }
        }
    }

    Ok(peers)
}

/// Discover peers via bootstrap nodes
async fn discover_bootstrap(
    bootstrap_nodes: &[SocketAddr],
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    let mut all_peers = Vec::new();

    for addr in bootstrap_nodes {
        match query_bootstrap(*addr, our_identity).await {
            Ok(peers) => {
                tracing::debug!("Got {} peers from bootstrap {}", peers.len(), addr);
                all_peers.extend(peers);
            }
            Err(e) => {
                tracing::debug!("Bootstrap {} unreachable: {}", addr, e);
            }
        }
    }

    // Deduplicate by UUID
    all_peers.sort_by_key(|p| p.uuid);
    all_peers.dedup_by_key(|p| p.uuid);

    Ok(all_peers)
}

/// Query a single bootstrap node
async fn query_bootstrap(
    addr: SocketAddr,
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
    use tokio::net::TcpStream;

    let timeout = Duration::from_secs(5);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
    stream.set_nodelay(true)?;

    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // Send discovery request
    let request = PeerMessage::DiscoveryRequest {
        requester: our_identity.clone(),
    };
    let data = request.encode()?;
    writer.write_all(&data).await?;
    writer.flush().await?;

    // Read response
    use super::protocol::FrameHeader;

    let mut header_buf = [0u8; FrameHeader::SIZE];
    tokio::time::timeout(timeout, reader.read_exact(&mut header_buf)).await??;
    let header = FrameHeader::parse(&header_buf)?;

    let mut payload = vec![0u8; header.length as usize];
    tokio::time::timeout(timeout, reader.read_exact(&mut payload)).await??;
    let response = PeerMessage::decode(&payload)?;

    match response {
        PeerMessage::DiscoveryResponse { peers } => Ok(peers),
        _ => anyhow::bail!("Unexpected response from bootstrap"),
    }
}

/// Discover peers using dns-sd command on Windows (Bonjour)
#[cfg(target_os = "windows")]
async fn discover_dnssd_browse(
    our_identity: &NodeIdentity,
) -> anyhow::Result<Vec<DiscoveredPeer>> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut peers = Vec::new();

    // Step 1: Browse for services using dns-sd -B
    // Output format: "Timestamp     A/R Flags if Domain   Service Type   Instance Name"
    let browse_output = tokio::task::spawn_blocking(|| {
        let child = Command::new("dns-sd")
            .args(["-B", "_ufm._tcp", "local", "-timeout", "3"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();

        match child {
            Ok(mut process) => {
                // dns-sd -B runs forever, so we need to kill it after a timeout
                std::thread::sleep(std::time::Duration::from_secs(3));
                let _ = process.kill();

                if let Some(stdout) = process.stdout.take() {
                    let reader = BufReader::new(stdout);
                    let instances: Vec<String> = reader
                        .lines()
                        .filter_map(|line| line.ok())
                        .filter_map(|line| {
                            // Parse lines like:
                            // "21:03:11.607  Add     2 13 local.   _ufm._tcp.   goldshire"
                            if line.contains("Add") && line.contains("_ufm._tcp") {
                                // Instance name is the last field
                                line.split_whitespace().last().map(|s| s.to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    Ok(instances)
                } else {
                    Ok(Vec::new())
                }
            }
            Err(e) => Err(anyhow::anyhow!("Failed to run dns-sd: {}", e)),
        }
    })
    .await??;

    tracing::debug!("dns-sd browse found {} instances", browse_output.len());

    // Step 2: Lookup each instance to get details
    for instance_name in browse_output {
        // Skip ourselves
        if instance_name.eq_ignore_ascii_case(&our_identity.name) {
            continue;
        }

        if let Ok(peer) = lookup_dnssd_service(&instance_name, our_identity).await {
            tracing::info!(
                "mDNS: Discovered peer {} ({}) via dns-sd at {:?}",
                peer.name,
                peer.uuid.map(|u| u.to_string()).unwrap_or_default(),
                peer.addresses
            );
            peers.push(peer);
        }
    }

    Ok(peers)
}

/// Lookup a specific service instance using dns-sd -L on Windows
#[cfg(target_os = "windows")]
async fn lookup_dnssd_service(
    instance_name: &str,
    _our_identity: &NodeIdentity,
) -> anyhow::Result<DiscoveredPeer> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::os::windows::process::CommandExt;
    use std::net::ToSocketAddrs;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let instance = instance_name.to_string();

    let lookup_result = tokio::task::spawn_blocking(move || {
        let child = Command::new("dns-sd")
            .args(["-L", &instance, "_ufm._tcp", "local"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();

        match child {
            Ok(mut process) => {
                // dns-sd -L runs forever, so we need to kill it after getting data
                std::thread::sleep(std::time::Duration::from_secs(2));
                let _ = process.kill();

                let mut hostname = String::new();
                let mut port: u16 = 9847;
                let mut uuid: Option<Uuid> = None;
                let mut version: Option<String> = None;
                let mut os: Option<String> = None;

                if let Some(stdout) = process.stdout.take() {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().filter_map(|l| l.ok()) {
                        // Parse lines like:
                        // "goldshire._ufm._tcp.local. can be reached at goldshire.local.:9847 (interface 13)"
                        // " uuid=68790f29-fe0c-4994-9fef-0a39725e4ace version=0.50.0 os=linux"

                        if line.contains("can be reached at") {
                            // Extract hostname and port
                            if let Some(at_pos) = line.find("can be reached at ") {
                                let rest = &line[at_pos + 18..];
                                if let Some(paren_pos) = rest.find(" (") {
                                    let host_port = &rest[..paren_pos];
                                    if let Some(colon_pos) = host_port.rfind(':') {
                                        hostname = host_port[..colon_pos].to_string();
                                        if let Ok(p) = host_port[colon_pos + 1..].parse() {
                                            port = p;
                                        }
                                    }
                                }
                            }
                        }

                        // Parse TXT records
                        if line.trim().starts_with("uuid=") || line.contains(" uuid=") {
                            for part in line.split_whitespace() {
                                if let Some(val) = part.strip_prefix("uuid=") {
                                    uuid = Uuid::parse_str(val).ok();
                                } else if let Some(val) = part.strip_prefix("version=") {
                                    version = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("os=") {
                                    os = Some(val.to_string());
                                }
                            }
                        }
                    }
                }

                Ok((instance, hostname, port, uuid, version, os))
            }
            Err(e) => Err(anyhow::anyhow!("Failed to run dns-sd -L: {}", e)),
        }
    })
    .await??;

    let (instance_name, hostname, port, uuid, version, os) = lookup_result;

    // Resolve hostname to IP address
    let mut all_addresses: Vec<SocketAddr> = Vec::new();
    if !hostname.is_empty() {
        let host_port = format!("{}:{}", hostname.trim_end_matches('.'), port);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            all_addresses = addrs.collect();
        }

        // If hostname resolution failed, try without the .local suffix
        if all_addresses.is_empty() {
            let clean_host = hostname.trim_end_matches('.').trim_end_matches(".local");
            let host_port = format!("{}:{}", clean_host, port);
            if let Ok(addrs) = host_port.to_socket_addrs() {
                all_addresses = addrs.collect();
            }
        }
    }

    // Filter to only Tailscale IPs (100.64.0.0/10 CGNAT range)
    let mut addresses: Vec<SocketAddr> = all_addresses
        .iter()
        .filter(|addr| is_tailscale_ip(&addr.ip()))
        .copied()
        .collect();

    // If no Tailscale IPs found, try DNS resolution (Tailscale MagicDNS)
    if addresses.is_empty() && !all_addresses.is_empty() {
        tracing::debug!(
            "dns-sd: No Tailscale IPs for {} in resolution, trying Tailscale DNS",
            instance_name
        );
        addresses = resolve_tailscale_ip(&instance_name, port);
        if !addresses.is_empty() {
            tracing::info!(
                "dns-sd: Resolved {} to {:?} via Tailscale DNS (original: {:?})",
                instance_name, addresses, all_addresses
            );
        }
    }

    if addresses.is_empty() {
        if all_addresses.is_empty() {
            anyhow::bail!("Could not resolve address for {}", instance_name);
        } else {
            anyhow::bail!(
                "No Tailscale IPs found for {} (had: {:?}, DNS: none)",
                instance_name, all_addresses
            );
        }
    }

    tracing::debug!(
        "dns-sd: Resolved {} to {:?} (filtered from {:?})",
        instance_name, addresses, all_addresses
    );

    Ok(DiscoveredPeer {
        name: instance_name,
        uuid,
        addresses,
        version,
        os,
        source: DiscoverySource::Mdns,
    })
}
