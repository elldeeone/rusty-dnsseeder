mod checkversion;
mod config;
mod dns;
mod dnsseed;
mod grpc;
mod logging;
mod manager;
mod netadapter;
mod profiling;
mod types;
mod version;

use crate::checkversion::check_version;
use crate::config::{log_paths, set_active_config, set_peers_default_port};
use crate::dns::DnsServer;
use crate::manager::Manager;
use crate::netadapter::{DnsseedNetAdapter, Routes};
use crate::types::NetAddress;
use kaspa_p2p_lib::common::DEFAULT_TIMEOUT;
use kaspa_p2p_lib::pb::RequestAddressesMessage;
use kaspa_p2p_lib::pb::kaspad_message::Payload;
use kaspa_p2p_lib::{KaspadMessagePayloadType, make_message};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;
use tokio::time::Duration;

static SYSTEM_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static DEFAULT_SEEDER: Lazy<parking_lot::Mutex<Option<NetAddress>>> =
    Lazy::new(|| parking_lot::Mutex::new(None));

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cfg = config::load_config()?;
    let (log_file, err_log_file) = log_paths(&cfg);
    logging::init(cfg.no_log_files, &cfg.log_level, &log_file, &err_log_file)?;
    info!("Version {}", version::version());

    let profile_server: Option<profiling::ProfileServer> = if !cfg.profile.is_empty() {
        match profiling::start(&cfg.profile).await {
            Ok(server) => Some(server),
            Err(err) => {
                error!("Failed to start profile server on {}: {}", cfg.profile, err);
                None
            }
        }
    } else {
        None
    };

    set_active_config(cfg.clone())?;
    let default_port: u16 = cfg
        .network
        .active_net_params
        .default_port
        .parse()
        .map_err(|e| {
            format!(
                "Invalid peers default port {}: {}",
                cfg.network.active_net_params.default_port, e
            )
        })?;
    set_peers_default_port(default_port);

    let manager = Manager::new(&cfg.app_dir)?;
    let manager_handle = manager.start_background();

    let mut disable_creep = false;
    if !cfg.known_peers.is_empty() {
        match parse_known_peers(&cfg.known_peers) {
            Ok(peers) => {
                manager.add_addresses(&peers);
                for peer in peers {
                    manager.attempt(&peer);
                    manager.good(&peer, None, None);
                }
            }
            Err(err) => {
                error!("{}", err);
                disable_creep = true;
            }
        }
    }

    if !cfg.seeder.is_empty() {
        match resolve_seeder(&cfg.seeder, default_port).await {
            Ok(Some(addr)) => {
                manager.add_addresses(std::slice::from_ref(&addr));
                *DEFAULT_SEEDER.lock() = Some(addr);
            }
            Ok(None) => {}
            Err(err) => {
                error!("{}", err);
                return Ok(());
            }
        }
    }

    let cfg_arc = Arc::new(cfg);
    let net_adapters: Vec<Arc<DnsseedNetAdapter>> = (0..cfg_arc.threads)
        .map(|_| Arc::new(DnsseedNetAdapter::new(cfg_arc.clone()).expect("netadapter init")))
        .collect();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let creep_handle = if disable_creep {
        None
    } else {
        let manager = manager.clone();
        let cfg = cfg_arc.clone();
        let adapters = net_adapters.clone();
        Some(tokio::spawn(async move {
            creep(manager, cfg, adapters, shutdown_rx).await;
        }))
    };

    let dns_handle = {
        let server = Arc::new(DnsServer::new(
            &cfg_arc.host,
            &cfg_arc.nameserver,
            &cfg_arc.listen,
            manager.clone(),
        ));
        let rx = shutdown_tx.subscribe();
        tokio::spawn(async move { server.start(rx).await })
    };

    let grpc_server = grpc::start(manager.clone(), &cfg_arc.grpc_listen).await?;

    wait_for_shutdown_signal().await;

    info!("Gracefully shutting down the seeder...");
    SYSTEM_SHUTDOWN.store(true, Ordering::Relaxed);
    let _ = shutdown_tx.send(true);
    manager.shutdown().await;
    if let Some(server) = profile_server {
        server.stop().await;
    }
    grpc_server.stop().await;
    if let Some(handle) = creep_handle {
        let _ = handle.await;
    }
    let _ = dns_handle.await;
    let _ = manager_handle.await;
    info!("Seeder shutdown complete");
    Ok(())
}

async fn creep(
    manager: Arc<Manager>,
    cfg: Arc<config::Config>,
    adapters: Vec<Arc<DnsseedNetAdapter>>,
    shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }

        let mut peers = manager.addresses();
        if peers.is_empty() && manager.address_count() == 0 {
            dnsseed::seed_from_dns(&cfg, None, true, None, manager.clone()).await;
            peers = manager.addresses();
        }

        if peers.is_empty() {
            debug!("No stale addresses");
            for _ in 0..10 {
                if *shutdown.borrow() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        let mut handles = Vec::new();
        for (i, addr) in peers.into_iter().enumerate() {
            if *shutdown.borrow() {
                return;
            }
            let adapter = adapters[i % adapters.len()].clone();
            let manager = manager.clone();
            let cfg = cfg.clone();
            handles.push(tokio::spawn(async move {
                if let Err(err) = poll_peer(&adapter, &manager, &cfg, &addr).await {
                    debug!("{}", err);
                    if is_default_seeder(&addr) {
                        error!("failed to poll default seeder");
                        std::process::exit(1);
                    }
                }
            }));
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
}

async fn poll_peer(
    adapter: &DnsseedNetAdapter,
    manager: &Manager,
    cfg: &config::Config,
    addr: &NetAddress,
) -> Result<(), String> {
    manager.attempt(addr);
    let peer_address = format!("{}:{}", addr.ip, addr.port);
    debug!("Polling peer {}", peer_address);
    let mut routes = adapter.connect(&peer_address).await?;
    let peer_version = routes.peer_version.clone();
    let result = poll_peer_connected(
        &mut routes,
        manager,
        cfg,
        addr,
        &peer_address,
        &peer_version,
    )
    .await;
    routes.disconnect().await;
    result
}

async fn poll_peer_connected(
    routes: &mut Routes,
    manager: &Manager,
    cfg: &config::Config,
    addr: &NetAddress,
    peer_address: &str,
    peer_version: &kaspa_p2p_lib::pb::VersionMessage,
) -> Result<(), String> {
    if cfg.min_proto_ver > 0 && peer_version.protocol_version < cfg.min_proto_ver as u32 {
        return Err(format!(
            "Peer {} ({}) protocol version {} is below minimum: {}",
            peer_address,
            peer_version.user_agent.as_str(),
            peer_version.protocol_version,
            cfg.min_proto_ver
        ));
    }

    let request = make_message!(
        Payload::RequestAddresses,
        RequestAddressesMessage {
            include_all_subnetworks: true,
            subnetwork_id: None,
        }
    );
    routes.enqueue(request).await.map_err(|e| e.to_string())?;
    let message = routes
        .wait_for_message(KaspadMessagePayloadType::Addresses, DEFAULT_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    let addresses_msg = match message.payload {
        Some(Payload::Addresses(a)) => a,
        _ => return Err("failed to receive addresses".to_string()),
    };

    let mut addrs = Vec::new();
    for addr in addresses_msg.address_list {
        if let Some(net_addr) = proto_to_net_address(&addr) {
            addrs.push(net_addr);
        }
    }

    let added = manager.add_addresses(&addrs);
    info!(
        "Peer {} ({}) sent {} addresses, {} new",
        peer_address,
        peer_version.user_agent.as_str(),
        addrs.len(),
        added
    );

    if !cfg.min_ua_ver.is_empty() {
        check_version(&cfg.min_ua_ver, &peer_version.user_agent).map_err(|_| {
            format!(
                "Peer {} version {} doesn't satisfy minimum: {}",
                peer_address,
                peer_version.user_agent.as_str(),
                cfg.min_ua_ver
            )
        })?;
    }
    manager.good(addr, Some(peer_version.user_agent.clone()), None);
    Ok(())
}

fn proto_to_net_address(addr: &kaspa_p2p_lib::pb::NetAddress) -> Option<NetAddress> {
    if addr.port > u16::MAX as u32 {
        return None;
    }
    let ip = match addr.ip.len() {
        4 => IpAddr::V4(std::net::Ipv4Addr::new(
            addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3],
        )),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr.ip);
            let ipv6 = Ipv6Addr::from(octets);
            match ipv6.to_ipv4() {
                Some(ipv4) => IpAddr::V4(ipv4),
                None => IpAddr::V6(ipv6),
            }
        }
        _ => return None,
    };
    Some(NetAddress::with_timestamp(
        ip,
        addr.port as u16,
        addr.timestamp,
    ))
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_known_peers(peers: &str) -> Result<Vec<NetAddress>, String> {
    let mut out = Vec::new();
    for raw in peers.split(',') {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid peer address: {}; addresses should be in format \"IP\":\"port\"",
                raw
            ));
        }
        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| format!("Invalid peer IP address: {}", parts[0]))?;
        let port: i64 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid peer port: {}", parts[1]))?;
        out.push(NetAddress::new(ip, port as u16));
    }
    Ok(out)
}

fn split_host_port(input: &str) -> Result<Option<(String, u16)>, String> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = match rest.find(']') {
            Some(end) => end,
            None => return Ok(None),
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if let Some(port_str) = after.strip_prefix(':') {
            let port = port_str
                .parse::<i64>()
                .map_err(|_| format!("Invalid seeder port: {}", port_str))?;
            return Ok(Some((host.to_string(), port as u16)));
        }
        return Ok(None);
    }

    if input.matches(':').count() == 1 {
        let (host, port_str) = match input.rsplit_once(':') {
            Some(value) => value,
            None => return Ok(None),
        };
        let port = port_str
            .parse::<i64>()
            .map_err(|_| format!("Invalid seeder port: {}", port_str))?;
        return Ok(Some((host.to_string(), port as u16)));
    }
    Ok(None)
}

async fn resolve_seeder(seeder: &str, default_port: u16) -> Result<Option<NetAddress>, String> {
    let (host, port) = match split_host_port(seeder)? {
        Some(value) => value,
        None => (seeder.to_string(), default_port),
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Some(NetAddress::new(ip, port)));
    }

    match lookup_host(&host).await {
        Ok(ip) => Ok(Some(NetAddress::new(ip, port))),
        Err(err) => {
            warn!("Failed to resolve seed host: {}, {}, ignoring", host, err);
            Ok(None)
        }
    }
}

async fn lookup_host(host: &str) -> Result<IpAddr, String> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:0", host);
        let mut addrs = addr.to_socket_addrs().map_err(|e| e.to_string())?;
        addrs
            .next()
            .map(|a| a.ip())
            .ok_or_else(|| "no addresses".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

fn is_default_seeder(addr: &NetAddress) -> bool {
    if let Some(default) = DEFAULT_SEEDER.lock().as_ref() {
        default.ip == addr.ip && default.port == addr.port
    } else {
        false
    }
}
