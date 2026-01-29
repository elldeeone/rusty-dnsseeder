use crate::config;
use crate::types::{GoTime, NetAddress, SubnetworkID};
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::{Duration, interval};

const DEFAULT_MAX_ADDRESSES: usize = 16;
const DEFAULT_STALE_GOOD_TIMEOUT_SECS: i64 = 60 * 60;
const DEFAULT_STALE_BAD_TIMEOUT_SECS: i64 = 2 * 60 * 60;
const DUMP_ADDRESS_INTERVAL_SECS: u64 = 120;
const PEERS_FILENAME: &str = "nodes.json";
const PRUNE_ADDRESS_INTERVAL_SECS: u64 = 60;
const PRUNE_EXPIRE_TIMEOUT_SECS: i64 = 8 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "Addr")]
    pub addr: NetAddress,
    #[serde(rename = "UserAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "LastAttempt")]
    pub last_attempt: GoTime,
    #[serde(rename = "LastSuccess")]
    pub last_success: GoTime,
    #[serde(rename = "LastSeen")]
    pub last_seen: GoTime,
    #[serde(rename = "SubnetworkID")]
    pub subnetwork_id: Option<SubnetworkID>,
}

pub struct Manager {
    nodes: RwLock<HashMap<String, Node>>,
    peers_file: PathBuf,
    shutdown: tokio::sync::Notify,
}

impl Manager {
    pub fn new(data_dir: &str) -> Result<Arc<Self>, String> {
        let peers_file = Path::new(data_dir).join(PEERS_FILENAME);
        let manager = Arc::new(Manager {
            nodes: RwLock::new(HashMap::new()),
            peers_file,
            shutdown: tokio::sync::Notify::new(),
        });

        if let Err(err) = manager.deserialize_peers() {
            warn!(
                "Failed to parse file {}: {}",
                manager.peers_file.display(),
                err
            );
            if let Err(remove_err) = fs::remove_file(&manager.peers_file) {
                warn!(
                    "Failed to remove corrupt peers file {}: {}",
                    manager.peers_file.display(),
                    remove_err
                );
            }
        }

        Ok(manager)
    }

    pub fn start_background(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.address_handler().await;
        })
    }

    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub fn add_addresses(&self, addrs: &[NetAddress]) -> usize {
        let mut count = 0;
        let mut nodes = self.nodes.write();
        for addr in addrs {
            if addr.port == 0
                || !is_routable(
                    addr,
                    config::active_config()
                        .network
                        .active_net_params
                        .accept_unroutable,
                )
            {
                continue;
            }
            let key = format!("{}_{}", addr.ip, addr.port);
            if let Some(existing) = nodes.get_mut(&key) {
                existing.last_seen = GoTime::now();
                continue;
            }
            let node = Node {
                addr: addr.clone(),
                user_agent: None,
                last_attempt: GoTime::zero(),
                last_success: GoTime::zero(),
                last_seen: GoTime::now(),
                subnetwork_id: None,
            };
            nodes.insert(key, node);
            count += 1;
        }
        count
    }

    pub fn addresses(&self) -> Vec<NetAddress> {
        let max = (config::active_config().threads as usize) * 3;
        let mut addrs = Vec::with_capacity(2000);
        let nodes = self.nodes.read();
        let mut remaining = max;
        for node in nodes.values() {
            if remaining == 0 {
                break;
            }
            if !is_stale(node) {
                continue;
            }
            addrs.push(node.addr.clone());
            remaining -= 1;
        }
        addrs
    }

    pub fn address_count(&self) -> usize {
        self.nodes.read().len()
    }

    pub fn good_addresses(
        &self,
        qtype: hickory_proto::rr::RecordType,
        include_all_subnetworks: bool,
        subnetwork_id: Option<SubnetworkID>,
    ) -> Vec<NetAddress> {
        let mut addrs = Vec::with_capacity(DEFAULT_MAX_ADDRESSES);
        let mut remaining = DEFAULT_MAX_ADDRESSES;

        if qtype != hickory_proto::rr::RecordType::A && qtype != hickory_proto::rr::RecordType::AAAA
        {
            return addrs;
        }

        let nodes = self.nodes.read();
        for node in nodes.values() {
            if remaining == 0 {
                break;
            }
            if !include_all_subnetworks && node.subnetwork_id != subnetwork_id {
                continue;
            }
            let is_ipv4 = matches!(node.addr.ip, IpAddr::V4(_));
            if qtype == hickory_proto::rr::RecordType::A && !is_ipv4 {
                continue;
            }
            if qtype == hickory_proto::rr::RecordType::AAAA && is_ipv4 {
                continue;
            }
            if !is_good(node) {
                continue;
            }
            addrs.push(node.addr.clone());
            remaining -= 1;
        }
        addrs
    }

    pub fn attempt(&self, addr: &NetAddress) {
        let key = format!("{}_{}", addr.ip, addr.port);
        if let Some(node) = self.nodes.write().get_mut(&key) {
            node.last_attempt = GoTime::now();
        }
    }

    pub fn good(
        &self,
        addr: &NetAddress,
        user_agent: Option<String>,
        subnetwork_id: Option<SubnetworkID>,
    ) {
        let key = format!("{}_{}", addr.ip, addr.port);
        if let Some(node) = self.nodes.write().get_mut(&key) {
            node.user_agent = user_agent;
            node.last_success = GoTime::now();
            node.subnetwork_id = subnetwork_id;
        }
    }

    async fn address_handler(self: Arc<Self>) {
        let mut prune_ticker = interval(Duration::from_secs(PRUNE_ADDRESS_INTERVAL_SECS));
        let mut dump_ticker = interval(Duration::from_secs(DUMP_ADDRESS_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = prune_ticker.tick() => {
                    self.prune_peers();
                }
                _ = dump_ticker.tick() => {
                    self.save_peers();
                }
                _ = self.shutdown.notified() => {
                    break;
                }
            }
        }
        info!("Address manager: saving peers");
        self.save_peers();
        info!("Address manager shutdown");
    }

    fn prune_peers(&self) {
        let mut pruned = 0;
        let mut good = 0;
        let mut stale = 0;
        let mut bad = 0;
        let mut ipv4 = 0;
        let mut ipv6 = 0;

        let mut nodes = self.nodes.write();
        let keys: Vec<String> = nodes.keys().cloned().collect();
        for key in keys {
            if let Some(node) = nodes.get(&key) {
                if is_expired(node) {
                    nodes.remove(&key);
                    pruned += 1;
                    continue;
                }
                if is_good(node) {
                    good += 1;
                    if matches!(node.addr.ip, IpAddr::V4(_)) {
                        ipv4 += 1;
                    } else {
                        ipv6 += 1;
                    }
                } else if is_stale(node) {
                    stale += 1;
                } else {
                    bad += 1;
                }
            }
        }

        let total = nodes.len();
        debug!("Pruned {} addresses. {} left.", pruned, total);
        info!(
            "Known nodes: Good:{} [4:{}, 6:{}] Stale:{} Bad:{}",
            good, ipv4, ipv6, stale, bad
        );
    }

    fn deserialize_peers(&self) -> Result<(), String> {
        if !self.peers_file.exists() {
            return Ok(());
        }
        let file = File::open(&self.peers_file).map_err(|e| e.to_string())?;
        let nodes: HashMap<String, Node> =
            serde_json::from_reader(file).map_err(|e| e.to_string())?;
        let count = nodes.len();
        *self.nodes.write() = nodes;
        info!("{} nodes loaded", count);
        Ok(())
    }

    fn save_peers(&self) {
        let tmpfile = self.peers_file.with_extension("json.new");
        let file = match File::create(&tmpfile) {
            Ok(f) => f,
            Err(err) => {
                error!("Error opening file {}: {}", tmpfile.display(), err);
                return;
            }
        };
        if let Err(err) = serde_json::to_writer(&file, &*self.nodes.read()) {
            error!("Failed to encode file {}: {}", tmpfile.display(), err);
            return;
        }
        if let Err(err) = file.sync_all() {
            error!("Error closing file {}: {}", tmpfile.display(), err);
            return;
        }
        if let Err(err) = fs::rename(&tmpfile, &self.peers_file) {
            error!("Error writing file {}: {}", self.peers_file.display(), err);
        }
    }
}

fn is_good(node: &Node) -> bool {
    !is_non_default_port(&node.addr)
        && node.last_success.elapsed_seconds_since_now() < DEFAULT_STALE_GOOD_TIMEOUT_SECS
}

fn is_stale(node: &Node) -> bool {
    (!node.last_success.is_zero()
        && node.last_attempt.elapsed_seconds_since_now() > DEFAULT_STALE_GOOD_TIMEOUT_SECS)
        || node.last_attempt.elapsed_seconds_since_now() > DEFAULT_STALE_BAD_TIMEOUT_SECS
}

fn is_expired(node: &Node) -> bool {
    node.last_seen.elapsed_seconds_since_now() > PRUNE_EXPIRE_TIMEOUT_SECS
        && node.last_success.elapsed_seconds_since_now() > PRUNE_EXPIRE_TIMEOUT_SECS
}

fn is_non_default_port(addr: &NetAddress) -> bool {
    addr.port != config::peers_default_port()
}

fn is_routable(addr: &NetAddress, accept_unroutable: bool) -> bool {
    if accept_unroutable {
        return !is_local(addr);
    }
    is_valid(addr)
        && !(is_rfc1918(addr)
            || is_rfc2544(addr)
            || is_rfc3927(addr)
            || is_rfc4862(addr)
            || is_rfc3849(addr)
            || is_rfc4843(addr)
            || is_rfc5737(addr)
            || is_rfc6598(addr)
            || is_local(addr)
            || is_rfc4193(addr))
}

fn is_valid(addr: &NetAddress) -> bool {
    match addr.ip {
        IpAddr::V4(ip) => !(ip.is_unspecified() || ip == Ipv4Addr::BROADCAST),
        IpAddr::V6(ip) => !(ip.is_unspecified() || is_rfc3849(addr) || ip == Ipv6Addr::UNSPECIFIED),
    }
}

fn is_local(addr: &NetAddress) -> bool {
    addr.ip.is_loopback() || is_zero4(addr)
}

fn is_rfc1918(addr: &NetAddress) -> bool {
    matches!(
        addr.ip,
        IpAddr::V4(ip)
            if ipv4_net_contains(ip, Ipv4Addr::new(10, 0, 0, 0), 8)
                || ipv4_net_contains(ip, Ipv4Addr::new(172, 16, 0, 0), 12)
                || ipv4_net_contains(ip, Ipv4Addr::new(192, 168, 0, 0), 16)
    )
}

fn is_rfc2544(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V4(ip) if ipv4_net_contains(ip, Ipv4Addr::new(198,18,0,0), 15))
}

fn is_rfc3849(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V6(ip) if ipv6_net_contains(ip, parse_ipv6("2001:db8::"), 32))
}

fn is_rfc3927(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V4(ip) if ipv4_net_contains(ip, Ipv4Addr::new(169,254,0,0), 16))
}

fn is_rfc4193(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V6(ip) if ipv6_net_contains(ip, parse_ipv6("fc00::"), 7))
}

fn is_rfc4843(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V6(ip) if ipv6_net_contains(ip, parse_ipv6("2001:10::"), 28))
}

fn is_rfc4862(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V6(ip) if ipv6_net_contains(ip, parse_ipv6("fe80::"), 64))
}

fn is_rfc5737(addr: &NetAddress) -> bool {
    matches!(
        addr.ip,
        IpAddr::V4(ip)
            if ipv4_net_contains(ip, Ipv4Addr::new(192,0,2,0), 24)
                || ipv4_net_contains(ip, Ipv4Addr::new(198,51,100,0), 24)
                || ipv4_net_contains(ip, Ipv4Addr::new(203,0,113,0), 24)
    )
}

fn is_rfc6598(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V4(ip) if ipv4_net_contains(ip, Ipv4Addr::new(100,64,0,0), 10))
}

fn is_zero4(addr: &NetAddress) -> bool {
    matches!(addr.ip, IpAddr::V4(ip) if ipv4_net_contains(ip, Ipv4Addr::new(0,0,0,0), 8))
}

fn ipv4_net_contains(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let ip = u32::from_be_bytes(ip.octets());
    let net = u32::from_be_bytes(network.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (ip & mask) == (net & mask)
}

fn ipv6_net_contains(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let ip = u128::from_be_bytes(ip.octets());
    let net = u128::from_be_bytes(network.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (ip & mask) == (net & mask)
}

fn parse_ipv6(s: &str) -> Ipv6Addr {
    s.parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkFlags, set_active_config, set_peers_default_port};
    use serde_json::json;

    fn init_config() {
        let _ = set_active_config(crate::config::Config {
            app_dir: ".".to_string(),
            known_peers: String::new(),
            show_version: false,
            host: "example.com".to_string(),
            listen: "127.0.0.1:5354".to_string(),
            nameserver: "example.com".to_string(),
            seeder: String::new(),
            profile: String::new(),
            grpc_listen: "127.0.0.1:3737".to_string(),
            min_proto_ver: 0,
            min_ua_ver: String::new(),
            net_suffix: 0,
            no_log_files: true,
            log_level: "info".to_string(),
            threads: 8,
            network: NetworkFlags {
                testnet: false,
                simnet: false,
                devnet: false,
                override_dag_params_file: None,
                active_net_params: crate::config::mainnet_params(),
            },
        });
        set_peers_default_port(16111);
    }

    #[test]
    fn test_pruning_and_good() {
        init_config();
        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.attempt(&addr);
        manager.good(&addr, Some("ua".to_string()), None);
        let addrs = manager.good_addresses(hickory_proto::rr::RecordType::A, true, None);
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_nodes_json_format_matches_go() {
        init_config();
        let addr = NetAddress::with_timestamp(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 16111, 0);
        let node = Node {
            addr: addr.clone(),
            user_agent: None,
            last_attempt: GoTime::zero(),
            last_success: GoTime::zero(),
            last_seen: GoTime::zero(),
            subnetwork_id: None,
        };
        let mut map = HashMap::new();
        map.insert("1.2.3.4_16111".to_string(), node);

        let value = serde_json::to_value(&map).unwrap();
        let expected = json!({
            "1.2.3.4_16111": {
                "Addr": {"Timestamp": {}, "IP": "1.2.3.4", "Port": 16111},
                "UserAgent": null,
                "LastAttempt": "0001-01-01T00:00:00Z",
                "LastSuccess": "0001-01-01T00:00:00Z",
                "LastSeen": "0001-01-01T00:00:00Z",
                "SubnetworkID": null
            }
        });
        assert_eq!(value, expected);
    }
}
