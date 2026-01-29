use crate::config::Config;
use crate::manager::Manager;
use crate::types::{NetAddress, SubnetworkID};
use log::info;
use rand::Rng;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::task;

const SECONDS_IN_3_DAYS: i64 = 24 * 60 * 60 * 3;
const SECONDS_IN_4_DAYS: i64 = 24 * 60 * 60 * 4;
const SUBNETWORK_ID_PREFIX_CHAR: char = 'n';

pub async fn seed_from_dns(
    cfg: &Config,
    custom_seed: Option<String>,
    include_all_subnetworks: bool,
    subnetwork_id: Option<SubnetworkID>,
    manager: Arc<Manager>,
) {
    let seeds = if let Some(seed) = custom_seed {
        vec![seed]
    } else {
        cfg.network.active_net_params.dns_seeds.clone()
    };

    for seed in seeds {
        let host = apply_subnetwork_prefix(&seed, include_all_subnetworks, subnetwork_id);
        let manager = manager.clone();
        let default_port: u16 = cfg
            .network
            .active_net_params
            .default_port
            .parse()
            .unwrap_or(0);
        task::spawn_blocking(move || {
            let addrs = match lookup_host_ips(&host) {
                Ok(addrs) => addrs,
                Err(err) => {
                    info!("DNS discovery failed on seed {}: {}", host, err);
                    return;
                }
            };
            let num_peers = addrs.len();
            info!("{} addresses found from DNS seed {}", num_peers, host);
            if num_peers == 0 {
                return;
            }
            let mut rng = rand::thread_rng();
            let mut net_addrs = Vec::with_capacity(addrs.len());
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            for ip in addrs {
                let delta = SECONDS_IN_3_DAYS + rng.gen_range(0..SECONDS_IN_4_DAYS);
                let ts = (now - delta) * 1000;
                net_addrs.push(NetAddress::with_timestamp(ip, default_port, ts));
            }
            manager.add_addresses(&net_addrs);
        });
    }
}

pub fn apply_subnetwork_prefix(
    seed: &str,
    include_all_subnetworks: bool,
    subnetwork_id: Option<SubnetworkID>,
) -> String {
    if include_all_subnetworks {
        return seed.to_string();
    }
    if let Some(id) = subnetwork_id {
        return format!("{}{}.{seed}", SUBNETWORK_ID_PREFIX_CHAR, hex::encode(id.0));
    }
    format!("{}.{seed}", SUBNETWORK_ID_PREFIX_CHAR)
}

fn lookup_host_ips(host: &str) -> Result<Vec<IpAddr>, String> {
    let addr = format!("{}:0", host);
    let mut ips = Vec::new();
    for socket in addr.to_socket_addrs().map_err(|e| e.to_string())? {
        ips.push(socket.ip());
    }
    Ok(ips)
}
