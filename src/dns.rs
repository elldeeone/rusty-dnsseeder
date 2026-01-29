use crate::manager::Manager;
use crate::types::SubnetworkID;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::{A, AAAA, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::info;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};

const SUBNETWORK_ID_PREFIX_CHAR: char = 'n';

pub struct DnsServer {
    hostname: String,
    listen: String,
    nameserver: String,
    manager: Arc<Manager>,
}

impl DnsServer {
    pub fn new(hostname: &str, nameserver: &str, listen: &str, manager: Arc<Manager>) -> Self {
        let mut host = hostname.to_string();
        if !host.ends_with('.') {
            host.push('.');
        }
        let mut ns = nameserver.to_string();
        if !ns.ends_with('.') {
            ns.push('.');
        }
        Self {
            hostname: host,
            listen: listen.to_string(),
            nameserver: ns,
            manager,
        }
    }

    pub async fn start(
        self: Arc<Self>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), String> {
        let mut addrs = self.listen.to_socket_addrs().map_err(|e| e.to_string())?;
        let listen_addr = addrs
            .find(|addr| matches!(addr, SocketAddr::V4(_)))
            .ok_or_else(|| "no IPv4 address resolved".to_string())?;
        let socket = UdpSocket::bind(listen_addr)
            .await
            .map_err(|e| e.to_string())?;
        let socket = Arc::new(socket);

        loop {
            if *shutdown.borrow() {
                info!("DNS server shutdown");
                return Ok(());
            }
            let mut buf = vec![0u8; 512];
            match timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    let server = Arc::clone(&self);
                    let sock = Arc::clone(&socket);
                    let data = buf[..size].to_vec();
                    tokio::spawn(async move {
                        if let Some(resp) = server.handle_request(addr, &data) {
                            let _ = sock.send_to(&resp, addr).await;
                        }
                    });
                }
                Ok(Err(_)) => continue,
                Err(_) => continue,
            }
        }
    }

    fn handle_request(&self, addr: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        let req = Message::from_vec(data).ok()?;
        if req.queries().len() != 1 {
            info!(
                "{} sent more than 1 question: {}",
                addr,
                req.queries().len()
            );
            return None;
        }
        let query = req.queries()[0].clone();
        let qname = query.name().to_utf8().to_lowercase();
        if !qname.contains(&self.hostname) {
            info!("{}: invalid name: {}", addr, query.name());
            return None;
        }
        let qtype = query.query_type();
        let atype = match qtype {
            RecordType::A | RecordType::AAAA | RecordType::NS => qtype,
            _ => {
                info!("{}: invalid qtype: {:?}", addr, qtype);
                return None;
            }
        };

        let (subnetwork_id, include_all_subnetworks) = match self.extract_subnetwork_id(&qname) {
            Ok(v) => v,
            Err(err) => {
                info!("{}: subnetworkid parse error: {}", addr, err);
                return None;
            }
        };

        info!(
            "{}: query {:?} for subnetwork ID {:?}",
            addr, qtype, subnetwork_id
        );
        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(req.op_code());
        resp.set_authoritative(true);
        resp.set_recursion_desired(req.recursion_desired());
        resp.set_recursion_available(false);
        resp.add_query(query.clone());

        if qtype != RecordType::NS {
            let ns = self.build_authority_record();
            resp.add_name_server(ns);
            let mut addrs =
                self.manager
                    .good_addresses(qtype, include_all_subnetworks, subnetwork_id);
            if addrs.is_empty() && qtype == RecordType::AAAA {
                addrs.push(crate::types::NetAddress::new("100::".parse().unwrap(), 0));
            }
            info!("{}: Sending {} addresses", addr, addrs.len());
            for a in addrs {
                if let Some(record) = build_address_record(query.name(), atype, a.ip) {
                    resp.add_answer(record);
                }
            }
        } else {
            let ns = self.build_ns_record(query.name());
            resp.add_answer(ns);
        }

        resp.to_vec().ok()
    }

    fn extract_subnetwork_id(
        &self,
        domain_name: &str,
    ) -> Result<(Option<SubnetworkID>, bool), String> {
        let mut subnetwork_id = None;
        let mut include_all = true;
        if self.hostname != domain_name {
            let labels: Vec<&str> = domain_name.trim_end_matches('.').split('.').collect();
            if let Some(first) = labels.first()
                && first.starts_with(SUBNETWORK_ID_PREFIX_CHAR)
            {
                include_all = false;
                if first.len() > 1 {
                    subnetwork_id = Some(SubnetworkID::from_hex(&first[1..])?);
                }
            }
        }
        Ok((subnetwork_id, include_all))
    }

    fn build_ns_record(&self, name: &Name) -> Record {
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::NS);
        record.set_ttl(86400);
        let name: Name = self.nameserver.parse().unwrap_or_else(|_| Name::new());
        record.set_data(Some(RData::NS(NS(name))));
        record
    }

    fn build_authority_record(&self) -> Record {
        let name: Name = self.hostname.parse().unwrap_or_else(|_| Name::new());
        self.build_ns_record(&name)
    }
}

fn build_address_record(name: &Name, record_type: RecordType, ip: IpAddr) -> Option<Record> {
    let mut record = Record::new();
    record.set_name(name.clone());
    record.set_record_type(record_type);
    record.set_ttl(30);
    match (record_type, ip) {
        (RecordType::A, IpAddr::V4(v4)) => {
            record.set_data(Some(RData::A(A(v4))));
            Some(record)
        }
        (RecordType::AAAA, IpAddr::V6(v6)) => {
            record.set_data(Some(RData::AAAA(AAAA(v6))));
            Some(record)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkFlags, set_active_config, set_peers_default_port};
    use crate::types::NetAddress;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::Name;
    use std::net::{IpAddr, Ipv4Addr};

    fn init_config() {
        let _ = set_active_config(crate::config::Config {
            app_dir: ".".to_string(),
            known_peers: String::new(),
            show_version: false,
            host: "seed.example.com".to_string(),
            listen: "127.0.0.1:5354".to_string(),
            nameserver: "ns.example.com".to_string(),
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
    fn test_dns_a_response() {
        init_config();
        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.good(&addr, None, None);
        let server = DnsServer::new(
            "seed.example.com",
            "ns.example.com",
            "127.0.0.1:5354",
            manager,
        );

        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Query);
        let name = Name::from_ascii("seed.example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let resp = server
            .handle_request("127.0.0.1:9999".parse().unwrap(), &msg.to_vec().unwrap())
            .unwrap();
        let parsed = Message::from_vec(&resp).unwrap();
        assert_eq!(parsed.answers().len(), 1);
    }

    #[test]
    fn test_dns_authority_uses_base_hostname() {
        init_config();
        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.good(&addr, None, None);
        let server = DnsServer::new(
            "seed.example.com",
            "ns.example.com",
            "127.0.0.1:5354",
            manager,
        );

        let mut msg = Message::new();
        msg.set_id(2);
        msg.set_message_type(MessageType::Query);
        let name = Name::from_ascii("n.seed.example.com").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let resp = server
            .handle_request("127.0.0.1:9999".parse().unwrap(), &msg.to_vec().unwrap())
            .unwrap();
        let parsed = Message::from_vec(&resp).unwrap();
        let ns = parsed.name_servers();
        assert_eq!(ns.len(), 1);
        let mut ns_name = ns[0].name().to_utf8().to_lowercase();
        if !ns_name.ends_with('.') {
            ns_name.push('.');
        }
        assert_eq!(ns_name, "seed.example.com.");
    }

    #[test]
    fn test_dns_accepts_hostname_substring() {
        init_config();
        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.good(&addr, None, None);
        let server = DnsServer::new(
            "seed.example.com",
            "ns.example.com",
            "127.0.0.1:5354",
            manager,
        );

        let mut msg = Message::new();
        msg.set_id(3);
        msg.set_message_type(MessageType::Query);
        let name = Name::from_ascii("foo.seed.example.com.evil").unwrap();
        msg.add_query(Query::query(name, RecordType::A));
        let resp = server.handle_request("127.0.0.1:9999".parse().unwrap(), &msg.to_vec().unwrap());
        assert!(resp.is_some());
    }
}
