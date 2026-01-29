use crate::manager::Manager;
use crate::types::{NetAddress, SubnetworkID};
use log::error;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

use pb::peer_service_server::{PeerService, PeerServiceServer};

pub struct GrpcServer {
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

pub async fn start(manager: Arc<Manager>, listen: &str) -> Result<GrpcServer, String> {
    let mut addrs = listen.to_socket_addrs().map_err(|e| e.to_string())?;
    let addr: SocketAddr = addrs
        .next()
        .ok_or_else(|| "no resolved addresses".to_string())?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let service = PeerServiceImpl { manager };
    let handle = tokio::spawn(async move {
        let server =
            tonic::transport::Server::builder().add_service(PeerServiceServer::new(service));
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        if let Err(err) = server
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
        {
            error!("gRPC server error: {}", err);
        }
    });
    Ok(GrpcServer {
        shutdown: tx,
        handle,
    })
}

impl GrpcServer {
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

#[derive(Clone)]
struct PeerServiceImpl {
    manager: Arc<Manager>,
}

#[tonic::async_trait]
impl PeerService for PeerServiceImpl {
    async fn get_peers_list(
        &self,
        request: tonic::Request<pb::GetPeersListRequest>,
    ) -> Result<tonic::Response<pb::GetPeersListResponse>, tonic::Status> {
        let req = request.into_inner();
        let subnetwork_id = if req.subnetwork_id.is_empty() {
            None
        } else {
            Some(SubnetworkID::from_bytes(&req.subnetwork_id).map_err(tonic::Status::unknown)?)
        };
        let mut addrs = self.manager.good_addresses(
            hickory_proto::rr::RecordType::A,
            req.include_all_subnetworks,
            subnetwork_id,
        );
        addrs.extend(self.manager.good_addresses(
            hickory_proto::rr::RecordType::AAAA,
            req.include_all_subnetworks,
            subnetwork_id,
        ));
        let proto_addrs = addrs.into_iter().map(net_address_to_proto).collect();
        Ok(tonic::Response::new(pb::GetPeersListResponse {
            addresses: proto_addrs,
        }))
    }
}

fn net_address_to_proto(addr: NetAddress) -> pb::NetAddress {
    let ip_bytes = match addr.ip {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    pb::NetAddress {
        timestamp: addr.timestamp / 1000,
        ip: ip_bytes,
        port: addr.port as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkFlags, set_active_config, set_peers_default_port};
    use crate::types::NetAddress;
    use std::net::{IpAddr, Ipv4Addr};
    use tonic::Code;

    #[tokio::test]
    async fn test_get_peers() {
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

        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(203, 105, 20, 21)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.good(&addr, None, None);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let service = PeerServiceImpl { manager };
        let handle = tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let server =
                tonic::transport::Server::builder().add_service(PeerServiceServer::new(service));
            server
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        let endpoint = format!("http://{}", addr);
        let mut client = pb::peer_service_client::PeerServiceClient::connect(endpoint)
            .await
            .unwrap();
        let req = pb::GetPeersListRequest {
            subnetwork_id: vec![],
            include_all_subnetworks: false,
        };
        let resp = client.get_peers_list(req).await.unwrap();
        let result = resp.into_inner();
        assert!(!result.addresses.is_empty());
        let ip_bytes = &result.addresses[0].ip;
        assert_eq!(ip_bytes.len(), 16);
        assert_eq!(&ip_bytes[0..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]);
        assert_eq!(&ip_bytes[12..16], &[203, 105, 20, 21]);

        let _ = tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_get_peers_invalid_subnetwork_id() {
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

        let manager = Manager::new(".").unwrap();
        let addr = NetAddress::new(IpAddr::V4(Ipv4Addr::new(203, 105, 20, 21)), 16111);
        manager.add_addresses(std::slice::from_ref(&addr));
        manager.good(&addr, None, None);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let service = PeerServiceImpl { manager };
        let handle = tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let server =
                tonic::transport::Server::builder().add_service(PeerServiceServer::new(service));
            server
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        let endpoint = format!("http://{}", addr);
        let mut client = pb::peer_service_client::PeerServiceClient::connect(endpoint)
            .await
            .unwrap();
        let req = pb::GetPeersListRequest {
            subnetwork_id: vec![1, 2, 3],
            include_all_subnetworks: false,
        };
        let status = client.get_peers_list(req).await.unwrap_err();
        assert_eq!(status.code(), Code::Unknown);

        let _ = tx.send(());
        let _ = handle.await;
    }
}
