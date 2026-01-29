use crate::config::Config;
use crate::version;
use kaspa_p2p_lib::common::{DEFAULT_TIMEOUT, ProtocolError};
use kaspa_p2p_lib::pb::kaspad_message::Payload;
use kaspa_p2p_lib::pb::{
    AddressesMessage, ReadyMessage, RequestAddressesMessage, VerackMessage, VersionMessage,
};
use kaspa_p2p_lib::{
    Adaptor, ConnectionInitializer, Hub, IncomingRoute, KaspadMessagePayloadType, Router,
    make_message,
};
use kaspa_utils_tower::counters::TowerConnectionCounters;
use log::debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct DnsseedNetAdapter {
    adaptor: Arc<Adaptor>,
    routes_rx: Mutex<mpsc::Receiver<Routes>>,
    connect_lock: Mutex<()>,
}

impl DnsseedNetAdapter {
    pub fn new(cfg: Arc<Config>) -> Result<Self, String> {
        let hub = Hub::new();
        let (routes_tx, routes_rx) = mpsc::channel(8);
        let initializer = Arc::new(SeedInitializer { routes_tx, cfg });
        let counters = Arc::new(TowerConnectionCounters::default());
        let adaptor = Adaptor::client_only(hub, initializer, counters);
        Ok(DnsseedNetAdapter {
            adaptor,
            routes_rx: Mutex::new(routes_rx),
            connect_lock: Mutex::new(()),
        })
    }

    pub async fn connect(&self, address: &str) -> Result<Routes, String> {
        let _guard = self.connect_lock.lock().await;
        let _peer_key = self
            .adaptor
            .connect_peer(address.to_string())
            .await
            .map_err(|e| format!("Error connecting to {}: {}", address, e))?;
        let mut rx = self.routes_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| "Failed to receive routes".to_string())
    }
}

struct SeedInitializer {
    routes_tx: mpsc::Sender<Routes>,
    cfg: Arc<Config>,
}

#[tonic::async_trait]
impl ConnectionInitializer for SeedInitializer {
    async fn initialize_connection(&self, router: Arc<Router>) -> Result<(), ProtocolError> {
        let mut routes = Routes::new(router);
        routes.start_router();
        let peer_version = perform_handshake(&self.cfg, &mut routes).await?;
        routes.peer_version = peer_version;
        routes.spawn_background_tasks();
        let _ = self.routes_tx.send(routes).await;
        Ok(())
    }
}

pub struct Routes {
    router: Arc<Router>,
    handshake_route: IncomingRoute,
    addresses_route: IncomingRoute,
    ping_route: Option<IncomingRoute>,
    ready_route: Option<IncomingRoute>,
    other_route: Option<IncomingRoute>,
    pub peer_version: VersionMessage,
}

impl Routes {
    fn new(router: Arc<Router>) -> Self {
        let handshake_route = router.subscribe(vec![
            KaspadMessagePayloadType::Version,
            KaspadMessagePayloadType::Verack,
        ]);
        let addresses_route = router.subscribe(vec![
            KaspadMessagePayloadType::RequestAddresses,
            KaspadMessagePayloadType::Addresses,
        ]);
        let ping_route = Some(router.subscribe(vec![KaspadMessagePayloadType::Ping]));
        let ready_route = Some(router.subscribe(vec![KaspadMessagePayloadType::Ready]));

        let other_types = all_payload_types()
            .into_iter()
            .filter(|t| {
                !matches!(
                    t,
                    KaspadMessagePayloadType::Version
                        | KaspadMessagePayloadType::Verack
                        | KaspadMessagePayloadType::RequestAddresses
                        | KaspadMessagePayloadType::Addresses
                        | KaspadMessagePayloadType::Ping
                        | KaspadMessagePayloadType::Ready
                )
            })
            .collect();
        let other_route = Some(router.subscribe(other_types));

        Routes {
            router,
            handshake_route,
            addresses_route,
            ping_route,
            ready_route,
            other_route,
            peer_version: VersionMessage::default(),
        }
    }

    fn start_router(&self) {
        self.router.start();
    }

    pub async fn enqueue(
        &self,
        msg: kaspa_p2p_lib::pb::KaspadMessage,
    ) -> Result<(), ProtocolError> {
        self.router.enqueue(msg).await
    }

    pub async fn wait_for_message(
        &mut self,
        expected: KaspadMessagePayloadType,
        timeout: Duration,
    ) -> Result<kaspa_p2p_lib::pb::KaspadMessage, ProtocolError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let route = self.choose_route(expected);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ProtocolError::Timeout(timeout));
            }
            let msg = tokio::time::timeout(remaining, route.recv())
                .await
                .map_err(|_| ProtocolError::Timeout(timeout))?;
            let msg = msg.ok_or(ProtocolError::ConnectionClosed)?;
            let msg_type: KaspadMessagePayloadType = msg
                .payload
                .as_ref()
                .map(|p| p.into())
                .unwrap_or(KaspadMessagePayloadType::Reject);
            if msg_type == expected {
                return Ok(msg);
            }
        }
    }

    fn choose_route(&mut self, expected: KaspadMessagePayloadType) -> &mut IncomingRoute {
        match expected {
            KaspadMessagePayloadType::Version | KaspadMessagePayloadType::Verack => {
                &mut self.handshake_route
            }
            KaspadMessagePayloadType::RequestAddresses | KaspadMessagePayloadType::Addresses => {
                &mut self.addresses_route
            }
            KaspadMessagePayloadType::Ping => self.ping_route.as_mut().expect("ping route"),
            KaspadMessagePayloadType::Ready => self.ready_route.as_mut().expect("ready route"),
            _ => self.other_route.as_mut().expect("other route"),
        }
    }

    pub async fn disconnect(&self) {
        let _ = self.router.close().await;
    }

    fn spawn_background_tasks(&mut self) {
        if let Some(mut ping_route) = self.ping_route.take() {
            let router = self.router.clone();
            tokio::spawn(async move {
                while let Some(msg) = ping_route.recv().await {
                    if let Some(Payload::Ping(ping)) = msg.payload {
                        let pong = make_message!(
                            Payload::Pong,
                            kaspa_p2p_lib::pb::PongMessage { nonce: ping.nonce }
                        );
                        let _ = router.enqueue(pong).await;
                    }
                }
            });
        }

        if let Some(mut ready_route) = self.ready_route.take() {
            tokio::spawn(async move { while ready_route.recv().await.is_some() {} });
        }

        if let Some(mut other_route) = self.other_route.take() {
            tokio::spawn(async move { while other_route.recv().await.is_some() {} });
        }
    }
}

async fn perform_handshake(
    cfg: &Config,
    routes: &mut Routes,
) -> Result<VersionMessage, ProtocolError> {
    let ready = make_message!(Payload::Ready, ReadyMessage {});
    routes.enqueue(ready).await?;

    let version_msg = routes
        .wait_for_message(KaspadMessagePayloadType::Version, DEFAULT_TIMEOUT)
        .await?;
    let peer_version = match version_msg.payload {
        Some(Payload::Version(v)) => v,
        _ => return Err(ProtocolError::Other("expected version message")),
    };

    let our_version = VersionMessage {
        protocol_version: peer_version.protocol_version,
        services: peer_version.services,
        timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
        address: None,
        id: Uuid::new_v4().as_bytes().to_vec(),
        user_agent: format!("/kaspa-dnsseeder:{}/", version::version()),
        disable_relay_tx: true,
        subnetwork_id: None,
        network: cfg.network.active_net_params.name.clone(),
    };
    routes
        .enqueue(make_message!(Payload::Version, our_version))
        .await?;

    routes
        .wait_for_message(KaspadMessagePayloadType::Verack, DEFAULT_TIMEOUT)
        .await?;
    routes
        .enqueue(make_message!(Payload::Verack, VerackMessage {}))
        .await?;

    routes
        .wait_for_message(KaspadMessagePayloadType::RequestAddresses, DEFAULT_TIMEOUT)
        .await?;
    routes
        .enqueue(make_message!(
            Payload::Addresses,
            AddressesMessage {
                address_list: vec![]
            }
        ))
        .await?;

    routes
        .enqueue(make_message!(
            Payload::RequestAddresses,
            RequestAddressesMessage {
                include_all_subnetworks: true,
                subnetwork_id: None,
            }
        ))
        .await?;

    routes
        .wait_for_message(KaspadMessagePayloadType::Addresses, DEFAULT_TIMEOUT)
        .await?;

    debug!("Handshake completed with peer {}", routes.router);
    Ok(peer_version)
}

fn all_payload_types() -> Vec<KaspadMessagePayloadType> {
    vec![
        KaspadMessagePayloadType::Addresses,
        KaspadMessagePayloadType::Block,
        KaspadMessagePayloadType::Transaction,
        KaspadMessagePayloadType::BlockLocator,
        KaspadMessagePayloadType::RequestAddresses,
        KaspadMessagePayloadType::RequestRelayBlocks,
        KaspadMessagePayloadType::RequestTransactions,
        KaspadMessagePayloadType::IbdBlock,
        KaspadMessagePayloadType::InvRelayBlock,
        KaspadMessagePayloadType::InvTransactions,
        KaspadMessagePayloadType::Ping,
        KaspadMessagePayloadType::Pong,
        KaspadMessagePayloadType::Verack,
        KaspadMessagePayloadType::Version,
        KaspadMessagePayloadType::TransactionNotFound,
        KaspadMessagePayloadType::Reject,
        KaspadMessagePayloadType::PruningPointUtxoSetChunk,
        KaspadMessagePayloadType::RequestIbdBlocks,
        KaspadMessagePayloadType::UnexpectedPruningPoint,
        KaspadMessagePayloadType::IbdBlockLocator,
        KaspadMessagePayloadType::IbdBlockLocatorHighestHash,
        KaspadMessagePayloadType::RequestNextPruningPointUtxoSetChunk,
        KaspadMessagePayloadType::DonePruningPointUtxoSetChunks,
        KaspadMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
        KaspadMessagePayloadType::BlockWithTrustedData,
        KaspadMessagePayloadType::DoneBlocksWithTrustedData,
        KaspadMessagePayloadType::RequestPruningPointAndItsAnticone,
        KaspadMessagePayloadType::BlockHeaders,
        KaspadMessagePayloadType::RequestNextHeaders,
        KaspadMessagePayloadType::DoneHeaders,
        KaspadMessagePayloadType::RequestPruningPointUtxoSet,
        KaspadMessagePayloadType::RequestHeaders,
        KaspadMessagePayloadType::RequestBlockLocator,
        KaspadMessagePayloadType::PruningPoints,
        KaspadMessagePayloadType::RequestPruningPointProof,
        KaspadMessagePayloadType::PruningPointProof,
        KaspadMessagePayloadType::Ready,
        KaspadMessagePayloadType::BlockWithTrustedDataV4,
        KaspadMessagePayloadType::TrustedData,
        KaspadMessagePayloadType::RequestIbdChainBlockLocator,
        KaspadMessagePayloadType::IbdChainBlockLocator,
        KaspadMessagePayloadType::RequestAntipast,
        KaspadMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks,
    ]
}
