use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use foca::{Foca, Notification, Timer};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::GossipConfig;
use crate::routing::{RegistryProvider, RegistryRecord, RoutingTable};

use super::discovery::PeerDiscovery;
use super::handler::RegistryBroadcast;

/// How often the peer list is re-resolved, to pick up membership churn.
const PEER_REFRESH: Duration = Duration::from_secs(60);

/// Assumed cluster size for tuning SWIM timings. Small: this is a handful of proxy
/// instances, not a large fleet.
const ASSUMED_CLUSTER_SIZE: u32 = 8;

/// Work items for the task that owns the Foca state machine.
///
/// Foca is a single-threaded state machine and is not `Sync`, so exactly one task
/// owns it and everything reaches it through this channel.
enum GossipMsg {
    /// A datagram arrived from a peer.
    Datagram(Vec<u8>),
    /// Introduce ourselves to a peer.
    Announce(SocketAddr),
    /// Disseminate a locally-originated record.
    Publish(RegistryRecord),
    /// A timer Foca asked us to deliver back to it.
    Timer(Timer<SocketAddr>),
}

/// Bridges Foca's synchronous expectations to tokio.
///
/// `send_to` and `submit_after` are called from inside Foca, which cannot await, so
/// both hand off to channels instead of doing the work inline.
struct TokioRuntime {
    outbound: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    timers: mpsc::UnboundedSender<(Timer<SocketAddr>, Duration)>,
}

impl foca::Runtime<SocketAddr> for TokioRuntime {
    fn notify(&mut self, notification: Notification<'_, SocketAddr>) {
        match notification {
            Notification::MemberUp(id) => tracing::info!(peer = %id, "gossip member up"),
            Notification::MemberDown(id) => tracing::info!(peer = %id, "gossip member down"),
            Notification::Active => tracing::info!("gossip cluster active"),
            Notification::Idle => tracing::warn!("gossip cluster idle — no known peers"),
            other => tracing::debug!(?other, "gossip notification"),
        }
    }

    fn send_to(&mut self, to: SocketAddr, data: &[u8]) {
        let _ = self.outbound.send((to, data.to_vec()));
    }

    fn submit_after(&mut self, event: Timer<SocketAddr>, after: Duration) {
        let _ = self.timers.send((event, after));
    }
}

/// Registry populated by SWIM gossip between Meridian instances.
///
/// Gossip is a freshness optimisation, not a correctness dependency: backends keep
/// re-registering directly, so an instance that cannot gossip still converges from
/// heartbeats — just over several intervals rather than one.
pub struct GossipProvider {
    config: GossipConfig,
}

impl GossipProvider {
    pub fn new(config: GossipConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl RegistryProvider for GossipProvider {
    async fn run(&self, table: Arc<RoutingTable>, shutdown: CancellationToken) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(&self.config.bind)
                .await
                .with_context(|| format!("failed to bind gossip socket {}", self.config.bind))?,
        );
        let self_addr = socket.local_addr()?;
        tracing::info!(addr = %self_addr, "gossip listening");

        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<GossipMsg>();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
        let (timer_tx, mut timer_rx) = mpsc::unbounded_channel::<(Timer<SocketAddr>, Duration)>();

        // Inbound: socket -> driver.
        {
            let socket = socket.clone();
            let msg_tx = msg_tx.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        result = socket.recv_from(&mut buf) => match result {
                            Ok((n, _from)) => {
                                let _ = msg_tx.send(GossipMsg::Datagram(buf[..n].to_vec()));
                            }
                            Err(e) => tracing::debug!(error = %e, "gossip recv error (continuing)"),
                        }
                    }
                }
            });
        }

        // Outbound: driver -> socket.
        {
            let socket = socket.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        Some((to, data)) = out_rx.recv() => {
                            if let Err(e) = socket.send_to(&data, to).await {
                                tracing::debug!(%to, error = %e, "gossip send failed");
                            }
                        }
                    }
                }
            });
        }

        // Timers: Foca asks for an event later; deliver it back to the driver.
        {
            let msg_tx = msg_tx.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        Some((event, after)) = timer_rx.recv() => {
                            let msg_tx = msg_tx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(after).await;
                                let _ = msg_tx.send(GossipMsg::Timer(event));
                            });
                        }
                    }
                }
            });
        }

        // Peer discovery: announce on start, then re-resolve to catch churn.
        {
            let names = self.config.peers.clone();
            let msg_tx = msg_tx.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(PEER_REFRESH);
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = interval.tick() => {
                            let peers = PeerDiscovery::resolve_peers(&names, self_addr).await;
                            if peers.is_empty() {
                                tracing::warn!(
                                    "no gossip peers resolved; converging from backend \
                                     heartbeats alone"
                                );
                            }
                            for peer in peers {
                                let _ = msg_tx.send(GossipMsg::Announce(peer));
                            }
                        }
                    }
                }
            });
        }

        // Publish locally-originated records so peers learn about them.
        {
            let table = table.clone();
            let msg_tx = msg_tx.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                // Re-publishing every record on a slow tick is what makes the
                // heartbeat double as anti-entropy: an instance that joined late
                // converges without a dedicated state-transfer protocol.
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = interval.tick() => {
                            for (name, backend) in table.list_backends() {
                                let _ = msg_tx.send(GossipMsg::Publish(RegistryRecord {
                                    name,
                                    hostname: backend.hostname,
                                    tcp_addr: backend.tcp_addr.to_string(),
                                    udp_addr: backend.udp_addr.to_string(),
                                    instance_id: backend.instance_id,
                                    version: backend.version,
                                }));
                            }
                        }
                    }
                }
            });
        }

        // The driver: sole owner of the Foca state machine.
        let cluster_size = NonZeroU32::new(ASSUMED_CLUSTER_SIZE).expect("non-zero");
        let mut foca = Foca::with_custom_broadcast(
            self_addr,
            foca::Config::new_lan(cluster_size),
            StdRng::from_os_rng(),
            foca::PostcardCodec,
            RegistryBroadcast::new(table),
        );
        let mut runtime = TokioRuntime {
            outbound: out_tx,
            timers: timer_tx,
        };

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                Some(msg) = msg_rx.recv() => {
                    let result = match msg {
                        GossipMsg::Datagram(data) => foca.handle_data(&data, &mut runtime),
                        GossipMsg::Announce(peer) => foca.announce(peer, &mut runtime),
                        GossipMsg::Timer(event) => foca.handle_timer(event, &mut runtime),
                        GossipMsg::Publish(record) => match record.encode() {
                            Ok(bytes) => foca.add_broadcast(&bytes).map(|_| ()),
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to encode record for gossip");
                                Ok(())
                            }
                        },
                    };
                    if let Err(e) = result {
                        // A single bad datagram or a transient error must not stop
                        // the cluster; gossip degrades rather than failing.
                        tracing::debug!(error = ?e, "gossip step failed (continuing)");
                    }
                }
            }
        }

        tracing::info!("gossip provider stopped");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "gossip"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{Backend, RecordVersion};

    fn provider(bind: &str, peers: Vec<String>) -> GossipProvider {
        GossipProvider::new(GossipConfig {
            bind: bind.to_string(),
            peers,
        })
    }

    async fn free_udp_port() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    }

    /// A record registered against one instance must reach the other.
    ///
    /// This is the property the whole gossip layer exists for: backends register
    /// with whichever instance they reach, and the rest of the fleet learns about
    /// them without the backend knowing the topology.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_record_registered_on_one_instance_reaches_the_other() {
        let port_a = free_udp_port().await;
        let port_b = free_udp_port().await;

        let table_a = RoutingTable::new();
        let table_b = RoutingTable::new();
        let shutdown = CancellationToken::new();

        // Each points at the other.
        let a = provider(
            &format!("127.0.0.1:{port_a}"),
            vec![format!("127.0.0.1:{port_b}")],
        );
        let b = provider(
            &format!("127.0.0.1:{port_b}"),
            vec![format!("127.0.0.1:{port_a}")],
        );

        {
            let (t, sd) = (table_a.clone(), shutdown.clone());
            tokio::spawn(async move { a.run(t, sd).await });
        }
        {
            let (t, sd) = (table_b.clone(), shutdown.clone());
            tokio::spawn(async move { b.run(t, sd).await });
        }

        // Register only with A, as a backend heartbeating to one instance would.
        table_a.add_backend(
            "customer-x".to_string(),
            Backend::new(
                "x.example.com".to_string(),
                "127.0.0.1:4443".parse().unwrap(),
                "127.0.0.1:4444".parse().unwrap(),
                31,
            )
            .with_version(RecordVersion::new(1, 1)),
        );

        // Allow announce + publish ticks to flow.
        let converged = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if table_b.lookup_by_hostname("x.example.com").is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;

        shutdown.cancel();

        assert!(
            converged.is_ok(),
            "instance B must learn the record registered against A; without this a \
             backend would only be reachable through whichever instance it happened \
             to contact"
        );
        let learned = table_b.lookup_by_hostname("x.example.com").unwrap();
        assert_eq!(learned.instance_id, 31);
        assert_eq!(learned.udp_addr.port(), 4444);
    }

    /// Losing gossip entirely must not stop an instance serving what it already
    /// knows — backends keep re-registering, so convergence degrades rather than
    /// breaking.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_instance_with_no_reachable_peers_still_serves_its_own_records() {
        let port = free_udp_port().await;
        let table = RoutingTable::new();
        let shutdown = CancellationToken::new();

        // Points at a name that cannot resolve.
        let p = provider(
            &format!("127.0.0.1:{port}"),
            vec!["this-host-does-not-exist.invalid:7946".to_string()],
        );
        {
            let (t, sd) = (table.clone(), shutdown.clone());
            tokio::spawn(async move { p.run(t, sd).await });
        }

        table.add_backend(
            "local".to_string(),
            Backend::new(
                "local.example.com".to_string(),
                "127.0.0.1:5443".parse().unwrap(),
                "127.0.0.1:5444".parse().unwrap(),
                9,
            ),
        );

        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            table.lookup_by_hostname("local.example.com").is_some(),
            "gossip failure must not affect locally-held records"
        );

        shutdown.cancel();
    }
}
