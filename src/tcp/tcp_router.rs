use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rustls::server::Acceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;
use crate::tls::TlsAlert;
use crate::udp::SocketFactory;

/// Deadline for reading a complete ClientHello.
///
/// A read loop without one lets a peer that connects and sends nothing pin a task and
/// an fd indefinitely, unauthenticated.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for connecting to the chosen backend.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on buffered handshake bytes before the ClientHello completes.
///
/// One maximum-size TLS record is 16 KiB + 5; the allowance above that covers a
/// ClientHello split across records. rustls enforces its own limits inside this.
const MAX_HANDSHAKE_BYTES: usize = 32 * 1024;

const READ_CHUNK: usize = 8 * 1024;

/// Why a connection ended before it could be spliced.
enum RejectReason {
    /// Caused by the peer and expected on a public port: scanners, health probes,
    /// non-TLS traffic, an SNI naming no tenant. Logged at debug, because the
    /// content is remote-controlled and `warn` would let anyone drive our log volume.
    Client(anyhow::Error),
    /// Our fault: a registered backend is unreachable. Reaching this requires an SNI
    /// that resolves to a real record, so it is not freely triggerable.
    Server(anyhow::Error),
}

/// A ClientHello that has been read in full.
struct BufferedHello {
    /// Every byte consumed from the client, replayed to the backend so the handshake
    /// continues untouched. Read rather than peeked, so nothing is left unread in the
    /// receive queue to turn a close into an RST.
    bytes: Vec<u8>,
    sni: Option<String>,
}

pub struct TcpRouter {
    routing_table: Arc<RoutingTable>,
    listen_addr: String,
}

impl TcpRouter {
    pub(crate) fn new(routing_table: Arc<RoutingTable>, listen_addr: String) -> Self {
        Self {
            routing_table,
            listen_addr,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        // Bound through SocketFactory rather than `TcpListener::bind` so a wildcard IPv6
        // listen address means the same thing here as it does for QUIC. Both routers are
        // handed the same `config.listen`.
        let listener = TcpListener::from_std(SocketFactory::bind_tcp_listener(&self.listen_addr)?)?;
        tracing::info!(addr = %self.listen_addr, "tcp router listening");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("tcp router shutting down");
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer_addr) = result?;
                    let routing_table = self.routing_table.clone();
                    tokio::spawn(async move {
                        match Self::handle_connection(stream, &routing_table).await {
                            Ok(()) => {}
                            Err(RejectReason::Client(e)) => {
                                tracing::debug!(%peer_addr, error = %e, "tcp connection rejected");
                            }
                            Err(RejectReason::Server(e)) => {
                                tracing::warn!(%peer_addr, error = %e, "tcp connection failed");
                            }
                        }
                    });
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        routing_table: &RoutingTable,
    ) -> std::result::Result<(), RejectReason> {
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| RejectReason::Client(e.into()))?;

        let hello = match timeout(HANDSHAKE_TIMEOUT, Self::read_client_hello(&mut stream)).await {
            Ok(Ok(hello)) => hello,
            Ok(Err(e)) => return Err(RejectReason::Client(e)),
            Err(_) => {
                Self::reject(&mut stream, &TlsAlert::HANDSHAKE_FAILURE).await;
                return Err(RejectReason::Client(anyhow::anyhow!(
                    "no complete ClientHello within {HANDSHAKE_TIMEOUT:?} from {peer_addr}"
                )));
            }
        };

        let Some(sni) = hello.sni else {
            Self::reject(&mut stream, &TlsAlert::HANDSHAKE_FAILURE).await;
            return Err(RejectReason::Client(anyhow::anyhow!(
                "no SNI in ClientHello from {peer_addr}"
            )));
        };

        let Some(backend) = routing_table.lookup_by_hostname(&sni) else {
            Self::reject(&mut stream, &TlsAlert::UNRECOGNIZED_NAME).await;
            return Err(RejectReason::Client(anyhow::anyhow!(
                "no backend for SNI '{sni}' from {peer_addr}"
            )));
        };

        let mut backend_stream =
            match timeout(DIAL_TIMEOUT, TcpStream::connect(backend.tcp_addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    Self::reject(&mut stream, &TlsAlert::INTERNAL_ERROR).await;
                    return Err(RejectReason::Server(anyhow::anyhow!(
                        "dial backend {} for '{sni}': {e}",
                        backend.tcp_addr
                    )));
                }
                Err(_) => {
                    Self::reject(&mut stream, &TlsAlert::INTERNAL_ERROR).await;
                    return Err(RejectReason::Server(anyhow::anyhow!(
                        "dial backend {} for '{sni}' timed out after {DIAL_TIMEOUT:?}",
                        backend.tcp_addr
                    )));
                }
            };

        // Replay the handshake bytes we consumed, then get out of the way.
        if let Err(e) = backend_stream.write_all(&hello.bytes).await {
            return Err(RejectReason::Server(anyhow::anyhow!(
                "replay ClientHello to {}: {e}",
                backend.tcp_addr
            )));
        }

        let (client_bytes, backend_bytes) =
            tokio::io::copy_bidirectional(&mut stream, &mut backend_stream)
                .await
                .map_err(|e| RejectReason::Client(e.into()))?;

        tracing::debug!(
            %peer_addr,
            %sni,
            backend = %backend.tcp_addr,
            client_bytes,
            backend_bytes,
            "tcp connection closed"
        );

        Ok(())
    }

    /// Read until rustls reports a complete ClientHello.
    ///
    /// `Acceptor::accept` returning `Ok(None)` is the "need more bytes" signal: a
    /// ClientHello carrying a post-quantum key share exceeds one MSS, so it arrives in
    /// several segments and any single read can land mid-message.
    async fn read_client_hello(stream: &mut TcpStream) -> Result<BufferedHello> {
        let mut acceptor = Acceptor::default();
        let mut bytes = Vec::with_capacity(READ_CHUNK);
        let mut chunk = [0u8; READ_CHUNK];

        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                anyhow::bail!(
                    "connection closed after {} bytes, before a complete ClientHello",
                    bytes.len()
                );
            }

            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > MAX_HANDSHAKE_BYTES {
                anyhow::bail!(
                    "handshake exceeded {MAX_HANDSHAKE_BYTES} bytes without a complete ClientHello"
                );
            }

            // rustls reads a record at a time, so drain the chunk into it.
            let mut cursor = Cursor::new(&chunk[..n]);
            while (cursor.position() as usize) < n {
                match acceptor.read_tls(&mut cursor) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => anyhow::bail!("feeding handshake bytes to rustls: {e}"),
                }
            }

            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    // rustls lowercases the name and accepts only a single DNS name,
                    // rejecting IP literals and malformed values per RFC 6066.
                    let sni = accepted.client_hello().server_name().map(str::to_string);
                    return Ok(BufferedHello { bytes, sni });
                }
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    let mut encoded = Vec::new();
                    let _ = alert.write_all(&mut encoded);
                    if !encoded.is_empty() {
                        let _ = stream.write_all(&encoded).await;
                    }
                    let _ = stream.shutdown().await;
                    anyhow::bail!("malformed ClientHello: {e}");
                }
            }
        }
    }

    /// Send a fatal alert and close, so the peer sees a TLS-level rejection.
    async fn reject(stream: &mut TcpStream, alert: &[u8]) {
        let _ = stream.write_all(alert).await;
        let _ = stream.shutdown().await;
    }
}
