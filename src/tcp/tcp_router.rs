use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;
use crate::tls::SniParser;

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
        let listener = TcpListener::bind(&self.listen_addr).await?;
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
                        if let Err(e) = handle_connection(stream, &routing_table).await {
                            tracing::warn!(%peer_addr, error = %e, "tcp connection failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(stream: TcpStream, routing_table: &RoutingTable) -> Result<()> {
    let peer_addr = stream.peer_addr()?;

    // Peek at the ClientHello without consuming bytes
    let mut buf = [0u8; 4096];
    let n = stream.peek(&mut buf).await?;

    let sni = SniParser::extract_sni_from_record(&buf[..n]).ok_or_else(|| {
        anyhow::anyhow!("no SNI found in ClientHello from {peer_addr}")
    })?;

    let backend = routing_table.lookup_by_hostname(&sni).ok_or_else(|| {
        anyhow::anyhow!("no backend for SNI '{sni}' from {peer_addr}")
    })?;

    let span = tracing::debug_span!("tcp_conn", %peer_addr, %sni, backend = %backend.tcp_addr);
    let _enter = span.enter();

    tracing::debug!("routing tcp connection");

    let mut backend_stream = TcpStream::connect(backend.tcp_addr).await?;
    let mut client_stream = stream;

    let (client_bytes, backend_bytes) =
        tokio::io::copy_bidirectional(&mut client_stream, &mut backend_stream).await?;

    tracing::debug!(client_bytes, backend_bytes, "tcp connection closed");

    Ok(())
}
