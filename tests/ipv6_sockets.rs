//! Address-family behaviour of every socket Meridian binds.
//!
//! `config.listen` is handed to the UDP router and the TCP router alike, so a wildcard
//! IPv6 address has to mean the same thing to both: serve IPv4 and IPv6 from one bind.
//! The backend-facing ephemeral socket is different — it faces a single backend, so it
//! only has to match that backend's family.
//!
//! None of this is visible from reading a bind call. It depends on socket options and on
//! platform defaults that differ (Linux reads `net.ipv6.bindv6only`, Windows enables
//! IPV6_V6ONLY), so every case here is asserted by moving a real datagram or completing
//! a real connection.

use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream,
    UdpSocket as StdUdpSocket,
};
use std::sync::Arc;
use std::time::Duration;

use meridian::udp::{EphemeralSocketManager, SocketFactory};
use tokio_util::sync::CancellationToken;

const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The factory hands back non-blocking sockets for the worker loop. A test wants to
/// block on a single datagram instead, so it takes the socket back to blocking with a
/// bounded read timeout.
fn into_blocking_reader(socket: StdUdpSocket) -> StdUdpSocket {
    socket
        .set_nonblocking(false)
        .expect("return the socket to blocking mode");
    socket
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("bound the read so a failure is a failed assertion, not a hang");
    socket
}

/// The load-bearing property of a `[::]` ingress bind: IPv4 clients still arrive.
///
/// Left to the platform this is a coin toss — Linux reads `net.ipv6.bindv6only` and
/// Windows defaults IPV6_V6ONLY to *enabled*, which refuses IPv4 outright. Meridian
/// clears the flag explicitly, and this is what proves it: without that call this test
/// fails on Windows and on any host whose sysctl has been hardened.
#[test]
fn a_wildcard_ipv6_listener_receives_ipv4_datagrams() {
    let sockets = SocketFactory::bind_worker_sockets("[::]:0", 1).expect("bind [::]:0");
    let listener = into_blocking_reader(sockets.into_iter().next().expect("one socket"));
    let port = listener.local_addr().expect("local addr").port();

    let client = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind an IPv4 client");
    client
        .send_to(b"v4-to-wildcard-v6", (Ipv4Addr::LOCALHOST, port))
        .expect("send over IPv4");

    let mut buf = [0u8; 64];
    let (len, from) = listener.recv_from(&mut buf).expect(
        "a wildcard IPv6 listener must receive IPv4 datagrams; if this timed out, \
         IPV6_V6ONLY is set and every IPv4 client is being refused",
    );

    assert_eq!(&buf[..len], b"v4-to-wildcard-v6");
    assert!(
        from.is_ipv6(),
        "an IPv4 peer should surface as a v4-mapped IPv6 address, got {from}"
    );
}

/// The same listener must still serve the family it was actually asked for. Paired
/// with the test above, this is what shows the socket is dual-stack rather than
/// silently downgraded to IPv4.
#[test]
fn a_wildcard_ipv6_listener_receives_ipv6_datagrams() {
    let sockets = SocketFactory::bind_worker_sockets("[::]:0", 1).expect("bind [::]:0");
    let listener = into_blocking_reader(sockets.into_iter().next().expect("one socket"));
    let port = listener.local_addr().expect("local addr").port();

    let client = StdUdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind an IPv6 client");
    client
        .send_to(b"v6-to-wildcard-v6", (Ipv6Addr::LOCALHOST, port))
        .expect("send over IPv6");

    let mut buf = [0u8; 64];
    let (len, _) = listener
        .recv_from(&mut buf)
        .expect("a wildcard IPv6 listener must receive IPv6 datagrams");

    assert_eq!(&buf[..len], b"v6-to-wildcard-v6");
}

/// An operator who pins an IPv4 listen address is unaffected. Guards the branch every
/// current deployment takes.
#[test]
fn an_ipv4_listener_still_receives_ipv4_datagrams() {
    let sockets = SocketFactory::bind_worker_sockets("0.0.0.0:0", 1).expect("bind 0.0.0.0:0");
    let listener = into_blocking_reader(sockets.into_iter().next().expect("one socket"));
    let port = listener.local_addr().expect("local addr").port();

    let client = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind an IPv4 client");
    client
        .send_to(b"v4-to-v4", (Ipv4Addr::LOCALHOST, port))
        .expect("send over IPv4");

    let mut buf = [0u8; 64];
    let (len, from) = listener
        .recv_from(&mut buf)
        .expect("an IPv4 listener must receive IPv4 datagrams");

    assert_eq!(&buf[..len], b"v4-to-v4");
    assert!(from.is_ipv4(), "expected an unmapped IPv4 peer, got {from}");
}

async fn manager() -> Arc<EphemeralSocketManager> {
    let main_socket = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind a stand-in main socket"),
    );

    EphemeralSocketManager::new(main_socket, Duration::from_secs(60), 16)
}

/// The backend-facing socket has to match the backend's family: a socket bound to
/// `0.0.0.0` cannot `connect` to an IPv6 address, so hardcoding the IPv4 wildcard made
/// an IPv6 backend unreachable outright.
///
/// `connect` on UDP only installs a default destination, so nothing needs to be
/// listening for this to be a real exercise of the bind decision.
#[tokio::test]
async fn the_backend_facing_socket_matches_an_ipv6_backend() {
    let manager = manager().await;
    let backend = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);

    let socket = manager
        .get_or_create(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
            Some(b"dcid-v6"),
            backend,
            CancellationToken::new(),
        )
        .await
        .expect("an IPv6 backend must be reachable");

    assert!(
        socket.local_addr().expect("local addr").is_ipv6(),
        "the socket must be bound in the backend's family"
    );
}

#[tokio::test]
async fn the_backend_facing_socket_matches_an_ipv4_backend() {
    let manager = manager().await;
    let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

    let socket = manager
        .get_or_create(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_001),
            Some(b"dcid-v4"),
            backend,
            CancellationToken::new(),
        )
        .await
        .expect("an IPv4 backend must be reachable");

    assert!(
        socket.local_addr().expect("local addr").is_ipv4(),
        "an IPv4 backend must not drag the socket onto IPv6"
    );
}

/// Path conservation still holds across the family change: a client whose address
/// moves but whose DCID does not must reuse its socket rather than bind a new source
/// port, because each new source port costs the backend one of five QUIC paths.
#[tokio::test]
async fn a_rebound_client_keeps_its_backend_socket() {
    let manager = manager().await;
    let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let cancel = CancellationToken::new();

    let first = manager
        .get_or_create(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_000),
            Some(b"stable-dcid"),
            backend,
            cancel.clone(),
        )
        .await
        .expect("first attach");

    let after_rebind = manager
        .get_or_create(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_001),
            Some(b"stable-dcid"),
            backend,
            cancel,
        )
        .await
        .expect("attach after the client address changed");

    assert_eq!(
        first.local_addr().expect("first local addr"),
        after_rebind.local_addr().expect("second local addr"),
        "a NAT rebind must not spend a backend QUIC path"
    );
}

/// `config.listen` is handed to the TCP router and the UDP router alike, so a wildcard
/// IPv6 address has to mean the same thing to both. `TcpListener::bind` never touches
/// IPV6_V6ONLY, so without routing the bind through `SocketFactory` the same host would
/// serve both families over QUIC and IPv6 only over TCP.
#[test]
fn a_wildcard_ipv6_tcp_listener_accepts_ipv4_connections() {
    let listener = SocketFactory::bind_tcp_listener("[::]:0").expect("bind TCP [::]:0");
    listener
        .set_nonblocking(false)
        .expect("block on a single accept");
    let port = listener.local_addr().expect("local addr").port();

    let dialer = std::thread::spawn(move || {
        StdTcpStream::connect((Ipv4Addr::LOCALHOST, port))
    });

    let (_stream, from) = listener.accept().expect(
        "a wildcard IPv6 TCP listener must accept IPv4 connections; if this failed,          IPV6_V6ONLY is set and every IPv4 client is being refused",
    );

    dialer.join().expect("dialer thread").expect("IPv4 connect");
    assert!(
        from.is_ipv6(),
        "an IPv4 peer should surface as a v4-mapped IPv6 address, got {from}"
    );
}

/// The same listener must still accept the family it was asked for.
#[test]
fn a_wildcard_ipv6_tcp_listener_accepts_ipv6_connections() {
    let listener = SocketFactory::bind_tcp_listener("[::]:0").expect("bind TCP [::]:0");
    listener
        .set_nonblocking(false)
        .expect("block on a single accept");
    let port = listener.local_addr().expect("local addr").port();

    let dialer = std::thread::spawn(move || {
        StdTcpStream::connect((Ipv6Addr::LOCALHOST, port))
    });

    listener
        .accept()
        .expect("a wildcard IPv6 TCP listener must accept IPv6 connections");
    dialer.join().expect("dialer thread").expect("IPv6 connect");
}

/// An operator who pins an IPv4 listen address is unaffected on the TCP path too.
#[test]
fn an_ipv4_tcp_listener_accepts_ipv4_connections() {
    let listener = SocketFactory::bind_tcp_listener("0.0.0.0:0").expect("bind TCP 0.0.0.0:0");
    listener
        .set_nonblocking(false)
        .expect("block on a single accept");
    let port = listener.local_addr().expect("local addr").port();

    let dialer = std::thread::spawn(move || {
        StdTcpStream::connect((Ipv4Addr::LOCALHOST, port))
    });

    let (_stream, from) = listener
        .accept()
        .expect("an IPv4 TCP listener must accept IPv4 connections");
    dialer.join().expect("dialer thread").expect("IPv4 connect");

    assert!(from.is_ipv4(), "expected an unmapped IPv4 peer, got {from}");
}
