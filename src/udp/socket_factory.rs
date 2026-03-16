use std::net::UdpSocket as StdUdpSocket;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

/// Create `count` UDP sockets bound to `addr`, using SO_REUSEPORT where available.
///
/// On Linux/macOS: each socket has SO_REUSEPORT set, allowing the kernel to
/// distribute incoming datagrams across workers by 4-tuple hash.
///
/// On Windows: SO_REUSEPORT is not available. If `count > 1`, logs a warning
/// and returns a single socket (callers should clamp worker count to 1).
pub fn bind_worker_sockets(addr: &str, count: usize) -> Result<Vec<StdUdpSocket>> {
    let addr: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address: {addr}"))?;

    let count = count.max(1);

    #[cfg(unix)]
    {
        bind_reuseport(&addr, count)
    }

    #[cfg(windows)]
    {
        bind_windows(&addr, count)
    }
}

#[cfg(unix)]
fn bind_reuseport(addr: &std::net::SocketAddr, count: usize) -> Result<Vec<StdUdpSocket>> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let mut sockets = Vec::with_capacity(count);
    for _ in 0..count {
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create UDP socket")?;
        socket
            .set_reuse_port(true)
            .context("failed to set SO_REUSEPORT")?;
        socket.set_nonblocking(true)?;
        socket
            .bind(&(*addr).into())
            .with_context(|| format!("failed to bind to {addr}"))?;
        sockets.push(socket.into());
    }

    Ok(sockets)
}

#[cfg(windows)]
fn bind_windows(addr: &std::net::SocketAddr, count: usize) -> Result<Vec<StdUdpSocket>> {
    if count > 1 {
        tracing::warn!(
            requested = count,
            "SO_REUSEPORT not available on Windows, using single worker"
        );
    }

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create UDP socket")?;
    socket.set_nonblocking(true)?;
    socket
        .bind(&(*addr).into())
        .with_context(|| format!("failed to bind to {addr}"))?;

    let std_socket: StdUdpSocket = socket.into();
    disable_connection_reset(&std_socket);

    Ok(vec![std_socket])
}

/// Disable Windows SIO_UDP_CONNRESET on a std UdpSocket.
#[cfg(windows)]
fn disable_connection_reset(socket: &StdUdpSocket) {
    use std::os::windows::io::AsRawSocket;

    const SIO_UDP_CONNRESET: u32 = 0x9800000C;

    let raw = socket.as_raw_socket() as usize;
    let mut bytes_returned: u32 = 0;
    let enable: u32 = 0;

    unsafe extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const u32,
            cbInBuffer: u32,
            lpvOutBuffer: *mut u8,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut u8,
            lpCompletionRoutine: *mut u8,
        ) -> i32;
    }

    unsafe {
        let _ = WSAIoctl(
            raw,
            SIO_UDP_CONNRESET,
            &enable,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}
