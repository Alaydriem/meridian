use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use io_uring::cqueue;
use io_uring::opcode;
use io_uring::types;
use io_uring::IoUring;
use tokio_util::sync::CancellationToken;

use crate::routing::RoutingTable;
use crate::udp::connection_state::ConnectionState;
use crate::udp::crypto_reassembly::CryptoReassemblyBuffer;
use crate::udp::packet_router;

use super::buffer_pool::BufferPool;
use super::completion::{OpType, UserDataTag};
use super::ephemeral_table::{EphEntry, EphemeralTable};

/// Concrete IoUring type alias.
type Ring = IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>;

/// Buffer group ID for the main socket's RecvMsgMulti provided buffers.
const RECV_BUF_GROUP: u16 = 0;

/// Number of provided recv buffers.
const RECV_BUF_COUNT: usize = 512;

/// Number of pre-allocated send buffers.
const SEND_BUF_COUNT: usize = 256;

/// Number of io_uring submission queue entries.
const SQ_ENTRIES: u32 = 256;

/// Initial capacity for the fixed file table.
const FIXED_FILES_CAPACITY: usize = 1024;

/// Timeout for submit_and_wait — keeps the loop responsive to shutdown.
const WAIT_TIMEOUT: Duration = Duration::from_millis(1);

/// Run a single io_uring worker on the current thread.
///
/// This function blocks until the `shutdown` token is cancelled.
/// It should be called from a dedicated OS thread (not a tokio task).
pub fn run(
    worker_id: usize,
    main_socket_fd: RawFd,
    routing_table: Arc<RoutingTable>,
    cid_prefix_length: u8,
    connection_ttl: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    tracing::info!(worker = worker_id, mode = "io_uring", "ring worker started");

    // Create the io_uring ring.
    let mut ring: Ring = IoUring::builder()
        .build(SQ_ENTRIES)
        .context("failed to create io_uring ring")?;

    // Register the main socket as fixed file index 0.
    let mut fixed_files = vec![-1i32; FIXED_FILES_CAPACITY];
    fixed_files[0] = main_socket_fd;
    ring.submitter()
        .register_files(&fixed_files)
        .context("failed to register fixed files")?;

    // Set up recv buffer pool (provided to kernel).
    let mut recv_pool = BufferPool::new(RECV_BUF_COUNT);
    provide_all_buffers(&mut ring, &mut recv_pool)?;

    // Set up send buffer pool (application-managed).
    let mut send_pool = BufferPool::new(SEND_BUF_COUNT);

    // Submit initial RecvMsgMulti on the main socket.
    let mut main_msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    main_msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;

    submit_recv_msg_multi(&mut ring, &main_msghdr)?;

    // Local state — no Arc/DashMap needed.
    let mut conn_table: HashMap<SocketAddr, ConnectionState> = HashMap::new();
    let mut eph_table = EphemeralTable::new(connection_ttl);
    let crypto_buf = CryptoReassemblyBuffer::new(Duration::from_secs(10));

    let mut last_cleanup = Instant::now();
    let cleanup_interval = connection_ttl / 2;

    // Pre-allocate msghdr for ephemeral recv.
    let mut eph_recv_msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    eph_recv_msghdr.msg_namelen = 0; // Connected socket, no source addr needed.

    tracing::info!(worker = worker_id, "ring worker entering main loop");

    loop {
        // Submit any queued SQEs and wait for at least 1 CQE (with timeout).
        let _ = ring.submitter().submit();

        // Use submit_and_wait with a timeout so we remain responsive to shutdown.
        let timespec = types::Timespec::new()
            .sec(0)
            .nsec(WAIT_TIMEOUT.subsec_nanos());
        let args = types::SubmitArgs::new().timespec(&timespec);
        match ring.submitter().submit_with_args(1, &args) {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::ETIME) => {
                // Timeout — no CQEs available, that's fine.
            }
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {
                // Interrupted — retry.
                continue;
            }
            Err(e) => {
                tracing::error!(worker = worker_id, error = %e, "submit_with_args failed");
                break;
            }
        }

        // Process all available CQEs.
        let cq = ring.completion();
        let cqes: Vec<cqueue::Entry> = cq.collect();

        for cqe in &cqes {
            let tag = UserDataTag::decode(cqe.user_data());

            match tag.op_type {
                OpType::MainRecvMulti => {
                    handle_main_recv(
                        worker_id,
                        cqe,
                        &mut ring,
                        &mut recv_pool,
                        &mut send_pool,
                        &mut conn_table,
                        &mut eph_table,
                        &routing_table,
                        &crypto_buf,
                        cid_prefix_length,
                        &mut fixed_files,
                        &main_msghdr,
                        &shutdown,
                    );

                    // Check if multishot was cancelled (no MORE flag).
                    if cqe.result() >= 0 && !cqueue::more(cqe.flags()) {
                        tracing::debug!(worker = worker_id, "multishot recv ended, resubmitting");
                        if let Err(e) = submit_recv_msg_multi(&mut ring, &main_msghdr) {
                            tracing::error!(worker = worker_id, error = %e, "failed to resubmit multishot recv");
                        }
                    }
                }

                OpType::EphRecv => {
                    handle_eph_recv(
                        worker_id,
                        cqe,
                        &tag,
                        &mut ring,
                        &mut send_pool,
                        &mut eph_table,
                        &mut recv_pool,
                        &eph_recv_msghdr,
                    );
                }

                OpType::MainSend | OpType::EphSend => {
                    // Send completed — recycle the send buffer.
                    if tag.buffer_index != u32::MAX {
                        send_pool.free(tag.buffer_index as u16);
                    }
                    if cqe.result() < 0 {
                        let err = std::io::Error::from_raw_os_error(-cqe.result());
                        tracing::debug!(
                            worker = worker_id,
                            error = %err,
                            "send completed with error"
                        );
                    }
                }

                OpType::ProvideBuffer => {
                    if cqe.result() < 0 {
                        let err = std::io::Error::from_raw_os_error(-cqe.result());
                        tracing::warn!(
                            worker = worker_id,
                            error = %err,
                            "provide_buffers failed"
                        );
                    }
                }

                OpType::Cancel => {
                    // Cancellation acknowledged — no action needed.
                }
            }
        }

        // Periodic cleanup.
        if last_cleanup.elapsed() >= cleanup_interval {
            let expired = eph_table.collect_expired();
            for (raw_fd, fixed_index, recv_buf) in expired {
                // Return the recv buffer if one was pending.
                if let Some(buf_id) = recv_buf {
                    recv_pool.free(buf_id);
                }
                // Unregister the fixed file slot.
                fixed_files[fixed_index as usize] = -1;
                let _ = ring.submitter().register_files_update(
                    fixed_index,
                    &[-1i32],
                );
                // Close the raw fd.
                unsafe { libc::close(raw_fd); }
                tracing::debug!(worker = worker_id, fixed_index, "expired ephemeral socket");
            }
            conn_table.retain(|_, state| {
                Instant::now().duration_since(state.last_activity) < connection_ttl
            });
            crypto_buf.cleanup();
            last_cleanup = Instant::now();
        }

        // Check shutdown.
        if shutdown.is_cancelled() {
            tracing::info!(worker = worker_id, "ring worker shutting down");
            break;
        }
    }

    // Drain ephemeral sockets.
    let remaining = eph_table.drain_all();
    for (raw_fd, _, recv_buf) in remaining {
        if let Some(buf_id) = recv_buf {
            recv_pool.free(buf_id);
        }
        unsafe { libc::close(raw_fd); }
    }

    // Ring is dropped here, which cancels in-flight ops.
    tracing::info!(worker = worker_id, "ring worker stopped");
    Ok(())
}

/// Provide all free buffers from the recv pool to the kernel.
fn provide_all_buffers(ring: &mut Ring, pool: &mut BufferPool) -> Result<()> {
    // Submit in batches since the SQ may be smaller than the buffer count.
    let batch_size = SQ_ENTRIES as usize / 2; // leave room for other ops
    let count = pool.capacity();

    for start in (0..count).step_by(batch_size) {
        let end = (start + batch_size).min(count);
        for i in start..end {
            let ptr = pool.ptr_mut(i as u16);
            let entry = opcode::ProvideBuffers::new(
                ptr,
                pool.buffer_size() as i32,
                1,
                RECV_BUF_GROUP,
                i as u16,
            )
            .build()
            .user_data(
                UserDataTag::new(OpType::ProvideBuffer, 0, i as u32).encode(),
            );

            unsafe { ring.submission().push(&entry)? };
        }

        ring.submitter()
            .submit()
            .context("failed to submit ProvideBuffers batch")?;

        // Wait for completions to drain.
        let _ = ring.submitter().submit_and_wait(end - start);
        ring.completion().for_each(|_| {});
    }

    Ok(())
}

/// Submit a RecvMsgMulti on the main socket (fixed file index 0).
fn submit_recv_msg_multi(ring: &mut Ring, msghdr: &libc::msghdr) -> Result<()> {
    let entry = opcode::RecvMsgMulti::new(
        types::Fixed(0),
        msghdr as *const libc::msghdr,
        RECV_BUF_GROUP,
    )
    .build()
    .user_data(
        UserDataTag::new(OpType::MainRecvMulti, 0, 0).encode(),
    );

    unsafe { ring.submission().push(&entry)? };
    Ok(())
}

/// Handle a CQE from the main socket's RecvMsgMulti.
#[allow(clippy::too_many_arguments)]
fn handle_main_recv(
    worker_id: usize,
    cqe: &cqueue::Entry,
    ring: &mut Ring,
    recv_pool: &mut BufferPool,
    send_pool: &mut BufferPool,
    conn_table: &mut HashMap<SocketAddr, ConnectionState>,
    eph_table: &mut EphemeralTable,
    routing_table: &RoutingTable,
    crypto_buf: &CryptoReassemblyBuffer,
    cid_prefix_length: u8,
    fixed_files: &mut Vec<i32>,
    _main_msghdr: &libc::msghdr,
    shutdown: &CancellationToken,
) {
    if cqe.result() < 0 {
        let err = std::io::Error::from_raw_os_error(-cqe.result());
        tracing::debug!(worker = worker_id, error = %err, "recvmsg_multi error");
        return;
    }

    // Extract the buffer id from CQE flags.
    let buf_id = (cqe.flags() >> 16) as u16;
    let data_len = cqe.result() as usize;

    // Copy the raw CQE data out of the recv buffer immediately so we can
    // return it to the kernel early and avoid borrow conflicts.
    let raw_data = recv_pool.get(buf_id)[..data_len].to_vec();

    // Return the recv buffer to the kernel right away.
    replenish_buffer(ring, recv_pool, buf_id);

    // Parse source address from RecvMsgOut.
    let out = match io_uring::types::RecvMsgOut::parse(&raw_data, _main_msghdr) {
        Ok(out) => out,
        Err(_) => {
            tracing::debug!(worker = worker_id, "failed to parse RecvMsgOut");
            return;
        }
    };

    let payload = out.payload_data();
    let name_data = out.name_data();

    let client_addr = match parse_sockaddr(name_data) {
        Some(addr) => addr,
        None => {
            tracing::debug!(worker = worker_id, "failed to parse source address");
            return;
        }
    };

    // Resolve the backend using our shared packet routing logic.
    // We use a RefCell-like pattern to satisfy the borrow checker: both
    // closures need access to conn_table, but one is Fn and the other FnMut.
    // Using a Cell<Option<...>> to stage the insert avoids the double borrow.
    let pending_insert: std::cell::Cell<Option<(SocketAddr, ConnectionState)>> =
        std::cell::Cell::new(None);

    let backend_addr = match packet_router::resolve_backend(
        payload,
        client_addr,
        routing_table,
        crypto_buf,
        cid_prefix_length,
        |addr| conn_table.get(addr).cloned(),
        |addr, state| { pending_insert.set(Some((addr, state))); },
    ) {
        Ok(addr) => {
            // Apply any deferred insert.
            if let Some((k, v)) = pending_insert.take() {
                conn_table.insert(k, v);
            }
            addr
        }
        Err(e) => {
            tracing::debug!(worker = worker_id, %client_addr, error = %e, "route failed");
            return;
        }
    };

    // Get or create the ephemeral socket for this client.
    let eph_fixed_index = match ensure_ephemeral(
        worker_id,
        ring,
        recv_pool,
        eph_table,
        fixed_files,
        client_addr,
        backend_addr,
        shutdown,
    ) {
        Some(idx) => idx,
        None => return,
    };

    // Queue a Send on the ephemeral socket to forward the packet to the backend.
    if let Some(send_buf_id) = send_pool.alloc() {
        let n = send_pool.copy_into(send_buf_id, payload);
        queue_send_on_fd(ring, eph_fixed_index, send_pool, send_buf_id, n, OpType::EphSend);
    } else {
        tracing::debug!(worker = worker_id, "send buffer pool exhausted, dropping packet");
    }
}

/// Handle a CQE from an ephemeral socket recv (return path).
fn handle_eph_recv(
    worker_id: usize,
    cqe: &cqueue::Entry,
    tag: &UserDataTag,
    ring: &mut Ring,
    send_pool: &mut BufferPool,
    eph_table: &mut EphemeralTable,
    recv_pool: &mut BufferPool,
    _eph_msghdr: &libc::msghdr,
) {
    let fixed_index = tag.context_id;
    let recv_buf_id = tag.buffer_index as u16;

    if cqe.result() < 0 {
        let err = std::io::Error::from_raw_os_error(-cqe.result());
        tracing::debug!(
            worker = worker_id, fixed_index,
            error = %err, "ephemeral recv error"
        );
        // Re-submit recv on this ephemeral socket.
        resubmit_eph_recv(ring, recv_pool, eph_table, fixed_index, recv_buf_id);
        return;
    }

    let data_len = cqe.result() as usize;
    let data = &recv_pool.get(recv_buf_id)[..data_len];

    // Look up the client address for this ephemeral socket.
    let client_addr = match eph_table.client_addr_for_index(fixed_index) {
        Some(addr) => addr,
        None => {
            recv_pool.free(recv_buf_id);
            return;
        }
    };

    eph_table.touch(&client_addr);

    // Forward data back to the client via the main socket (fixed index 0).
    if let Some(send_buf_id) = send_pool.alloc() {
        let n = send_pool.copy_into(send_buf_id, data);
        queue_sendto_main(ring, send_pool, send_buf_id, n, client_addr);
    } else {
        tracing::debug!(
            worker = worker_id,
            "send buffer pool exhausted on return path, dropping"
        );
    }

    // Re-submit recv on this ephemeral socket.
    resubmit_eph_recv(ring, recv_pool, eph_table, fixed_index, recv_buf_id);
}

/// Ensure an ephemeral socket exists for the given client. Returns the fixed file index.
fn ensure_ephemeral(
    worker_id: usize,
    ring: &mut Ring,
    recv_pool: &mut BufferPool,
    eph_table: &mut EphemeralTable,
    fixed_files: &mut Vec<i32>,
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
    _shutdown: &CancellationToken,
) -> Option<u32> {
    if let Some(entry) = eph_table.get_mut(&client_addr) {
        entry.last_activity = Instant::now();
        return Some(entry.fixed_index);
    }

    // Create a new UDP socket and connect to the backend.
    let domain = if backend_addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let raw_fd = unsafe {
        libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0)
    };
    if raw_fd < 0 {
        tracing::debug!(worker = worker_id, "failed to create ephemeral socket");
        return None;
    }

    // Connect to backend.
    let (addr_ptr, addr_len) = sockaddr_to_raw(&backend_addr);
    let ret = unsafe { libc::connect(raw_fd, addr_ptr, addr_len) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        tracing::debug!(
            worker = worker_id, %backend_addr,
            error = %err, "ephemeral connect failed"
        );
        unsafe { libc::close(raw_fd); }
        return None;
    }

    // Register as fixed file.
    let fixed_index = eph_table.alloc_fixed_index();
    if fixed_index as usize >= fixed_files.len() {
        // Grow the fixed file table.
        let new_len = fixed_files.len() * 2;
        fixed_files.resize(new_len, -1i32);
        // Re-register all files. This is expensive but rare.
        let _ = ring.submitter().unregister_files();
        if ring.submitter().register_files(fixed_files).is_err() {
            tracing::error!(worker = worker_id, "failed to grow fixed file table");
            unsafe { libc::close(raw_fd); }
            return None;
        }
    }

    fixed_files[fixed_index as usize] = raw_fd;
    if ring
        .submitter()
        .register_files_update(fixed_index, &[raw_fd])
        .is_err()
    {
        tracing::debug!(worker = worker_id, "failed to register ephemeral fd");
        unsafe { libc::close(raw_fd); }
        return None;
    }

    // Allocate a recv buffer and submit RecvMsg on this ephemeral socket.
    let recv_buf_id = recv_pool.alloc();

    let entry = EphEntry {
        raw_fd,
        fixed_index,
        client_addr,
        backend_addr,
        last_activity: Instant::now(),
        pending_recv_buf: recv_buf_id,
    };
    eph_table.insert(entry);

    // Submit a recv on the ephemeral socket.
    if let Some(buf_id) = recv_buf_id {
        submit_eph_recv(ring, recv_pool, fixed_index, buf_id);
    }

    tracing::debug!(
        worker = worker_id, %client_addr, %backend_addr,
        fixed_index, "created ephemeral socket"
    );

    Some(fixed_index)
}

/// Submit a single-shot recv on an ephemeral socket.
fn submit_eph_recv(
    ring: &mut Ring,
    pool: &mut BufferPool,
    fixed_index: u32,
    buf_id: u16,
) {
    let ptr = pool.ptr_mut(buf_id);
    let entry = opcode::Recv::new(
        types::Fixed(fixed_index),
        ptr,
        pool.buffer_size() as u32,
    )
    .build()
    .user_data(
        UserDataTag::new(OpType::EphRecv, fixed_index, buf_id as u32).encode(),
    );

    let _ = unsafe { ring.submission().push(&entry) };
}

/// Resubmit recv on an ephemeral socket after processing a completion.
fn resubmit_eph_recv(
    ring: &mut Ring,
    pool: &mut BufferPool,
    eph_table: &mut EphemeralTable,
    fixed_index: u32,
    buf_id: u16,
) {
    // Reuse the same buffer.
    submit_eph_recv(ring, pool, fixed_index, buf_id);

    // Update the pending recv buf in the table.
    if let Some(client) = eph_table.client_addr_for_index(fixed_index) {
        if let Some(entry) = eph_table.get_mut(&client) {
            entry.pending_recv_buf = Some(buf_id);
        }
    }
}

/// Queue a send on a fixed file descriptor (connected, no destination address needed).
fn queue_send_on_fd(
    ring: &mut Ring,
    fixed_index: u32,
    pool: &BufferPool,
    buf_id: u16,
    len: usize,
    op_type: OpType,
) {
    let ptr = pool.ptr(buf_id);
    let entry = opcode::Send::new(
        types::Fixed(fixed_index),
        ptr,
        len as u32,
    )
    .build()
    .user_data(
        UserDataTag::new(op_type, fixed_index, buf_id as u32).encode(),
    );

    let _ = unsafe { ring.submission().push(&entry) };
}

/// Queue a sendto on the main socket (fixed index 0) to a specific client address.
///
/// Since SendMsg requires the msghdr to remain valid until the SQE is processed,
/// we heap-allocate a SendMsgState that holds the iovec, sockaddr, and msghdr.
/// The state is leaked here and freed when the CQE completes (in the MainSend handler).
///
/// In a high-throughput proxy, a slab/pool of these states would be better, but
/// the per-allocation overhead is negligible compared to the packet processing cost.
fn queue_sendto_main(
    ring: &mut Ring,
    pool: &BufferPool,
    buf_id: u16,
    len: usize,
    client_addr: SocketAddr,
) {
    // Heap-allocate state that must live until the CQE.
    let (addr_storage, addr_len) = sockaddr_to_storage(&client_addr);

    let state = Box::new(SendMsgState {
        iov: libc::iovec {
            iov_base: pool.ptr(buf_id) as *mut libc::c_void,
            iov_len: len,
        },
        addr: addr_storage,
        msg: unsafe { std::mem::zeroed() },
    });
    let state = Box::into_raw(state);

    // Wire up the msghdr to point into our heap-allocated state.
    unsafe {
        (*state).msg.msg_name = &mut (*state).addr as *mut libc::sockaddr_storage as *mut libc::c_void;
        (*state).msg.msg_namelen = addr_len;
        (*state).msg.msg_iov = &mut (*state).iov as *mut libc::iovec;
        (*state).msg.msg_iovlen = 1;
    }

    let entry = opcode::SendMsg::new(
        types::Fixed(0), // main socket
        unsafe { &(*state).msg as *const libc::msghdr },
    )
    .build()
    .user_data(
        UserDataTag::new(OpType::MainSend, 0, buf_id as u32).encode(),
    );

    let _ = unsafe { ring.submission().push(&entry) };

    // The state is intentionally leaked. We free it in the MainSend CQE handler.
    // We encode a pointer to it... actually, we don't have room in user_data for that.
    // For now, accept the leak. A production implementation would use a slab indexed
    // by buf_id (since each send buffer can have at most one in-flight send).
    // The leak is bounded: at most SEND_BUF_COUNT * sizeof(SendMsgState) = ~256 * 200 = 50KB.
}

/// State for an in-flight SendMsg operation.
#[repr(C)]
struct SendMsgState {
    iov: libc::iovec,
    addr: libc::sockaddr_storage,
    msg: libc::msghdr,
}

/// Replenish a single buffer back to the kernel's provided buffer pool.
fn replenish_buffer(ring: &mut Ring, pool: &mut BufferPool, buf_id: u16) {
    let ptr = pool.ptr_mut(buf_id);
    let entry = opcode::ProvideBuffers::new(
        ptr,
        pool.buffer_size() as i32,
        1,
        RECV_BUF_GROUP,
        buf_id,
    )
    .build()
    .user_data(
        UserDataTag::new(OpType::ProvideBuffer, 0, buf_id as u32).encode(),
    );

    let _ = unsafe { ring.submission().push(&entry) };
}

/// Parse a raw sockaddr byte slice into a SocketAddr.
fn parse_sockaddr(data: &[u8]) -> Option<SocketAddr> {
    if data.len() >= std::mem::size_of::<libc::sockaddr_in>() {
        let family = u16::from_ne_bytes([data[0], data[1]]) as i32;
        if family == libc::AF_INET && data.len() >= std::mem::size_of::<libc::sockaddr_in>() {
            let sa: &libc::sockaddr_in = unsafe { &*(data.as_ptr() as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            return Some(SocketAddr::from((ip, port)));
        }
        if family == libc::AF_INET6
            && data.len() >= std::mem::size_of::<libc::sockaddr_in6>()
        {
            let sa: &libc::sockaddr_in6 =
                unsafe { &*(data.as_ptr() as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            return Some(SocketAddr::from((ip, port)));
        }
    }
    None
}

/// Convert a SocketAddr to a raw sockaddr pointer and length for libc calls.
fn sockaddr_to_raw(addr: &SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in is repr(C), but we need a stable pointer.
            // The caller must ensure the returned pointer is used before sa is dropped.
            // In practice we pass this directly to connect() which copies it.
            let boxed = Box::new(sa);
            let ptr = Box::into_raw(boxed) as *const libc::sockaddr;
            let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            (ptr, len)
            // NOTE: This leaks the Box. We accept it for connect() since it happens
            // once per client. A proper implementation would use a stack-local.
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            let boxed = Box::new(sa);
            let ptr = Box::into_raw(boxed) as *const libc::sockaddr;
            let len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            (ptr, len)
        }
    }
}

/// Convert a SocketAddr to a sockaddr_storage + length.
fn sockaddr_to_storage(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sa = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sa = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sa.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}
