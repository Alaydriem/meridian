use anyhow::{Context, Result};

pub struct UringProbe;

impl UringProbe {
    /// Check that the running kernel supports the io_uring features we need.
    ///
    /// Requirements:
    /// - io_uring basic support (kernel 5.1+)
    /// - `IORING_OP_RECVMSG` (kernel 5.3+)
    /// - `IORING_OP_SENDMSG` (kernel 5.3+)
    /// - Multishot recv (kernel 6.0+)
    ///
    /// Returns `Ok(())` if supported, or an error with a descriptive message.
    pub fn check_io_uring_support() -> Result<()> {
        use io_uring::IoUring;

        // Try to create a minimal ring.
        let ring: IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry> = IoUring::builder()
            .build(4)
            .context("io_uring not supported on this kernel")?;

        // Probe for supported opcodes.
        let mut probe = io_uring::Probe::new();
        ring.submitter()
            .register_probe(&mut probe)
            .context("failed to probe io_uring capabilities")?;

        if !probe.is_supported(io_uring::opcode::RecvMsg::CODE) {
            anyhow::bail!(
                "kernel does not support IORING_OP_RECVMSG (requires kernel 5.3+)"
            );
        }

        if !probe.is_supported(io_uring::opcode::SendMsg::CODE) {
            anyhow::bail!(
                "kernel does not support IORING_OP_SENDMSG (requires kernel 5.3+)"
            );
        }

        // Check for RecvMsgMulti — it shares the same opcode as RecvMsg but
        // uses the IOSQE_BUFFER_SELECT flag + IORING_RECV_MULTISHOT.
        // We can't directly probe for multishot, but we can check for
        // ProvideBuffers which is required for it (kernel 5.7+).
        if !probe.is_supported(io_uring::opcode::ProvideBuffers::CODE) {
            anyhow::bail!(
                "kernel does not support IORING_OP_PROVIDE_BUFFERS (requires kernel 5.7+). \
                 Multishot recv requires kernel 6.0+"
            );
        }

        // Check kernel version for multishot (6.0+) via uname.
        Self::check_kernel_version(6, 0)?;

        tracing::info!("io_uring support verified (multishot recv available)");
        Ok(())
    }

    /// Parse the kernel version from uname and check it meets the minimum.
    fn check_kernel_version(min_major: u32, min_minor: u32) -> Result<()> {
        let uname = Self::rustix_uname()
            .context("failed to get kernel version")?;

        let version_str = uname.trim();
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() < 2 {
            anyhow::bail!("unexpected kernel version format: {version_str}");
        }

        let major: u32 = parts[0]
            .parse()
            .with_context(|| format!("invalid major version in: {version_str}"))?;
        // Minor may have a suffix like "0-rc1" or "5-generic"
        let minor_str = parts[1].split('-').next().unwrap_or(parts[1]);
        let minor: u32 = minor_str
            .parse()
            .with_context(|| format!("invalid minor version in: {version_str}"))?;

        if (major, minor) < (min_major, min_minor) {
            anyhow::bail!(
                "kernel {major}.{minor} does not meet minimum {min_major}.{min_minor} \
                 required for io_uring multishot recv"
            );
        }

        Ok(())
    }

    /// Get kernel version string using libc::uname.
    fn rustix_uname() -> Result<String> {
        unsafe {
            let mut info: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut info) != 0 {
                anyhow::bail!("uname() failed");
            }
            let release = std::ffi::CStr::from_ptr(info.release.as_ptr());
            Ok(release.to_string_lossy().into_owned())
        }
    }
}
