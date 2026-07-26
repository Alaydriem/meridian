/// Pre-encoded fatal TLS alert records, for rejecting a connection before any
/// ServerHello.
///
/// Dropping the socket instead sends RST — the client surfaces `ECONNRESET` mid-handshake
/// with nothing to distinguish "unknown host" from a network fault. An alert names the
/// reason at the TLS layer, which is what the client can actually report.
///
/// Layout is `ContentType(0x15) LegacyVersion(0x0303) Length(0x0002) Level Description`.
/// The legacy record version is what a server sends before version negotiation
/// completes (RFC 8446 §5.1).
pub struct TlsAlert;

impl TlsAlert {
    /// `unrecognized_name` (112) — the SNI parsed fine but names no known backend.
    pub const UNRECOGNIZED_NAME: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];

    /// `handshake_failure` (40) — no usable SNI in the ClientHello.
    pub const HANDSHAKE_FAILURE: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

    /// `internal_error` (80) — our fault: the backend is unreachable.
    pub const INTERNAL_ERROR: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50];
}
