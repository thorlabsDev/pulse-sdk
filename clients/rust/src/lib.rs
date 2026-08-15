//! Rust client SDK for the **pulse** QUIC decoded-shred transaction stream
//! (wire v2).
//!
//! Two tiers, one connection each (the server selects the tier from the first
//! control message, which this SDK always negotiates to wire v2 —
//! [`thornode_pulse_wire::frame::WIRE_VERSION`]):
//!   * [`PulseClient::subscribe_sig_first`] — the low-latency **sig-first**
//!     tier. One QUIC DATAGRAM per tx ([`SigFirstItem`]: slot, per-subscriber
//!     `seq`, signature), fire-and-forget, no head-of-line blocking.
//!     [`SigFirstSub::gaps`] counts sequence numbers this subscriber may not
//!     have received (see its docs for the exact, honest guarantee — QUIC
//!     datagrams are unordered, so it over-reports under reordering).
//!   * [`PulseClient::subscribe_full`] — the **full-tx** tier. A single
//!     ordered QUIC stream that opens with a 6-byte preamble (this SDK
//!     reads and verifies it before the subscription is ever handed back —
//!     see [`Error::BadPreamble`]), then length-delimited, fully-decoded
//!     transaction frames ([`Frame::Tx`] wrapping [`FullTxV2`]). Stream bytes
//!     are ordered/reliable after the server enqueues them; the server's
//!     bounded pre-stream queue may shed transactions before that point.
//!
//! Both tiers also carry periodic heartbeats (idle-stream liveness, plus
//! `highest_seq` — the highest sequence number assigned to this subscriber so
//! far; `u64::MAX` means none yet, see [`NO_SEQ_ASSIGNED`]). A heartbeat is
//! folded into [`FullSub::heartbeat`] / [`SigFirstSub::gaps`] rather than
//! handed back as an item, and a message or datagram type this SDK doesn't
//! recognize is skipped rather than treated as an error — that is what keeps
//! a future wire addition from breaking this client (see [`Frame::Unknown`] /
//! [`Datagram::Unknown`]).
//!
//! ```no_run
//! use thornode_pulse::{Filter, PulseClient};
//! # async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let endpoint = std::env::var("PULSE_ADDR")
//!     .expect("set PULSE_ADDR to <HOST:PORT_FROM_DASHBOARD>");
//! let token = std::env::var("PULSE_TOKEN")
//!     .expect("set PULSE_TOKEN to <TOKEN_FROM_SAME_LOCATION>");
//! let account = std::env::var("PULSE_ACCOUNT")
//!     .expect("set PULSE_ACCOUNT to <ACCOUNT_OR_PROGRAM_PUBKEY>");
//! let client = PulseClient::connect_with_token(endpoint, token).await?;
//! let mut sub = client.subscribe_sig_first(&Filter::accounts([account])).await?;
//! while let Some(item) = sub.next().await? {
//!     println!("slot {} seq {} sig {}", item.slot, item.seq, bs58::encode(item.signature).into_string());
//! }
//! # Ok(()) }
//! ```
//!
//! The wire protocol is documented in `docs/PROTOCOL.md`. Frame/datagram
//! decoders and derived-field helpers are provided by `thornode-pulse-wire`
//! and re-exported here.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thornode_pulse_wire::frame::{decode_datagram, decode_frame};
use tokio::io::AsyncReadExt;

pub use thornode_pulse_wire::derive::{
    compute_unit_limit, compute_unit_price, fee_payer, program_ids, static_writable_accounts,
};
pub use thornode_pulse_wire::frame::{Datagram, Frame, FullTx, FullTxV2};
pub use thornode_pulse_wire::protocol::RetryClass;

/// Wire sentinel for a heartbeat's `highest_seq` meaning "nothing has been
/// assigned to this subscriber yet". `0` is a real, already-assigned sequence
/// number (the FIRST delivery on any connection is `seq == 0`), so `0` cannot
/// double as "none" — conflating the two would tell a client it already
/// missed transaction 0 the instant it connected.
pub const NO_SEQ_ASSIGNED: u64 = u64::MAX;

/// Subscription filter — the account predicate model the server applies. An
/// empty account filter ([`Filter::all`]) selects the unfiltered non-vote feed;
/// the access selected for the connection determines whether that feed is
/// available. Vote transactions remain excluded unless [`Filter::with_vote`]
/// is `true`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub account_include: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub account_exclude: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub account_required: Vec<String>,
    /// Vote selection (Yellowstone parity): `Some(true)` selects vote-only;
    /// `Some(false)` selects non-vote-only. Omitted by default (`None`), in
    /// which case the server also selects non-votes. One subscription cannot
    /// combine both sets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vote: Option<bool>,
}

impl Filter {
    /// Subscribe without an account predicate. Votes remain excluded by the
    /// server default; use [`Filter::with_vote`] with a separate connection to
    /// select the vote-only feed.
    pub fn all() -> Self {
        Filter::default()
    }

    /// Subscribe to transactions touching any of `accounts` (base58 pubkeys /
    /// program ids).
    pub fn accounts<I, S>(accounts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Filter {
            account_include: accounts.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Selects vote-only (`true`) or non-vote-only (`false`). Without this, the
    /// field is omitted and the server default selects non-votes. Use two
    /// connections when an application needs both sets.
    pub fn with_vote(mut self, include: bool) -> Self {
        self.vote = Some(include);
        self
    }
}

/// The JSON control message sent on a bi-directional stream. `v` always
/// declares wire v2 (this SDK speaks no other version); `full` selects the
/// tier and is only honored on the connection's FIRST control message;
/// `fields` opts into per-frame enrichment groups (currently just `"alt"`)
/// and is only meaningful on the full-tx tier — the sig-first tier carries no
/// enrichment under any subscription, so the server simply ignores it there.
#[derive(Serialize)]
struct Control<'a> {
    #[serde(flatten)]
    filter: &'a Filter,
    #[serde(skip_serializing_if = "str::is_empty")]
    token: &'a str,
    full: bool,
    v: u32,
    fields: &'a [&'a str],
}

/// A parsed `{"type":"...","ok":bool,...}` control-channel envelope — the
/// server's answer to any control message (first or update).
#[derive(Debug, Clone, Deserialize)]
pub struct Ack {
    /// Envelope discriminator. Only `"ack"` and `"error"` are valid; it is
    /// optional at deserialization time so validation can turn a missing or
    /// unknown value into a stable [`Error::BadFrame`] instead of exposing a
    /// serde implementation detail.
    #[serde(rename = "type", default)]
    pub message_type: Option<String>,
    /// The server's `error` envelope carries no `ok` field. Defaulting to
    /// `false` preserves it as a rejection so its code and reason remain
    /// available to the caller.
    #[serde(default)]
    pub ok: bool,
    /// Present when `ok` is `false`: why the message was rejected.
    #[serde(default)]
    pub reason: Option<String>,
    /// Present on a terminal error envelope. When supplied, the SDK preserves
    /// the same typed close/retry semantics as a QUIC application close.
    #[serde(default)]
    pub code: Option<u64>,
    /// Present only on the FIRST control message's ack: the wire version the
    /// server actually negotiated (`min(client_max, SERVER_WIRE_VERSION)`).
    #[serde(default)]
    pub v: Option<u32>,
}

/// Errors surfaced by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidEndpoint(String),
    Connect(String),
    ConnectTimeout,
    Io(String),
    Tls(String),
    /// An explicit insecure-local-dev constructor was given a non-loopback
    /// address. Unverified TLS is never permitted for a public endpoint.
    InsecureEndpointNotLoopback(SocketAddr),
    /// The peer terminated the connection with a Pulse application close.
    ApplicationClosed(CloseInfo),
    /// A datagram or stream frame that did not match the documented layout.
    BadFrame,
    /// A full-tx frame was truncated and the peer also supplied a terminal
    /// application close. Both signals matter: the close explains why the
    /// transport ended, while the framing error proves the final announced
    /// frame was incomplete.
    BadFrameWithClose(CloseInfo),
    /// The full-tx stream's opening bytes were not
    /// `thornode_pulse_wire::frame::PREAMBLE` — the strongest signal available that
    /// this client is not actually talking to a wire v2 server (or the
    /// stream was corrupted in transit). Deliberately its own loud variant:
    /// never folded into `BadFrame`, and never silently skipped — the
    /// preamble is the one place a client confirms it is speaking the
    /// protocol it thinks it is.
    BadPreamble,
    /// The full-tx preamble was incomplete or invalid and the peer also sent
    /// an application close. Both the protocol error and close context are
    /// preserved.
    BadPreambleWithClose(CloseInfo),
    /// The server answered a control message with `{"ok": false, ...}`.
    /// Carries the server's stated reason.
    Rejected(String),
    /// No complete control ack arrived within [`ACK_TIMEOUT`]. A subscribe
    /// call must fail loudly here rather than wait forever on a peer that
    /// accepted the control stream and then went quiet.
    AckTimeout,
    /// The server acknowledged a full-tx subscription but did not open and
    /// preface its stream within [`FULL_STREAM_TIMEOUT`].
    FullStreamTimeout,
    /// The server's first-control-message ack named a negotiated wire version
    /// this SDK does not speak. Carries the version the server chose.
    VersionMismatch(u32),
    /// A successful first ack omitted `v`, leaving the datagram-only tier with
    /// no proof that wire v2 was negotiated.
    MissingVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidEndpoint(e) => write!(f, "invalid endpoint: {e}"),
            Error::Connect(e) => write!(f, "connect: {e}"),
            Error::ConnectTimeout => write!(
                f,
                "timed out after {}s connecting to the server",
                CONNECT_TIMEOUT.as_secs()
            ),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Tls(e) => write!(f, "tls: {e}"),
            Error::InsecureEndpointNotLoopback(addr) => write!(
                f,
                "insecure local-dev TLS is restricted to loopback addresses, got {addr}"
            ),
            Error::ApplicationClosed(close) => write!(
                f,
                "server closed the connection (code {}): {}",
                close.code, close.reason
            ),
            Error::BadFrame => write!(f, "malformed frame"),
            Error::BadFrameWithClose(close) => write!(
                f,
                "truncated frame before server close (code {}): {}",
                close.code, close.reason
            ),
            Error::BadPreamble => write!(
                f,
                "bad stream preamble: this server is not speaking pulse wire v2"
            ),
            Error::BadPreambleWithClose(close) => write!(
                f,
                "bad stream preamble before server close (code {}): {}",
                close.code, close.reason
            ),
            Error::Rejected(reason) => write!(f, "control message rejected: {reason}"),
            Error::AckTimeout => write!(
                f,
                "timed out after {}s waiting for the server's control ack",
                ACK_TIMEOUT.as_secs()
            ),
            Error::FullStreamTimeout => write!(
                f,
                "timed out after {}s waiting for the full-tx stream and preamble",
                FULL_STREAM_TIMEOUT.as_secs()
            ),
            Error::VersionMismatch(v) => write!(
                f,
                "server negotiated wire v{v}, this SDK speaks only wire v{}",
                thornode_pulse_wire::frame::WIRE_VERSION
            ),
            Error::MissingVersion => write!(
                f,
                "successful initial control ack omitted the negotiated wire version"
            ),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// A terminal QUIC application close sent by the Pulse server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    pub code: u64,
    pub reason: String,
}

impl CloseInfo {
    /// Stable retry classification for Pulse close codes 0–5. Unknown codes
    /// stay unknown rather than being guessed retryable.
    pub fn retry_class(&self) -> RetryClass {
        thornode_pulse_wire::protocol::classify_close_code(self.code)
    }

    /// `true` only for code 3 (transient admission/capacity). Code 2 requires
    /// new credentials first; codes 1, 4 and 5 must not be retried unchanged.
    pub fn retryable(&self) -> bool {
        self.retry_class() == RetryClass::Transient
    }
}

impl Error {
    /// Returns the terminal application close carried by this error, including
    /// a close that coincided with a truncated full-tx frame.
    pub fn close_info(&self) -> Option<&CloseInfo> {
        match self {
            Error::ApplicationClosed(close)
            | Error::BadFrameWithClose(close)
            | Error::BadPreambleWithClose(close) => Some(close),
            _ => None,
        }
    }

    /// Whether this error reports malformed/truncated wire framing.
    pub fn is_bad_frame(&self) -> bool {
        matches!(self, Error::BadFrame | Error::BadFrameWithClose(_))
    }

    /// Whether this error reports an invalid or truncated full-tx preamble.
    pub fn is_bad_preamble(&self) -> bool {
        matches!(self, Error::BadPreamble | Error::BadPreambleWithClose(_))
    }
}

/// UDP receive buffer requested for the client socket, in bytes.
///
/// The kernel may clamp this to the platform's configured receive-buffer limit.
pub const DEFAULT_RECV_BUFFER: usize = 8 << 20; // 8 MiB

/// Bound for DNS resolution plus the QUIC/TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound for the server to open and preface the full-tx stream after acking.
pub const FULL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Binds the client's UDP socket with an enlarged receive buffer.
///
/// The buffer request is best-effort: the kernel silently clamps it to
/// `rmem_max` rather than failing, so a clamped result is not an error.
fn client_socket(addr: SocketAddr, recv_buffer: usize) -> std::io::Result<std::net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    // Ignore the error: some platforms reject an oversized request outright, and
    // an undersized buffer is a performance problem, not a connection failure.
    let _ = sock.set_recv_buffer_size(recv_buffer);
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// A connected pulse client. Pick exactly one tier per connection.
pub struct PulseClient {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    token: Option<String>,
}

impl PulseClient {
    /// Creates a verified-TLS client builder for `host:port`.
    pub fn builder(endpoint: impl Into<String>) -> PulseClientBuilder {
        PulseClientBuilder::new(endpoint)
    }

    /// Resolves `host:port`, uses the host as TLS SNI, verifies the certificate
    /// against native system roots, and negotiates QUIC ALPN `pulse`.
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self> {
        Self::builder(endpoint).connect().await
    }

    /// Verified-TLS connection that sends `token` only after the certificate
    /// and hostname handshake succeeds.
    pub async fn connect_with_token(
        endpoint: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        Self::builder(endpoint).with_token(token).connect().await
    }

    /// Connects without certificate verification for an in-process/local test
    /// server. The address must be loopback; a public address is rejected
    /// before any packet or bearer token is sent.
    pub async fn dangerous_connect_insecure_local_dev(addr: SocketAddr) -> Result<Self> {
        connect_to(
            addr,
            "localhost".to_owned(),
            None,
            Trust::InsecureLocalDev,
            CONNECT_TIMEOUT,
        )
        .await
    }

    /// Token-bearing counterpart to
    /// [`PulseClient::dangerous_connect_insecure_local_dev`]. This remains
    /// loopback-only and is intended solely for local auth integration tests.
    pub async fn dangerous_connect_insecure_local_dev_with_token(
        addr: SocketAddr,
        token: impl Into<String>,
    ) -> Result<Self> {
        connect_to(
            addr,
            "localhost".to_owned(),
            Some(token.into()),
            Trust::InsecureLocalDev,
            CONNECT_TIMEOUT,
        )
        .await
    }

    /// Subscribes to the **sig-first** DATAGRAM tier. Yields [`SigFirstItem`]
    /// per transaction, lowest latency. Enrichment fields are a full-tx-only
    /// concept and are deliberately absent from this API.
    pub async fn subscribe_sig_first(self, filter: &Filter) -> Result<SigFirstSub> {
        let ack = self.send_control(filter, false, &[]).await?;
        ensure_initial_ack(&ack)?;
        Ok(SigFirstSub::spawn(self.conn))
    }

    /// Subscribes to the **full-tx** tier. Yields decoded [`Frame::Tx`] values
    /// in stream order (heartbeats and unknown frame types are
    /// filtered out by [`FullSub::next`] itself — see its doc comment).
    /// `fields` requests enrichment groups (currently just `["alt"]`, which
    /// adds each frame's ALT-loaded addresses).
    ///
    /// The stream's 6-byte preamble is read and verified here, before the
    /// subscription is ever returned to the caller — a mismatch is a loud
    /// [`Error::BadPreamble`], never a silent skip.
    pub async fn subscribe_full(self, filter: &Filter, fields: &[&str]) -> Result<FullSub> {
        let ack = self.send_control(filter, true, fields).await?;
        ensure_initial_ack(&ack)?;
        // The server opens exactly one unidirectional stream for this tier.
        // Bound both its arrival and its preamble; either could otherwise wait
        // forever after a peer sends a successful control ack and goes quiet.
        let setup = async {
            let mut recv = self
                .conn
                .accept_uni()
                .await
                .map_err(|e| Error::Io(e.to_string()))?;
            verify_preamble(&mut recv).await?;
            Ok(recv)
        };
        let recv = match tokio::time::timeout(FULL_STREAM_TIMEOUT, setup).await {
            Ok(result) => {
                result.map_err(|e| merge_wire_and_terminal(e, terminal_error(&self.conn)))?
            }
            Err(_) => return Err(terminal_error(&self.conn).unwrap_or(Error::FullStreamTimeout)),
        };
        Ok(FullSub {
            conn: self.conn,
            recv,
            buf: Vec::with_capacity(4096),
            last_heartbeat: None,
        })
    }

    async fn send_control(&self, filter: &Filter, full: bool, fields: &[&str]) -> Result<Ack> {
        let token = self.token.as_deref().unwrap_or("");
        control_round_trip(&self.conn, filter, full, fields, token).await
    }
}

/// Builder for verified production connections. Native system roots are
/// always loaded; custom CA certificates are additive, which supports private
/// PKI without weakening verification for public endpoints.
pub struct PulseClientBuilder {
    endpoint: String,
    token: Option<String>,
    custom_ca_der: Vec<Vec<u8>>,
}

impl PulseClientBuilder {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: None,
            custom_ca_der: Vec::new(),
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Adds a DER-encoded trust anchor while retaining native system roots.
    /// The certificate is still checked for the endpoint hostname/SNI.
    pub fn add_custom_ca_der(mut self, certificate: impl Into<Vec<u8>>) -> Self {
        self.custom_ca_der.push(certificate.into());
        self
    }

    pub async fn connect(self) -> Result<PulseClient> {
        let started = tokio::time::Instant::now();
        let host = endpoint_host(&self.endpoint)?;
        let resolved = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let mut addresses: Vec<_> = tokio::net::lookup_host(self.endpoint.as_str())
                .await
                .map_err(|e| Error::Connect(format!("resolve {}: {e}", self.endpoint)))?
                .collect();
            // Prefer IPv4 when both families are returned. This avoids waiting
            // out a full QUIC handshake timeout on systems where `localhost`
            // (and some public resolvers) return an unreachable IPv6 address
            // first. Stable sort preserves resolver order within each family.
            addresses.sort_by_key(|address| !address.is_ipv4());
            addresses.into_iter().next().ok_or_else(|| {
                Error::Connect(format!("{} resolved to no addresses", self.endpoint))
            })
        })
        .await
        .map_err(|_| Error::ConnectTimeout)??;

        let remaining = CONNECT_TIMEOUT
            .checked_sub(started.elapsed())
            .ok_or(Error::ConnectTimeout)?;

        connect_to(
            resolved,
            host,
            self.token,
            Trust::Verified(self.custom_ca_der),
            remaining,
        )
        .await
    }
}

enum Trust {
    Verified(Vec<Vec<u8>>),
    InsecureLocalDev,
}

fn endpoint_host(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.contains("://") || endpoint.contains('/') {
        return Err(Error::InvalidEndpoint(
            "expected host:port without a URL scheme or path".to_owned(),
        ));
    }
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr.ip().to_string());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidEndpoint(format!("{endpoint:?} must include a port")))?;
    if host.is_empty() || host.contains(':') || host.chars().any(char::is_whitespace) {
        return Err(Error::InvalidEndpoint(format!(
            "{endpoint:?} has an invalid host"
        )));
    }
    port.parse::<u16>()
        .map_err(|_| Error::InvalidEndpoint(format!("{endpoint:?} has an invalid port")))?;
    Ok(host.trim_end_matches('.').to_owned())
}

async fn connect_to(
    addr: SocketAddr,
    server_name: String,
    token: Option<String>,
    trust: Trust,
    timeout: Duration,
) -> Result<PulseClient> {
    if matches!(trust, Trust::InsecureLocalDev) && !addr.ip().is_loopback() {
        return Err(Error::InsecureEndpointNotLoopback(addr));
    }
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls = match trust {
        Trust::Verified(custom_ca_der) => {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                roots
                    .add(cert)
                    .map_err(|e| Error::Tls(format!("invalid native trust anchor: {e}")))?;
            }
            for cert in custom_ca_der {
                roots
                    .add(rustls::pki_types::CertificateDer::from(cert))
                    .map_err(|e| Error::Tls(format!("invalid custom CA certificate: {e}")))?;
            }
            if roots.is_empty() {
                return Err(Error::Tls(
                    "native certificate store contained no usable roots".to_owned(),
                ));
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        Trust::InsecureLocalDev => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    };
    tls.alpn_protocols = vec![thornode_pulse_wire::protocol::ALPN.to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(qcc));

    // Not Endpoint::client: that inherits net.core.rmem_default, which is far
    // too small to absorb a shred-rate burst.
    let bind_addr = SocketAddr::new(
        if addr.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let socket =
        client_socket(bind_addr, DEFAULT_RECV_BUFFER).map_err(|e| Error::Io(e.to_string()))?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    endpoint.set_default_client_config(client_cfg);

    let connecting = endpoint
        .connect(addr, &server_name)
        .map_err(|e| Error::Connect(e.to_string()))?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| Error::ConnectTimeout)?
        .map_err(|error| {
            close_info(&error)
                .map(Error::ApplicationClosed)
                .unwrap_or_else(|| Error::Connect(error.to_string()))
        })?;

    Ok(PulseClient {
        conn,
        _endpoint: endpoint,
        token,
    })
}

/// Rejects a control message the server answered with `ok: false`, surfacing
/// its stated reason rather than letting the caller silently proceed as if
/// the subscription it asked for actually took effect — and rejects an ack
/// naming a negotiated version this SDK does not speak.
///
/// The version check is not decoration. On the **sig-first tier the ack's `v`
/// is the only version channel there is**: that tier is DATAGRAM-only, so
/// there is no stream and therefore no preamble to confirm the dialect
/// another way. Without this check a client acked `v:1` proceeds happily and
/// misparses every 81-byte v2 datagram as a 72-byte v1 one. The server closes
/// (code 4) rather than acking a version it cannot serve, so in practice this
/// is a backstop — but it is the only one this tier has.
fn ensure_envelope(ack: &Ack) -> Result<()> {
    let reason = ack.reason.clone().unwrap_or_default();
    match ack.message_type.as_deref() {
        Some("ack") => {
            if ack.ok {
                Ok(())
            } else {
                Err(Error::Rejected(reason))
            }
        }
        Some("error") if !ack.ok => match ack.code {
            Some(code) => Err(Error::ApplicationClosed(CloseInfo { code, reason })),
            None => Err(Error::BadFrame),
        },
        // Missing/unknown envelope types, and a contradictory `error` success,
        // are protocol errors rather than successful or ordinary rejections.
        _ => Err(Error::BadFrame),
    }
}

fn ensure_initial_ack(ack: &Ack) -> Result<()> {
    ensure_envelope(ack)?;
    match ack.v {
        Some(v) if v == thornode_pulse_wire::frame::WIRE_VERSION as u32 => Ok(()),
        Some(v) => Err(Error::VersionMismatch(v)),
        None => Err(Error::MissingVersion),
    }
}

fn ensure_update_ack(ack: &Ack) -> Result<()> {
    ensure_envelope(ack)?;
    // Updates normally omit `v`; if a peer does send one, it must not
    // contradict the already-negotiated connection dialect.
    match ack.v {
        Some(v) if v != thornode_pulse_wire::frame::WIRE_VERSION as u32 => {
            Err(Error::VersionMismatch(v))
        }
        _ => Ok(()),
    }
}

/// Writes one control message (`"v"` always negotiates wire v2 —
/// `thornode_pulse_wire::frame::WIRE_VERSION`) and reads back the server's ack
/// envelope on the same stream. Shared by the initial subscribe and every
/// later `update_filter` call.
async fn control_round_trip(
    conn: &quinn::Connection,
    filter: &Filter,
    full: bool,
    fields: &[&str],
    token: &str,
) -> Result<Ack> {
    let result = tokio::time::timeout(
        ACK_TIMEOUT,
        control_round_trip_inner(conn, filter, full, fields, token),
    )
    .await;
    match result {
        Ok(result) => result.map_err(|e| terminal_error(conn).unwrap_or(e)),
        Err(_) => Err(terminal_error(conn).unwrap_or(Error::AckTimeout)),
    }
}

async fn control_round_trip_inner(
    conn: &quinn::Connection,
    filter: &Filter,
    full: bool,
    fields: &[&str],
    token: &str,
) -> Result<Ack> {
    let body = serde_json::to_vec(&Control {
        filter,
        token,
        full,
        v: thornode_pulse_wire::frame::WIRE_VERSION as u32,
        fields,
    })
    .map_err(|_| Error::BadFrame)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| Error::Io(e.to_string()))?;
    send.write_all(&body)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let _ = send.finish();
    read_ack(&mut recv).await
}

/// Bound on a control-ack envelope's length prefix: acks are a few dozen
/// bytes of JSON, so this is generous headroom against a corrupted length
/// rather than a realistic ack size.
const MAX_ACK_BYTES: usize = 16 * 1024;

/// How long the complete control round-trip (open, write and ack read) may
/// take before failing with [`Error::AckTimeout`].
///
/// This bounds control-stream opening, writing, and acknowledgement reading.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

async fn read_ack(recv: &mut quinn::RecvStream) -> Result<Ack> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_ACK_BYTES {
        return Err(Error::BadFrame);
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_slice(&body).map_err(|_| Error::BadFrame)
}

fn close_info(error: &quinn::ConnectionError) -> Option<CloseInfo> {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => Some(CloseInfo {
            code: close.error_code.into_inner(),
            reason: String::from_utf8_lossy(&close.reason).into_owned(),
        }),
        _ => None,
    }
}

fn terminal_error(conn: &quinn::Connection) -> Option<Error> {
    conn.close_reason().and_then(|error| {
        close_info(&error)
            .map(Error::ApplicationClosed)
            .or_else(|| match error {
                quinn::ConnectionError::LocallyClosed => None,
                other => Some(Error::Io(other.to_string())),
            })
    })
}

/// Reads exactly [`thornode_pulse_wire::frame::PREAMBLE`]'s length from `recv` and
/// rejects anything else — including a short read at EOF — as
/// [`Error::BadPreamble`]. Generic over the reader so this is unit-testable
/// against an in-memory pipe instead of requiring a live QUIC stream.
async fn verify_preamble<R: tokio::io::AsyncRead + Unpin>(recv: &mut R) -> Result<()> {
    let mut buf = [0u8; 6];
    debug_assert_eq!(thornode_pulse_wire::frame::PREAMBLE.len(), buf.len());
    recv.read_exact(&mut buf)
        .await
        .map_err(|_| Error::BadPreamble)?;
    if &buf != thornode_pulse_wire::frame::PREAMBLE {
        return Err(Error::BadPreamble);
    }
    Ok(())
}

/// One sig-first delivery: the transaction's slot, this subscriber's
/// per-connection sequence number (see [`SigFirstSub::gaps`]), and its
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigFirstItem {
    pub slot: u64,
    pub seq: u64,
    pub signature: [u8; 64],
}

/// Folds an item's own `seq` into the running (last-seen, gap-count) state. A
/// gap is exactly the count of sequence numbers skipped between the previous
/// (highest-seen) item this subscriber saw and this one.
///
/// QUIC DATAGRAMs are explicitly unordered, so out-of-order arrival is
/// expected traffic, not a pathology — the watermark (`*last_seq`) MUST be
/// monotonic (`last.max(seq)`), never just overwritten with whatever arrived
/// most recently. An unconditional overwrite would let a reordered item drag
/// the watermark backwards, and the very next in-order item would then be
/// charged again for a range that was never actually missing — inflating
/// `gaps()`, this tier's only loss signal, on a stream that lost nothing.
fn note_item_seq(last_seq: &mut Option<u64>, gaps: &AtomicU64, seq: u64) {
    if let Some(last) = *last_seq {
        // `last.saturating_add(1)`, not `last + 1`: a corrupt or hostile
        // datagram could carry `seq == NO_SEQ_ASSIGNED` (u64::MAX) as a real
        // item seq — `apply_datagram` has no reason to reject that value on
        // this path (the sentinel is only reserved on the HEARTBEAT side) —
        // and an unguarded `+ 1` would overflow-panic the spawned drain task
        // in a debug build, surfacing to the caller as a silent `Ok(None)`
        // indistinguishable from a clean server close.
        gaps.fetch_add(
            seq.saturating_sub(last.saturating_add(1)),
            Ordering::Relaxed,
        );
        *last_seq = Some(last.max(seq));
    } else {
        *last_seq = Some(seq);
    }
}

/// Folds a heartbeat's `highest_seq` into the running (last-seen, gap-count)
/// state. This is what reveals TRAILING loss — datagrams dropped after the
/// last item this subscriber actually received, which item-to-item
/// comparison alone can never see (there is no next item to reveal the hole).
///
/// [`NO_SEQ_ASSIGNED`] MUST be treated as "no information yet", never as a
/// real, enormous sequence number: a naive `highest_seq - last` on the
/// sentinel would report an absurd multi-quintillion gap instead of the true
/// answer, which is "nothing assigned yet, so don't guess".
fn note_heartbeat_seq(last_seq: &mut Option<u64>, gaps: &AtomicU64, highest_seq: u64) {
    if highest_seq == NO_SEQ_ASSIGNED {
        return;
    }
    match *last_seq {
        Some(last) if highest_seq > last => {
            gaps.fetch_add(highest_seq - last, Ordering::Relaxed);
            *last_seq = Some(highest_seq);
        }
        // Heartbeat is stale/equal to what item traffic already told us:
        // nothing new to fold in.
        Some(_) => {}
        // First observation ever, with no item to compare against: establish
        // a baseline rather than alleging a gap we have no evidence for.
        None => *last_seq = Some(highest_seq),
    }
}

/// Applies one decoded datagram to the running gap-tracking state, returning
/// the item to forward (if any). `Datagram::Unknown` and a `None` decode
/// (corrupt bytes, or a known type too short to parse) both mean "skip" —
/// never an error, never a reason to tear the stream down; that is what
/// keeps a future datagram type from breaking this client.
/// `Datagram::Heartbeat` updates the gap counter but is never forwarded as an
/// item.
fn apply_datagram(dg: &[u8], last_seq: &mut Option<u64>, gaps: &AtomicU64) -> Option<SigFirstItem> {
    match decode_datagram(dg) {
        Some(Datagram::SigFirst {
            slot,
            seq,
            signature,
        }) => {
            note_item_seq(last_seq, gaps, seq);
            Some(SigFirstItem {
                slot,
                seq,
                signature,
            })
        }
        Some(Datagram::Heartbeat { highest_seq, .. }) => {
            note_heartbeat_seq(last_seq, gaps, highest_seq);
            None
        }
        Some(Datagram::Unknown(_)) | None => None,
    }
}

/// Depth of the sig-first handoff queue.
///
/// quinn buffers only a small budget of datagrams itself and evicts on
/// overflow, so the SDK drains it continuously into this queue rather than
/// leaving datagrams there until the caller happens to call
/// [`SigFirstSub::next`].
pub const SIG_QUEUE_LEN: usize = 4096;

/// Live sig-first subscription. Call [`SigFirstSub::next`] in a loop.
///
/// A background task drains the connection as fast as the network delivers, so
/// a slow `next` loop costs you the OLDEST items (counted by
/// [`SigFirstSub::dropped`]) rather than silently losing whatever arrives while
/// you work. [`SigFirstSub::gaps`] is a separate, provisional counter for
/// sequence numbers that appear not to have arrived (network loss, a shed
/// delivery — or merely reordering, which it cannot tell apart), as opposed to
/// `dropped`, which counts items that definitely arrived and were evicted
/// because this consumer fell behind.
pub struct SigFirstSub {
    conn: Option<quinn::Connection>,
    rx: tokio::sync::broadcast::Receiver<SigFirstItem>,
    dropped: Arc<AtomicU64>,
    gaps: Arc<AtomicU64>,
    /// Terminal error, if the drain ended on anything but a clean close.
    fatal: Arc<OnceLock<Error>>,
    drain: Option<tokio::task::JoinHandle<()>>,
}

impl SigFirstSub {
    fn spawn(conn: quinn::Connection) -> Self {
        let (tx, rx) = tokio::sync::broadcast::channel(SIG_QUEUE_LEN);
        let dropped = Arc::new(AtomicU64::new(0));
        let gaps = Arc::new(AtomicU64::new(0));
        let fatal: Arc<OnceLock<Error>> = Arc::new(OnceLock::new());

        let drain_conn = conn.clone();
        let drain_fatal = Arc::clone(&fatal);
        let drain_gaps = Arc::clone(&gaps);
        let drain = tokio::spawn(async move {
            let mut last_seq: Option<u64> = None;
            loop {
                match drain_conn.read_datagram().await {
                    Ok(dg) => {
                        if let Some(item) = apply_datagram(&dg, &mut last_seq, &drain_gaps) {
                            // A broadcast send only fails when every receiver
                            // is gone, which means the caller dropped the sub.
                            if tx.send(item).is_err() {
                                return;
                            }
                        }
                    }
                    Err(quinn::ConnectionError::LocallyClosed) => return,
                    Err(e) => {
                        let error = close_info(&e)
                            .map(Error::ApplicationClosed)
                            .unwrap_or_else(|| Error::Io(e.to_string()));
                        let _ = drain_fatal.set(error);
                        return;
                    }
                }
            }
        });

        SigFirstSub {
            conn: Some(conn),
            rx,
            dropped,
            gaps,
            fatal,
            drain: Some(drain),
        }
    }

    #[cfg(test)]
    fn for_test(rx: tokio::sync::broadcast::Receiver<SigFirstItem>) -> Self {
        SigFirstSub {
            conn: None,
            rx,
            dropped: Arc::new(AtomicU64::new(0)),
            gaps: Arc::new(AtomicU64::new(0)),
            fatal: Arc::new(OnceLock::new()),
            drain: None,
        }
    }

    /// Awaits the next [`SigFirstItem`]. A QUIC application close is returned
    /// as [`Error::ApplicationClosed`], including normal close code `0`;
    /// `Ok(None)` is reserved for a locally ended drain with no terminal error.
    ///
    /// Do the work for each item elsewhere. Time spent between two calls is
    /// queue depth, and past [`SIG_QUEUE_LEN`] it is loss.
    pub async fn next(&mut self) -> Result<Option<SigFirstItem>> {
        loop {
            match self.rx.recv().await {
                Ok(item) => return Ok(Some(item)),
                // The queue overran while we were away: it kept the newest and
                // tells us exactly how many it discarded.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    self.dropped.fetch_add(n, Ordering::Relaxed);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return match self.fatal.get() {
                        Some(e) => Err(e.clone()),
                        None => Ok(None),
                    };
                }
            }
        }
    }

    /// Items evicted because this consumer fell behind. Watch it: no kernel
    /// or NIC counter will show this loss.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A **provisional** loss indicator: item-to-item `seq` gaps plus
    /// trailing loss revealed by a heartbeat's `highest_seq`.
    /// [`NO_SEQ_ASSIGNED`] on the wire never contributes to this counter.
    ///
    /// It can **over-report under reordering**. QUIC DATAGRAMs are unordered
    /// by definition, so a scalar high-watermark cannot distinguish "this seq
    /// is late" from "this seq is lost" at the moment a later one arrives out
    /// of order — it charges one provisional gap on that jump, and never
    /// reverses the charge if the late item shows up afterward. A perfectly
    /// lossless but reordered stream can therefore report `gaps() > 0`. Treat
    /// this as "loss happened, or reordering did" rather than an exact count
    /// of sequence numbers that never arrived on the wire at all.
    pub fn gaps(&self) -> u64 {
        self.gaps.load(Ordering::Relaxed)
    }

    /// Updates the active filter live (opens a fresh control stream) and
    /// returns the server's parsed ack. Enrichment fields do not exist on the
    /// sig-first tier, so this always sends an empty `fields` list. The tier
    /// cannot change after the first control message.
    pub async fn update_filter(&self, filter: &Filter) -> Result<Ack> {
        let ack = match &self.conn {
            Some(conn) => control_round_trip(conn, filter, false, &[], "").await,
            // `#[cfg(test)] for_test` variant: no real connection to update.
            None => Ok(Ack {
                message_type: Some("ack".to_owned()),
                ok: true,
                reason: None,
                code: None,
                v: None,
            }),
        }?;
        ensure_update_ack(&ack)?;
        Ok(ack)
    }
}

impl Drop for SigFirstSub {
    fn drop(&mut self) {
        if let Some(drain) = self.drain.take() {
            drain.abort();
        }
    }
}

/// Sanity cap on a single v2 frame's total length prefix — generous enough
/// for `MAX_FULL_TX_BODY` plus the largest possible TLV trailer (two
/// loaded-address lists, each up to `u16::MAX` bytes long) plus the 2-byte
/// msg_type/flags header. A plain v1-sized cap here would wrongly reject a
/// legitimately large `fields: ["alt"]`-enriched frame.
const MAX_FULL_TX_FRAME: usize =
    thornode_pulse_wire::frame::MAX_FULL_TX_BODY + 2 * (u16::MAX as usize + 3) + 2;

/// Live full-tx subscription. Call [`FullSub::next`] in a loop.
pub struct FullSub {
    conn: quinn::Connection,
    recv: quinn::RecvStream,
    buf: Vec<u8>,
    /// The most recent heartbeat observed on this stream: `(server_ts_ms,
    /// highest_seq)`. See [`FullSub::heartbeat`].
    last_heartbeat: Option<(u64, u64)>,
}

impl FullSub {
    /// Awaits the next transaction frame. `Frame::Unknown` message types are
    /// skipped transparently for forward compatibility, and
    /// `Frame::Heartbeat` frames update [`FullSub::heartbeat`] instead of
    /// being returned. Only `Frame::Tx` is ever handed back here. Returns
    /// `Ok(None)` at a clean end of stream.
    pub async fn next(&mut self) -> Result<Option<Frame>> {
        match next_frame(&mut self.recv, &mut self.buf, &mut self.last_heartbeat).await {
            Ok(None) => match terminal_error(&self.conn) {
                Some(error) => Err(error),
                None => Ok(None),
            },
            Err(error) => Err(merge_wire_and_terminal(error, terminal_error(&self.conn))),
            ok => ok,
        }
    }

    /// The most recent heartbeat observed on this stream: `(server_ts_ms,
    /// highest_seq)`. `highest_seq == NO_SEQ_ASSIGNED` means the server has
    /// not assigned this subscriber a transaction yet. `None` means no
    /// heartbeat has arrived at all yet (a busy stream can go a long time
    /// without one — the server resets its heartbeat timer on every real
    /// send).
    ///
    /// Unlike [`SigFirstSub::gaps`], the full-tx wire carries no per-frame
    /// sequence number, so this SDK cannot compute a numeric gap count for
    /// this tier — `highest_seq` is the raw signal a caller can compare
    /// against its own received-frame count if it wants that.
    pub fn heartbeat(&self) -> Option<(u64, u64)> {
        self.last_heartbeat
    }

    /// Updates the active filter/enrichment fields live (opens a fresh
    /// control stream) and returns the server's parsed ack. The tier cannot
    /// change after the first control message.
    pub async fn update_filter(&self, filter: &Filter, fields: &[&str]) -> Result<Ack> {
        let ack = control_round_trip(&self.conn, filter, true, fields, "").await?;
        ensure_update_ack(&ack)?;
        Ok(ack)
    }
}

/// Reads and decodes the next `Frame` from `recv`, transparently skipping
/// `Frame::Unknown` and folding `Frame::Heartbeat` into `*last_heartbeat`
/// until a `Frame::Tx` arrives or the stream ends cleanly. Generic over the
/// reader so this framing logic is unit-testable against an in-memory pipe
/// instead of requiring a live QUIC stream — see the `next_frame_*` tests
/// below.
async fn next_frame<R: tokio::io::AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut Vec<u8>,
    last_heartbeat: &mut Option<(u64, u64)>,
) -> Result<Option<Frame>> {
    loop {
        // Each frame is a u32 big-endian length prefix followed by the body.
        let len = match read_n_or_eof(recv, buf, 4).await? {
            Some(()) => {
                let l = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if l > MAX_FULL_TX_FRAME {
                    return Err(Error::BadFrame);
                }
                l
            }
            None => return Ok(None),
        };
        match read_n_or_eof(recv, buf, len).await {
            Ok(Some(())) => match decode_frame(&buf[..len]) {
                Ok(Frame::Unknown(_)) => continue,
                Ok(Frame::Heartbeat {
                    server_ts_ms,
                    highest_seq,
                }) => {
                    *last_heartbeat = Some((server_ts_ms, highest_seq));
                    continue;
                }
                Ok(tx @ Frame::Tx(_)) => return Ok(Some(tx)),
                Err(_) => return Err(Error::BadFrame),
            },
            // The length prefix arrived but the body never did. That is a
            // TRUNCATED frame, not a clean close — the sender told us how many
            // bytes were coming and then stopped. Reporting `Ok(None)` here
            // would present silent loss as a normal end of stream. Matches
            // Go's `nextFrame` (`ErrBadFrame`); a clean close is only a close
            // that happens on a frame boundary, i.e. before the length prefix.
            Ok(None) | Err(_) => return Err(Error::BadFrame),
        }
    }
}

/// Fills `buf[..n]` with exactly `n` bytes. Returns `Ok(None)` on a clean
/// end-of-stream before any byte was read; a partial read followed by EOF is
/// `Error::BadFrame` (a truncated frame, not a clean boundary).
async fn read_n_or_eof<R: tokio::io::AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut Vec<u8>,
    n: usize,
) -> Result<Option<()>> {
    buf.resize(n, 0);
    let mut got = 0;
    while got < n {
        match recv.read(&mut buf[got..n]).await {
            Ok(0) => {
                return if got == 0 {
                    Ok(None)
                } else {
                    Err(Error::BadFrame)
                };
            }
            Ok(k) => got += k,
            Err(error) if got == 0 => return Err(Error::Io(error.to_string())),
            Err(_) => return Err(Error::BadFrame),
        }
    }
    Ok(Some(()))
}

fn merge_wire_and_terminal(error: Error, terminal: Option<Error>) -> Error {
    match (error, terminal) {
        (Error::BadFrame, Some(Error::ApplicationClosed(close))) => Error::BadFrameWithClose(close),
        (Error::BadPreamble, Some(Error::ApplicationClosed(close))) => {
            Error::BadPreambleWithClose(close)
        }
        (_, Some(terminal)) => terminal,
        (error, None) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SigFirstSub: consumer backpressure (dropped) ----------------------

    /// A stalled consumer must lose the OLDEST items and be able to count
    /// them. Nothing below the SDK will ever report this loss.
    #[tokio::test]
    async fn stalled_consumer_loses_oldest_and_counts_them() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        let mut sub = SigFirstSub::for_test(rx);

        for slot in 0..10u64 {
            tx.send(SigFirstItem {
                slot,
                seq: slot,
                signature: [0u8; 64],
            })
            .unwrap();
        }
        drop(tx); // end of stream once the buffered items are read

        let mut got = Vec::new();
        while let Some(item) = sub.next().await.unwrap() {
            got.push(item.slot);
        }

        assert_eq!(got, vec![6, 7, 8, 9], "the freshest items must survive");
        assert_eq!(sub.dropped(), 6);
    }

    /// A consumer that keeps up loses nothing and counts nothing.
    #[tokio::test]
    async fn consumer_that_keeps_up_drops_nothing() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        let mut sub = SigFirstSub::for_test(rx);

        tx.send(SigFirstItem {
            slot: 1,
            seq: 0,
            signature: [0u8; 64],
        })
        .unwrap();
        tx.send(SigFirstItem {
            slot: 2,
            seq: 1,
            signature: [0u8; 64],
        })
        .unwrap();
        drop(tx);

        let mut got = Vec::new();
        while let Some(item) = sub.next().await.unwrap() {
            got.push(item.slot);
        }

        assert_eq!(got, vec![1, 2]);
        assert_eq!(sub.dropped(), 0);
    }

    // ---- gap tracking: the u64::MAX sentinel must never fabricate a gap ----

    #[test]
    fn note_item_seq_counts_missed_numbers_between_consecutive_items() {
        let mut last_seq = None;
        let gaps = AtomicU64::new(0);
        note_item_seq(&mut last_seq, &gaps, 0);
        assert_eq!(
            gaps.load(Ordering::Relaxed),
            0,
            "first item establishes the baseline"
        );
        note_item_seq(&mut last_seq, &gaps, 3); // missed 1 and 2
        assert_eq!(gaps.load(Ordering::Relaxed), 2);
        assert_eq!(last_seq, Some(3));
    }

    #[test]
    fn note_item_seq_out_of_order_never_underflows() {
        // Datagrams are UDP: they can arrive out of order. A later item with a
        // LOWER seq than the last one seen must not wrap a u64 subtraction.
        let mut last_seq = Some(10u64);
        let gaps = AtomicU64::new(0);
        note_item_seq(&mut last_seq, &gaps, 3);
        assert_eq!(
            gaps.load(Ordering::Relaxed),
            0,
            "no underflow, no bogus gap"
        );
        // The watermark must stay monotonic: a reordered item behind the high
        // watermark must never drag it backwards (see
        // `note_item_seq_reordering_does_not_double_count_the_same_gap` for
        // why that matters — a regressed watermark double-charges the next
        // in-order item for a range that was never actually missing).
        assert_eq!(last_seq, Some(10), "watermark must not regress on reorder");
        note_item_seq(&mut last_seq, &gaps, 11);
        assert_eq!(
            gaps.load(Ordering::Relaxed),
            0,
            "seq 11 directly follows the watermark of 10"
        );
        assert_eq!(last_seq, Some(11));
    }

    #[test]
    fn note_item_seq_reordering_does_not_double_count_the_same_gap() {
        // Sequences 0,1,2,3 can arrive as 0,2,1,3 with no actual loss. The
        // 0->2 jump produces one provisional gap, but the late 1 must not move
        // the watermark backwards and cause the following 3 to count it again.
        let mut last_seq = None;
        let gaps = AtomicU64::new(0);
        for seq in [0u64, 2, 1, 3] {
            note_item_seq(&mut last_seq, &gaps, seq);
        }
        assert_eq!(
            gaps.load(Ordering::Relaxed),
            1,
            "one provisional gap from the 0->2 jump, never double-charged on the later in-order 3"
        );
        assert_eq!(
            last_seq,
            Some(3),
            "watermark must track the highest seq seen, not the latest arrival"
        );
    }

    #[test]
    fn note_item_seq_sentinel_seq_does_not_overflow_the_gap_addition() {
        // A corrupt or hostile datagram could carry seq == u64::MAX. The `+1`
        // this function computes against the PREVIOUS watermark must not
        // panic (debug-build overflow) — that would kill the drain task and
        // surface to the caller as an indistinguishable-from-clean `Ok(None)`.
        let mut last_seq = Some(u64::MAX);
        let gaps = AtomicU64::new(0);
        note_item_seq(&mut last_seq, &gaps, u64::MAX);
        assert_eq!(gaps.load(Ordering::Relaxed), 0);
        assert_eq!(last_seq, Some(u64::MAX));
    }

    #[test]
    fn note_heartbeat_seq_sentinel_is_never_a_gap() {
        // THE required property: NO_SEQ_ASSIGNED (u64::MAX) must never be
        // treated as a real value. A naive `highest_seq - last` here would
        // compute an astronomical, nonsensical gap.
        let mut last_seq = Some(5u64);
        let gaps = AtomicU64::new(0);
        note_heartbeat_seq(&mut last_seq, &gaps, NO_SEQ_ASSIGNED);
        assert_eq!(gaps.load(Ordering::Relaxed), 0);
        assert_eq!(
            last_seq,
            Some(5),
            "the sentinel must not overwrite a real baseline either"
        );
    }

    #[test]
    fn note_heartbeat_seq_reveals_trailing_loss() {
        // This is the case item-to-item comparison can never see: datagrams
        // dropped AFTER the last one we actually received, with nothing since
        // to reveal the hole. Only a heartbeat's highest_seq can tell us.
        let mut last_seq = Some(2u64);
        let gaps = AtomicU64::new(0);
        note_heartbeat_seq(&mut last_seq, &gaps, 7);
        assert_eq!(gaps.load(Ordering::Relaxed), 5);
        assert_eq!(last_seq, Some(7));
    }

    #[test]
    fn note_heartbeat_seq_first_observation_establishes_a_baseline_not_a_gap() {
        // No prior item to compare against: we have no evidence anything was
        // actually lost, so don't allege a number we can't justify.
        let mut last_seq = None;
        let gaps = AtomicU64::new(0);
        note_heartbeat_seq(&mut last_seq, &gaps, 9);
        assert_eq!(gaps.load(Ordering::Relaxed), 0);
        assert_eq!(last_seq, Some(9));
    }

    // ---- apply_datagram: unknown types are skipped, never an error ---------

    #[test]
    fn apply_datagram_skips_an_unknown_type() {
        let mut last_seq = None;
        let gaps = AtomicU64::new(0);
        let buf = [200u8, 1, 2, 3];
        assert_eq!(apply_datagram(&buf, &mut last_seq, &gaps), None);
        assert_eq!(gaps.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn apply_datagram_forwards_sig_first_and_tracks_gaps() {
        let mut last_seq = None;
        let gaps = AtomicU64::new(0);
        let mut buf = [0u8; thornode_pulse_wire::frame::DG_SIG_FIRST_MIN];

        thornode_pulse_wire::frame::encode_dg_sig_first(&mut buf, 100, 0, &[1u8; 64]);
        let item = apply_datagram(&buf, &mut last_seq, &gaps).expect("sig-first forwards");
        assert_eq!((item.slot, item.seq), (100, 0));

        thornode_pulse_wire::frame::encode_dg_sig_first(&mut buf, 100, 3, &[1u8; 64]);
        let item = apply_datagram(&buf, &mut last_seq, &gaps).expect("sig-first forwards");
        assert_eq!(item.seq, 3);
        assert_eq!(gaps.load(Ordering::Relaxed), 2, "missed seq 1 and 2");
    }

    #[test]
    fn apply_datagram_heartbeat_is_never_forwarded_as_an_item() {
        let mut last_seq = Some(1u64);
        let gaps = AtomicU64::new(0);
        let mut buf = [0u8; thornode_pulse_wire::frame::DG_HEARTBEAT_MIN];
        thornode_pulse_wire::frame::encode_dg_heartbeat(&mut buf, 123, 4);
        assert_eq!(apply_datagram(&buf, &mut last_seq, &gaps), None);
        assert_eq!(gaps.load(Ordering::Relaxed), 3);
    }

    // ---- next_frame: unknown frames skipped, heartbeats folded, not items --

    fn sample_full_tx() -> thornode_pulse_wire::frame::FullTx {
        thornode_pulse_wire::frame::FullTx {
            slot: 438_690_000,
            versioned: false,
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
            recent_blockhash: [0xCC; 32],
            signatures: vec![[7u8; 64]],
            account_keys: vec![[0xA1; 32]],
            instructions: vec![thornode_pulse_wire::frame::FullInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: vec![9, 9],
            }],
            address_table_lookups: vec![],
        }
    }

    async fn write_framed(w: &mut (impl tokio::io::AsyncWrite + Unpin), body: &[u8]) {
        use tokio::io::AsyncWriteExt;
        w.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        w.write_all(body).await.unwrap();
    }

    #[tokio::test]
    async fn next_frame_skips_unknown_and_folds_heartbeat_without_surfacing_it() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);

        // Frame 1: an unknown message type (99) — must be skipped, not error.
        write_framed(&mut writer, &[99u8, 0]).await;

        // Frame 2: a heartbeat — must update `last_heartbeat`, not be returned.
        let mut hb = Vec::new();
        hb.push(thornode_pulse_wire::frame::MSG_HEARTBEAT);
        hb.push(0);
        thornode_pulse_wire::frame::put_tlv(
            &mut hb,
            thornode_pulse_wire::frame::TLV_SERVER_TS_MS,
            &123u64.to_le_bytes(),
        );
        thornode_pulse_wire::frame::put_tlv(
            &mut hb,
            thornode_pulse_wire::frame::TLV_HIGHEST_SEQ,
            &7u64.to_le_bytes(),
        );
        write_framed(&mut writer, &hb).await;

        // Frame 3: a real (bare) tx frame — what next_frame must finally return.
        let tx = sample_full_tx();
        let tx_bytes = thornode_pulse_wire::frame::encode_frame_tx(&tx, false, &[], &[]);
        write_framed(&mut writer, &tx_bytes).await;
        drop(writer); // clean EOF right after

        let mut buf = Vec::new();
        let mut last_heartbeat = None;
        let got = next_frame(&mut reader, &mut buf, &mut last_heartbeat)
            .await
            .unwrap();
        match got {
            Some(Frame::Tx(v2)) => assert_eq!(v2.tx, tx),
            other => panic!("expected Some(Frame::Tx(_)), got {other:?}"),
        }
        assert_eq!(
            last_heartbeat,
            Some((123, 7)),
            "the heartbeat must be captured via the accessor, not returned as an item"
        );
    }

    #[tokio::test]
    async fn next_frame_returns_none_at_a_clean_end_of_stream() {
        let (writer, mut reader) = tokio::io::duplex(64);
        drop(writer);
        let mut buf = Vec::new();
        let mut last_heartbeat = None;
        assert_eq!(
            next_frame(&mut reader, &mut buf, &mut last_heartbeat)
                .await
                .unwrap(),
            None
        );
    }

    /// A frame whose length prefix arrived but whose body never did is
    /// truncated, not a clean close.
    #[tokio::test]
    async fn next_frame_rejects_a_length_prefix_with_no_body() {
        for body_bytes in [0usize, 3] {
            let (mut writer, mut reader) = tokio::io::duplex(64);
            {
                use tokio::io::AsyncWriteExt;
                writer.write_all(&64u32.to_be_bytes()).await.unwrap();
                if body_bytes > 0 {
                    writer.write_all(&vec![0u8; body_bytes]).await.unwrap();
                }
            }
            drop(writer); // EOF mid-frame
            let mut buf = Vec::new();
            let mut last_heartbeat = None;
            let err = next_frame(&mut reader, &mut buf, &mut last_heartbeat)
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::BadFrame),
                "a 64-byte frame truncated to {body_bytes} body bytes must be BadFrame, got {err:?}"
            );
        }
    }

    /// The complement: a close on a frame BOUNDARY (a partial length prefix
    /// counts as mid-frame too) stays a clean end of stream only when nothing
    /// at all was pending.
    #[tokio::test]
    async fn next_frame_rejects_a_partial_length_prefix() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        {
            use tokio::io::AsyncWriteExt;
            writer.write_all(&[0u8, 0, 1]).await.unwrap(); // 3 of 4 prefix bytes
        }
        drop(writer);
        let mut buf = Vec::new();
        let mut last_heartbeat = None;
        let err = next_frame(&mut reader, &mut buf, &mut last_heartbeat)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::BadFrame), "got {err:?}");
    }

    #[test]
    fn truncated_frame_preserves_a_simultaneous_application_close() {
        let close = CloseInfo {
            code: 3,
            reason: "capacity temporarily unavailable".to_owned(),
        };
        let error = merge_wire_and_terminal(
            Error::BadFrame,
            Some(Error::ApplicationClosed(close.clone())),
        );
        assert!(error.is_bad_frame());
        assert_eq!(error.close_info(), Some(&close));
        assert!(matches!(error, Error::BadFrameWithClose(_)));
    }

    // ---- preamble: loud failure, never a silent skip ------------------------

    #[tokio::test]
    async fn verify_preamble_accepts_the_real_preamble() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = writer.write_all(thornode_pulse_wire::frame::PREAMBLE).await;
        });
        verify_preamble(&mut reader).await.unwrap();
    }

    #[tokio::test]
    async fn verify_preamble_rejects_a_mismatched_header_loudly() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = writer.write_all(b"XXXXXX").await;
        });
        let err = verify_preamble(&mut reader).await.unwrap_err();
        assert!(matches!(err, Error::BadPreamble), "got {err:?}");
    }

    #[tokio::test]
    async fn verify_preamble_rejects_a_short_stream_loudly() {
        let (writer, mut reader) = tokio::io::duplex(64);
        drop(writer); // EOF before the 6-byte preamble is complete
        let err = verify_preamble(&mut reader).await.unwrap_err();
        assert!(matches!(err, Error::BadPreamble), "got {err:?}");
    }

    // ---- control-ack interpretation ---------------------------------------

    fn parse_ack(json: &str) -> Ack {
        serde_json::from_str(json).expect("ack envelope must deserialize")
    }

    /// The ack's `v` is the sig-first tier's ONLY version channel — no
    /// stream, so no preamble. A client that ignores it proceeds against a
    /// v1 server and misparses every datagram.
    #[test]
    fn an_ack_negotiating_an_older_version_is_rejected() {
        let err = ensure_initial_ack(&parse_ack(r#"{"type":"ack","ok":true,"v":1}"#)).unwrap_err();
        match err {
            Error::VersionMismatch(v) => assert_eq!(v, 1),
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn initial_ack_requires_v_but_update_ack_may_omit_it() {
        ensure_initial_ack(&parse_ack(r#"{"type":"ack","ok":true,"v":2}"#))
            .expect("v2 is what we speak");
        let missing = parse_ack(r#"{"type":"ack","ok":true}"#);
        assert_eq!(ensure_initial_ack(&missing), Err(Error::MissingVersion));
        ensure_update_ack(&missing).expect("an update ack intentionally omits v");
        ensure_update_ack(&parse_ack(r#"{"type":"ack","ok":true,"v":2}"#))
            .expect("a matching additive update version is harmless");
        assert_eq!(
            ensure_update_ack(&parse_ack(r#"{"type":"ack","ok":true,"v":3}"#)),
            Err(Error::VersionMismatch(3))
        );
    }

    #[test]
    fn ack_envelope_requires_a_known_type() {
        for json in [
            r#"{"ok":true,"v":2}"#,
            r#"{"type":"future","ok":true,"v":2}"#,
            r#"{"type":"error","ok":true,"code":4,"v":2}"#,
        ] {
            assert_eq!(ensure_initial_ack(&parse_ack(json)), Err(Error::BadFrame));
        }
    }

    /// The server's code-4 envelope has no `ok` field; it must still preserve
    /// the close code and reason as a typed terminal error.
    #[test]
    fn the_code_4_error_envelope_surfaces_typed_close_not_a_bad_frame() {
        let ack = parse_ack(
            r#"{"type":"error","code":4,"reason":"unsupported protocol version; this server speaks wire v2"}"#,
        );
        assert!(!ack.ok, "an envelope with no `ok` field is not a success");
        match ensure_initial_ack(&ack).unwrap_err() {
            Error::ApplicationClosed(close) => {
                assert_eq!(close.code, 4);
                assert_eq!(
                    close.reason,
                    "unsupported protocol version; this server speaks wire v2"
                );
                assert_eq!(close.retry_class(), RetryClass::NonRetryable);
                assert!(!close.retryable());
            }
            other => panic!("expected typed code-4 close, got {other:?}"),
        }
    }

    #[test]
    fn a_rejection_ack_surfaces_its_reason() {
        match ensure_initial_ack(&parse_ack(
            r#"{"type":"ack","ok":false,"reason":"quota exceeded: 51 > 50 accounts"}"#,
        ))
        .unwrap_err()
        {
            Error::Rejected(reason) => assert_eq!(reason, "quota exceeded: 51 > 50 accounts"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // ---- socket buffer sizing (unrelated to wire v2, unchanged behavior) ---

    /// quinn never resizes the socket it is handed, so a client built on
    /// `Endpoint::client` silently inherits `net.core.rmem_default` (212992
    /// bytes on a stock Linux). Bursts land in a buffer far too small for a
    /// shred feed, and the loss shows up as UDP receive errors nobody attributes
    /// to us. Assert we actually ask for more.
    #[test]
    fn client_socket_enlarges_the_receive_buffer() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let default_size = socket2::Socket::from(std::net::UdpSocket::bind(addr).unwrap())
            .recv_buffer_size()
            .unwrap();
        let ours = socket2::Socket::from(client_socket(addr, DEFAULT_RECV_BUFFER).unwrap())
            .recv_buffer_size()
            .unwrap();

        assert!(
            ours > default_size,
            "recv buffer {ours} is no larger than the default {default_size}"
        );
    }

    /// The kernel clamps the request to rmem_max rather than failing it, so an
    /// unreachably large ask must still yield a usable socket.
    #[test]
    fn client_socket_survives_a_clamped_request() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let sock = client_socket(addr, 1 << 30).expect("clamped request must not fail");

        assert!(sock.local_addr().is_ok());
    }
}

/// Accepts the server's self-signed certificate without verification.
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
