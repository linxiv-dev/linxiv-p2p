//! Remote Query Mode transport: JSON request/response plus a paced raw-byte
//! lane (PDFs) over one iroh ALPN.
//!
//! linXiv-agnostic by design: the member/role type `M` and every policy
//! decision (roles, route groups, Provider Access) live in the caller's
//! callbacks. This module only enforces the transport rule that matters at
//! this layer: a peer the member check rejects is refused at the transport —
//! the connection is closed without answering anything, so a non-member
//! cannot tell "node offline" from "not admitted".
//!
//! Wire shape (one bidi stream per request): the client writes its request
//! JSON and finishes; the server reads to end (capped), answers, finishes.
//! JSON answers are a single envelope object. Byte answers are one JSON
//! header line terminated by `\n` followed by exactly `size` raw bytes,
//! paced at `rate` bytes/sec.

use std::{fmt, future::Future, pin::Pin, str::FromStr, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl,
    endpoint::{Connection, ConnectionError, ReadToEndError, RecvStream, SendStream},
    protocol::{AcceptError, DynProtocolHandler, ProtocolHandler},
};
use iroh_tickets::{ParseError, Ticket};
use n0_error::{AnyError, Result, StackResultExt, StdResultExt, anyerr};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::sync::RECV_TIMEOUT;

/// ALPN for linXiv remote-query API sessions. The protocol version lives in
/// the string: an incompatible v2 gets a new ALPN, never a handshake field.
pub const ALPN: &[u8] = b"linxiv-api/1";

/// Close code for a transport refusal (non-member / role-none knock). The
/// reason bytes are empty on purpose: the node reveals nothing to strangers.
const REFUSED_CODE: u32 = 1;

/// Cap on a JSON response (or byte-lane header line) the client buffers.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// Cap on a byte-lane payload the client will buffer: the declared `size`
/// is remote-controlled, so it must never drive an allocation past this.
const MAX_LANE_PAYLOAD: u64 = 256 * 1024 * 1024;

// --- server ------------------------------------------------------------------

/// Membership gate: `remote endpoint id (string form)` -> the caller's
/// member/role context, or `None` for "refuse at the transport" (unknown
/// device, or an admitted device whose role is `none`).
pub type MemberCheckFn<M> = Arc<dyn Fn(&str) -> Option<M> + Send + Sync>;

/// Fired with the knocking endpoint id when a connection is refused.
pub type KnockLogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// Per-connection request-body cap, derived from the admitted member: role
/// `read` gets ~1 MiB, `read-write` enough for `file_b64` PDF imports.
pub type MaxRequestFn<M> = Arc<dyn Fn(&M) -> usize + Send + Sync>;

/// Fired with `(peer endpoint id, outcome)` when a byte-lane transfer ends.
/// There is no application-level receipt: this is the sender's own view.
pub type TransferLogFn = Arc<dyn Fn(&str, TransferOutcome) + Send + Sync>;

/// Per-request handler: `(member context, raw request bytes)` -> response.
/// The JSON envelope (`{"status":..,"body":..}` / `{"status":..,"detail":..}`)
/// is built by the caller; the transport ships it verbatim.
pub type ApiHandlerFn<M> =
    Arc<dyn Fn(M, Vec<u8>) -> Pin<Box<dyn Future<Output = ApiResponse> + Send>> + Send + Sync>;

/// What a handler answers a request with.
pub enum ApiResponse {
    /// A complete JSON envelope, shipped as the whole stream body.
    Json(Value),
    /// Byte lane: `header` (see [`byte_header`]) as one `\n`-terminated line,
    /// then exactly `size` bytes read from `source`, paced at `rate` bytes/sec.
    Bytes {
        header: Value,
        source: Box<dyn AsyncRead + Send + Unpin>,
        size: u64,
        rate: u64,
    },
}

/// The sender-side outcome of one byte-lane transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    /// Every byte was written and the stream finished cleanly.
    Delivered { bytes: u64 },
    /// The write side failed (peer reset / connection lost / short source)
    /// after `sent` payload bytes.
    Aborted { sent: u64 },
}

/// The byte-lane success header: `eta_seconds` is the paced transfer time
/// plus a couple seconds of latency slack.
pub fn byte_header(size: u64, rate: u64) -> Value {
    json!({
        "status": 200,
        "size": size,
        "rate": rate,
        "eta_seconds": size as f64 / rate.max(1) as f64 + 2.0,
    })
}

/// The remote-query protocol handler. Mount it on a router at [`ALPN`]:
/// `Router::builder(endpoint).accept(api::ALPN, proto).spawn()`.
#[derive(Clone)]
pub struct ApiProtocol<M> {
    member_check: MemberCheckFn<M>,
    knock_log: KnockLogFn,
    transfer_log: TransferLogFn,
    handler: ApiHandlerFn<M>,
    max_request: MaxRequestFn<M>,
}

impl<M> fmt::Debug for ApiProtocol<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiProtocol").finish_non_exhaustive()
    }
}

impl<M: Clone + Send + 'static> ApiProtocol<M> {
    /// `max_request` derives the request-body cap from the admitted member
    /// (role-aware by design: ~1 MiB for `read`, upload-sized for
    /// `read-write`); an oversized request is answered with a `413` envelope.
    pub fn new(
        member_check: MemberCheckFn<M>,
        knock_log: KnockLogFn,
        transfer_log: TransferLogFn,
        handler: ApiHandlerFn<M>,
        max_request: MaxRequestFn<M>,
    ) -> Self {
        Self {
            member_check,
            knock_log,
            transfer_log,
            handler,
            max_request,
        }
    }

    async fn handle_stream(
        &self,
        member: M,
        peer: &str,
        mut send: SendStream,
        mut recv: RecvStream,
    ) {
        let max_request = (self.max_request)(&member);
        let body =
            match tokio::time::timeout(RECV_TIMEOUT, recv.read_to_end(max_request)).await {
                Ok(Ok(body)) => body,
                Ok(Err(ReadToEndError::TooLong)) => {
                    let env = json!({
                        "status": 413,
                        "detail": format!("request body exceeds {max_request} bytes"),
                    });
                    let _ = send.write_all(env.to_string().as_bytes()).await;
                    let _ = send.finish();
                    return;
                }
                // reset or silent peer: nothing sensible to answer.
                _ => return,
            };
        match (self.handler)(member, body).await {
            ApiResponse::Json(env) => {
                let _ = send.write_all(env.to_string().as_bytes()).await;
                let _ = send.finish();
            }
            ApiResponse::Bytes {
                header,
                mut source,
                size,
                rate,
            } => {
                let mut line = header.to_string().into_bytes();
                line.push(b'\n');
                if send.write_all(&line).await.is_err() {
                    (self.transfer_log)(peer, TransferOutcome::Aborted { sent: 0 });
                    return;
                }
                // outcome comes from our own write result: finish ok =
                // delivered. No application-level receipt by design.
                let outcome = match stream_paced(&mut send, &mut *source, size, rate).await {
                    Ok(bytes) if send.finish().is_ok() => TransferOutcome::Delivered { bytes },
                    Ok(bytes) => TransferOutcome::Aborted { sent: bytes },
                    Err(sent) => TransferOutcome::Aborted { sent },
                };
                (self.transfer_log)(peer, outcome);
            }
        }
    }
}

impl<M: Clone + Send + 'static> ProtocolHandler for ApiProtocol<M> {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let peer = conn.remote_id().to_string();
        let Some(member) = (self.member_check)(&peer) else {
            (self.knock_log)(&peer);
            conn.close(REFUSED_CODE.into(), b"");
            return Ok(());
        };
        // one bidi stream per request; spawned so a paced byte transfer
        // doesn't head-of-line block the next request on this connection.
        while let Ok((send, recv)) = conn.accept_bi().await {
            let proto = self.clone();
            let member = member.clone();
            let peer = peer.clone();
            tokio::spawn(async move { proto.handle_stream(member, &peer, send, recv).await });
        }
        Ok(())
    }
}

/// Late-mount slot for [`ApiProtocol`]: iroh routers take protocols only at
/// build time, but the bind paths run before the app can construct its
/// handler (it closes over app state). So every bind mounts this empty slot
/// at [`ALPN`] and the app installs the real handler afterwards. An empty
/// slot refuses every connection with the same silence a non-member gets —
/// desktop nodes simply never install anything.
#[derive(Debug, Clone, Default)]
pub struct ApiSlot(Arc<std::sync::Mutex<Option<Arc<dyn DynProtocolHandler>>>>);

impl ApiSlot {
    /// Installs (or replaces) the handler served at [`ALPN`].
    pub fn install(&self, handler: impl Into<Box<dyn DynProtocolHandler>>) {
        *self.0.lock().unwrap() = Some(Arc::from(handler.into()));
    }
}

impl ProtocolHandler for ApiSlot {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        let inner = self.0.lock().unwrap().clone();
        match inner {
            Some(handler) => handler.accept(conn).await,
            None => {
                conn.close(REFUSED_CODE.into(), b"");
                Ok(())
            }
        }
    }
}

/// Writes `size` bytes from `source`, paced at `rate` bytes/sec with a
/// sleep-based schedule. `Ok(sent)` on success, `Err(sent)` when the write
/// failed or the source ran dry before `size`.
async fn stream_paced(
    send: &mut SendStream,
    source: &mut (dyn AsyncRead + Send + Unpin),
    size: u64,
    rate: u64,
) -> std::result::Result<u64, u64> {
    // ponytail: fixed chunk = rate/10 clamped to [1 KiB, 256 KiB]; a real
    // token bucket only if burst smoothing ever matters.
    let chunk = ((rate / 10).clamp(1024, 256 * 1024)) as usize;
    let start = tokio::time::Instant::now();
    let mut buf = vec![0u8; chunk];
    let mut sent: u64 = 0;
    while sent < size {
        let want = chunk.min((size - sent) as usize);
        let n = match source.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => return Err(sent),
            Ok(n) => n,
        };
        if send.write_all(&buf[..n]).await.is_err() {
            return Err(sent);
        }
        sent += n as u64;
        let due = start + Duration::from_secs_f64(sent as f64 / rate.max(1) as f64);
        tokio::time::sleep_until(due).await;
    }
    Ok(sent)
}

// --- client ------------------------------------------------------------------

/// Typed client failure, so an answered error envelope (which [`request`]
/// returns as `Ok`) is never confused with a transport-level close.
#[derive(Debug)]
pub enum ApiClientError {
    /// The node closed the connection without answering. Non-member,
    /// role-none, or node shutting down — indistinguishable by design.
    Refused,
    Other(AnyError),
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiClientError::Refused => write!(f, "node closed the connection without answering"),
            ApiClientError::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ApiClientError {}

/// Dials `addr` on the remote-query [`ALPN`].
pub async fn connect(endpoint: &Endpoint, addr: impl Into<EndpointAddr>) -> Result<Connection> {
    endpoint
        .connect(addr.into(), ALPN)
        .await
        .context("dialing api node")
}

/// One JSON request/response round trip on its own stream. `request` is the
/// ApiRequest object (`{method, path, body}`); the return value is the
/// server's envelope — including answered errors like `{"status":413,..}`.
pub async fn request(
    conn: &Connection,
    request: &Value,
) -> std::result::Result<Value, ApiClientError> {
    let mut recv = send_request(conn, request).await?;
    let buf = match tokio::time::timeout(RECV_TIMEOUT, recv.read_to_end(MAX_RESPONSE)).await {
        Err(_) => {
            return Err(ApiClientError::Other(anyerr!(
                "timed out waiting for api response"
            )));
        }
        Ok(Err(e)) => return Err(refusal_or(conn, anyerr!("reading api response: {e}"))),
        Ok(Ok(buf)) => buf,
    };
    if buf.is_empty() {
        // stream finished with no body: the node hung up without answering.
        return Err(ApiClientError::Refused);
    }
    serde_json::from_slice(&buf)
        .map_err(|e| ApiClientError::Other(anyerr!("response is not valid JSON: {e}")))
}

/// Byte-lane request: returns the parsed header and a [`ByteLane`] carrying
/// the declared payload. On an answered error the header is the error
/// envelope and the lane is empty (`size == 0`).
pub async fn request_bytes(
    conn: &Connection,
    request: &Value,
) -> std::result::Result<(Value, ByteLane), ApiClientError> {
    let mut recv = send_request(conn, request).await?;
    let line = match tokio::time::timeout(RECV_TIMEOUT, read_header_line(&mut recv)).await {
        Err(_) => {
            return Err(ApiClientError::Other(anyerr!(
                "timed out waiting for byte-lane header"
            )));
        }
        Ok(Err(e)) => return Err(refusal_or(conn, e)),
        Ok(Ok(None)) => return Err(ApiClientError::Refused),
        Ok(Ok(Some(line))) => line,
    };
    let header: Value = serde_json::from_slice(&line)
        .map_err(|e| ApiClientError::Other(anyerr!("byte-lane header is not valid JSON: {e}")))?;
    let size = header.get("size").and_then(Value::as_u64).unwrap_or(0);
    Ok((header, ByteLane { recv, size }))
}

/// The raw-byte half of a [`request_bytes`] answer: exactly [`Self::size`]
/// bytes. No read deadline — a paced transfer legitimately takes
/// `eta_seconds`; the caller owns any timeout policy.
pub struct ByteLane {
    recv: RecvStream,
    size: u64,
}

impl fmt::Debug for ByteLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteLane {{ size: {} }}", self.size)
    }
}

impl ByteLane {
    /// The payload size the header declared.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads the whole payload; errors if the stream carries fewer or more
    /// bytes than declared, or declares more than [`MAX_LANE_PAYLOAD`].
    // ponytail: buffers in memory (PDF-sized payloads); add a
    // stream-to-file helper when callers outgrow Vec.
    pub async fn read_to_vec(mut self) -> Result<Vec<u8>> {
        if self.size > MAX_LANE_PAYLOAD {
            return Err(anyerr!(
                "byte-lane payload declares {} bytes, cap is {MAX_LANE_PAYLOAD}",
                self.size
            ));
        }
        let size = usize::try_from(self.size).std_context("byte-lane size")?;
        // Grow with the bytes actually received — the declared size is the
        // peer's claim, never the initial allocation.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        while buf.len() < size {
            let want = chunk.len().min(size - buf.len());
            match self
                .recv
                .read(&mut chunk[..want])
                .await
                .std_context("reading byte-lane payload")?
            {
                None => return Err(anyerr!("byte lane ended before its declared size")),
                Some(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        match self
            .recv
            .read(&mut [0u8; 1])
            .await
            .std_context("checking byte-lane end")?
        {
            None => Ok(buf),
            Some(_) => Err(anyerr!("byte lane overran its declared size")),
        }
    }
}

/// Opens a stream, writes the request JSON, finishes the send side.
async fn send_request(
    conn: &Connection,
    request: &Value,
) -> std::result::Result<RecvStream, ApiClientError> {
    let res = async {
        let (mut send, recv) = conn.open_bi().await.std_context("opening request stream")?;
        send.write_all(request.to_string().as_bytes())
            .await
            .std_context("writing request")?;
        send.finish().std_context("finishing request")?;
        Ok::<_, AnyError>(recv)
    }
    .await;
    res.map_err(|e| refusal_or(conn, e))
}

/// A failure on a connection the peer application-closed is a refusal;
/// anything else surfaces as-is.
fn refusal_or(conn: &Connection, e: AnyError) -> ApiClientError {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(_)) => ApiClientError::Refused,
        _ => ApiClientError::Other(e),
    }
}

/// Bytes up to a consumed-and-excluded `\n`, or up to clean end-of-stream
/// (the answered-error case ships a bare envelope with no newline).
/// `None` if the stream finished with no bytes at all.
async fn read_header_line(recv: &mut RecvStream) -> Result<Option<Vec<u8>>> {
    // ponytail: byte-at-a-time reads; the header is ~100 bytes.
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match recv
            .read(&mut b)
            .await
            .std_context("reading byte-lane header")?
        {
            None => return Ok(if line.is_empty() { None } else { Some(line) }),
            Some(_) if b[0] == b'\n' => return Ok(Some(line)),
            Some(_) => {
                line.push(b[0]);
                if line.len() > MAX_RESPONSE {
                    return Err(anyerr!("byte-lane header exceeds {MAX_RESPONSE} bytes"));
                }
            }
        }
    }
}

// --- node address ------------------------------------------------------------

/// A compact copyable locator for a headless node: endpoint id + relay URL.
/// A locator, not a capability — possessing it grants nothing; the node's
/// member check alone decides access.
///
/// Round-trips through its `Display`/`FromStr` string form
/// (`linxivnode...`, same encoding family as [`crate::ShareTicket`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddress {
    id: EndpointId,
    relay: RelayUrl,
}

impl NodeAddress {
    pub fn new(id: EndpointId, relay: RelayUrl) -> Self {
        Self { id, relay }
    }

    /// The node's endpoint id.
    pub fn endpoint_id(&self) -> EndpointId {
        self.id
    }

    /// The relay the node is reachable through.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay
    }

    /// The dialable address (id + relay hop) for [`connect`].
    pub fn endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr::new(self.id).with_relay_url(self.relay.clone())
    }
}

impl Ticket for NodeAddress {
    const KIND: &'static str = "linxivnode";

    fn encode_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&(&self.id, &self.relay)).expect("postcard serialization failed")
    }

    fn decode_bytes(bytes: &[u8]) -> std::result::Result<Self, ParseError> {
        let (id, relay) = postcard::from_bytes(bytes)?;
        Ok(Self { id, relay })
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode_string())
    }
}

impl FromStr for NodeAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, ParseError> {
        Self::decode_string(s)
    }
}
