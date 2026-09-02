//! Remote-query transport tests: in-process endpoint pairs, like tests/p2p.rs.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::presets, protocol::Router};
use linxiv_p2p::{ApiClientError, ApiProtocol, ApiResponse, NodeAddress, TransferOutcome, api};
use serde_json::{Value, json};

const PDF_SIZE: u64 = 6000;
const PDF_RATE: u64 = 3000;

fn pdf_bytes() -> Vec<u8> {
    (0..PDF_SIZE).map(|i| (i % 251) as u8).collect()
}

/// Echo handler: `path == "/pdf"` answers on the byte lane, anything else
/// echoes the request back inside a 200 envelope.
fn handler() -> api::ApiHandlerFn<String> {
    Arc::new(|member: String, body: Vec<u8>| {
        Box::pin(async move {
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            if req.get("path").and_then(Value::as_str) == Some("/pdf") {
                ApiResponse::Bytes {
                    header: api::byte_header(PDF_SIZE, PDF_RATE),
                    source: Box::new(std::io::Cursor::new(pdf_bytes())),
                    size: PDF_SIZE,
                    rate: PDF_RATE,
                }
            } else {
                ApiResponse::Json(json!({
                    "status": 200,
                    "body": { "member": member, "echo": req },
                }))
            }
        })
    })
}

struct Logs {
    knocks: Arc<Mutex<Vec<String>>>,
    transfers: Arc<Mutex<Vec<TransferOutcome>>>,
}

/// A server admitting only `admit` (as role "read-write"), plus a client
/// endpoint, both bound locally (no relays/discovery).
async fn bind_pair(
    admit: Option<EndpointId>,
    max_request: usize,
) -> Result<(Router, EndpointAddr, Endpoint, Logs)> {
    let knocks: Arc<Mutex<Vec<String>>> = Default::default();
    let transfers: Arc<Mutex<Vec<TransferOutcome>>> = Default::default();
    let logs = Logs {
        knocks: knocks.clone(),
        transfers: transfers.clone(),
    };
    let admit = admit.map(|id| id.to_string());
    let proto = ApiProtocol::new(
        Arc::new(move |peer: &str| {
            (Some(peer) == admit.as_deref()).then(|| "read-write".to_string())
        }),
        Arc::new(move |peer: &str| knocks.lock().unwrap().push(peer.to_string())),
        Arc::new(move |_peer: &str, outcome| transfers.lock().unwrap().push(outcome)),
        handler(),
        max_request,
    );
    let server = Endpoint::builder(presets::Minimal).bind().await?;
    let router = Router::builder(server).accept(api::ALPN, proto).spawn();
    let addr = router.endpoint().addr();
    let client = Endpoint::builder(presets::Minimal).bind().await?;
    Ok((router, addr, client, logs))
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_endpoint_is_refused_at_transport() -> Result<()> {
    // admit nobody: the client is a stranger.
    let (router, addr, client, logs) = bind_pair(None, 1024).await?;
    let conn = api::connect(&client, addr).await?;
    let err = api::request(&conn, &json!({"method": "GET", "path": "/papers"}))
        .await
        .expect_err("a stranger must not get an answer");
    assert!(
        matches!(err, ApiClientError::Refused),
        "expected transport refusal, got: {err}"
    );
    assert_eq!(
        *logs.knocks.lock().unwrap(),
        vec![client.id().to_string()],
        "the knock log must record the stranger's endpoint id"
    );
    router.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn admitted_member_round_trips_json() -> Result<()> {
    let client_ep = Endpoint::builder(presets::Minimal).bind().await?;
    let (router, addr, _unused, logs) = bind_pair(Some(client_ep.id()), 1024 * 1024).await?;
    let conn = api::connect(&client_ep, addr).await?;
    let req = json!({"method": "GET", "path": "/papers", "body": null});
    let envelope = api::request(&conn, &req)
        .await
        .expect("admitted round trip");
    assert_eq!(envelope["status"], 200);
    assert_eq!(envelope["body"]["member"], "read-write");
    assert_eq!(envelope["body"]["echo"], req);
    assert!(
        logs.knocks.lock().unwrap().is_empty(),
        "no knock for members"
    );
    router.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn byte_lane_delivers_exact_paced_payload() -> Result<()> {
    let client_ep = Endpoint::builder(presets::Minimal).bind().await?;
    let (router, addr, _unused, logs) = bind_pair(Some(client_ep.id()), 1024 * 1024).await?;
    let conn = api::connect(&client_ep, addr).await?;
    let start = Instant::now();
    let (header, lane) = api::request_bytes(&conn, &json!({"method": "GET", "path": "/pdf"}))
        .await
        .expect("byte-lane request");
    assert_eq!(header["status"], 200);
    assert_eq!(header["size"], PDF_SIZE);
    assert_eq!(header["rate"], PDF_RATE);
    let eta = header["eta_seconds"].as_f64().unwrap();
    assert!(
        (eta - 4.0).abs() < 0.01,
        "eta = size/rate + 2s slack, got {eta}"
    );
    assert_eq!(lane.size(), PDF_SIZE);
    let bytes = lane.read_to_vec().await?;
    assert_eq!(bytes, pdf_bytes());
    // 6000 B at 3000 B/s = 2 s of pacing; generous lower bound for CI jitter.
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1400),
        "pacing not respected: finished in {elapsed:?}"
    );
    // the sender logs Delivered right after its finish(); poll briefly.
    for _ in 0..50 {
        if !logs.transfers.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        *logs.transfers.lock().unwrap(),
        vec![TransferOutcome::Delivered { bytes: PDF_SIZE }]
    );
    router.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_request_is_answered_413() -> Result<()> {
    let client_ep = Endpoint::builder(presets::Minimal).bind().await?;
    let (router, addr, _unused, _logs) = bind_pair(Some(client_ep.id()), 1024).await?;
    let conn = api::connect(&client_ep, addr).await?;
    let req = json!({"method": "POST", "path": "/papers", "body": "x".repeat(4096)});
    let envelope = api::request(&conn, &req)
        .await
        .expect("an oversized request is answered, not dropped");
    assert_eq!(envelope["status"], 413);
    assert!(envelope["detail"].is_string());
    router.shutdown().await?;
    Ok(())
}

#[test]
fn node_address_roundtrip() {
    let id = iroh::SecretKey::generate().public();
    let relay: iroh::RelayUrl = "https://relay.example.com".parse().unwrap();
    let node = NodeAddress::new(id, relay.clone());
    let s = node.to_string();
    assert!(s.starts_with("linxivnode"), "got: {s}");
    let parsed: NodeAddress = s.parse().unwrap();
    assert_eq!(parsed, node);
    assert_eq!(parsed.endpoint_id(), id);
    assert_eq!(parsed.relay_url(), &relay);
    let addr = parsed.endpoint_addr();
    assert_eq!(addr.id, id);
    assert!(addr.relay_urls().any(|u| u == &relay));
}
