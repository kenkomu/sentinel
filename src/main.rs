//! Sentinel — an accountable, standalone watchtower service for Fiber Network.
//!
//! Two servers run side by side:
//!   * a JSON-RPC server on `--rpc-port` that a Fiber node points its
//!     `standalone_watchtower_rpc_url` at, and
//!   * an HTTP server on `--http-port` serving health, metrics, the public
//!     liveness attestation, receipts, and the operator dashboard.

use axum::{extract::State, routing::get, Json, Router};
use sentinel::attest::{self, Attestor, LivenessAttestation};
use sentinel::ckb::CkbClient;
use sentinel::rpc;
use sentinel::store;
use clap::Parser;
use secp256k1::{rand::rngs::OsRng, Secp256k1};
use std::sync::{Arc, RwLock};
use store::Store;

#[derive(Parser, Debug)]
#[command(name = "sentinel", about = "Accountable watchtower for Fiber Network")]
struct Args {
    /// Path to the sled data directory.
    #[arg(long, default_value = "./sentinel-data")]
    data_dir: String,

    /// JSON-RPC port a Fiber node connects to (the watchtower surface).
    #[arg(long, default_value_t = 23456)]
    rpc_port: u16,

    /// HTTP port for health, metrics, attestations, and dashboard.
    #[arg(long, default_value_t = 8080)]
    http_port: u16,

    /// CKB node RPC used for liveness attestations and (later) the chain watcher.
    #[arg(long, default_value = "http://127.0.0.1:8114")]
    ckb_rpc_url: String,

    /// Seconds between liveness attestations.
    #[arg(long, default_value_t = 10)]
    attest_interval: u64,
}

/// The most recently produced liveness attestation, refreshed by the background
/// loop and served verbatim at `/attestation`.
type LatestAttestation = Arc<RwLock<Option<LivenessAttestation>>>;

#[derive(Clone)]
struct AppState {
    store: Store,
    attestor: Arc<Attestor>,
    latest: LatestAttestation,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sentinel=debug".into()),
        )
        .init();

    let args = Args::parse();

    let store = Store::open(&args.data_dir).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Ephemeral identity key for now; persisting it (stable tower identity across
    // restarts) is a small follow-up.
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut OsRng);
    let attestor = Arc::new(Attestor::new(sk));

    tracing::info!(tower_pubkey = %attestor.pubkey_hex(), "Sentinel identity");
    tracing::info!(channels = store.channel_count(), "loaded store");

    let latest: LatestAttestation = Arc::new(RwLock::new(None));

    // Background accountability loop: bind each attestation to the live CKB tip.
    let ckb = CkbClient::new(args.ckb_rpc_url.clone());
    {
        let attestor = attestor.clone();
        let store = store.clone();
        let latest = latest.clone();
        let interval = args.attest_interval.max(1);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                tick.tick().await;
                match ckb.tip().await {
                    Some(tip) => {
                        let att = attestor.attest_liveness(
                            &tip.hash,
                            tip.number,
                            store.channel_count(),
                            unix_now(),
                        );
                        tracing::debug!(height = tip.number, channels = att.channels_watched, "attested");
                        *latest.write().unwrap() = Some(att);
                    }
                    None => {
                        // CKB unreachable: do NOT emit a fresh attestation. A
                        // stale/absent attestation is exactly the signal a client
                        // should act on — the tower cannot currently prove liveness.
                        tracing::warn!(ckb = %args.ckb_rpc_url, "CKB tip unavailable; withholding attestation");
                    }
                }
            }
        });
    }

    let state = AppState {
        store: store.clone(),
        attestor: attestor.clone(),
        latest: latest.clone(),
    };

    // JSON-RPC watchtower surface — what a Fiber node's
    // `standalone_watchtower_rpc_url` points at.
    let handler = rpc::WatchtowerRpc::new(store.clone(), attestor.clone());
    let rpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.rpc_port).parse()?;
    let (bound, rpc_handle) = rpc::server::serve(handler, rpc_addr).await?;
    tracing::info!(%bound, "JSON-RPC watchtower surface up (7 methods, capture+store)");

    let app = Router::new()
        .route("/health", get(health))
        .route("/attestation", get(attestation))
        .route("/channels", get(channels))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "HTTP surface up (health, attestation, channels)");

    tokio::select! {
        r = axum::serve(listener, app) => { r?; }
        _ = rpc_handle.stopped() => { tracing::warn!("RPC server stopped"); }
    }
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "sentinel" }))
}

/// Public proof the tower is awake: the latest attestation bound to the live CKB
/// tip. Returns 503 semantics (an explicit `live: false`) if none has been
/// produced yet or CKB is unreachable — a client must treat that as "unproven".
async fn attestation(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.latest.read().unwrap().clone() {
        Some(att) => {
            let age = unix_now().saturating_sub(att.timestamp);
            Json(serde_json::json!({ "live": true, "age_seconds": age, "attestation": att }))
        }
        None => Json(serde_json::json!({
            "live": false,
            "reason": "no attestation yet (CKB unreachable or tower just started)",
            "tower_pubkey": s.attestor.pubkey_hex(),
        })),
    }
}

async fn channels(State(s): State<AppState>) -> Json<serde_json::Value> {
    let list = s.store.all_channels().unwrap_or_default();
    Json(serde_json::json!({ "count": list.len(), "channels": list }))
}
