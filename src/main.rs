//! Sentinel — an accountable, standalone watchtower service for Fiber Network.
//!
//! Two servers run side by side:
//!   * a JSON-RPC server on `--rpc-port` that a Fiber node points its
//!     `standalone_watchtower_rpc_url` at, and
//!   * an HTTP server on `--http-port` serving health, metrics, the public
//!     liveness attestation, receipts, and the operator dashboard.

use axum::{extract::State, routing::get, Json, Router};
use sentinel::attest::{Attestor, LivenessAttestation};
use sentinel::ckb::CkbClient;
use sentinel::metrics::Metrics;
use sentinel::watch::{ChainWatcher, ScanOutcome, WatchParams};
use sentinel::detector::Verdict;
use sentinel::rpc;
use sentinel::store;
use clap::Parser;
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

    /// Seconds between chain scans for breaches.
    #[arg(long, default_value_t = 5)]
    scan_interval: u64,

    /// Funding-lock code hash for this network (devnet default shown).
    #[arg(long, default_value = "0xf02ae41c20f3baeda929b5fd87703978e48aed9a6ac6d993ec8a375f941da021")]
    funding_lock_code_hash: String,

    /// Funding-lock hash type: "data2" | "type" | "data" | "data1".
    #[arg(long, default_value = "data2")]
    funding_lock_hash_type: String,

    /// Blocks of confirmation before acting on a detected spend (reorg safety).
    #[arg(long, default_value_t = 3)]
    reorg_safety_blocks: u64,

    /// Optional TOML config enabling active defence (penalty broadcast). Without
    /// it, the tower runs in detection/alerting-only mode.
    #[arg(long)]
    config: Option<String>,
}

/// The most recently produced liveness attestation, refreshed by the background
/// loop and served verbatim at `/attestation`.
type LatestAttestation = Arc<RwLock<Option<LivenessAttestation>>>;

/// Latest scan outcomes, keyed by channel_id, refreshed each scan and surfaced
/// on the dashboard and `/breaches`.
type LatestScan = Arc<RwLock<Vec<ScanOutcome>>>;

#[derive(Clone)]
struct AppState {
    store: Store,
    attestor: Arc<Attestor>,
    latest: LatestAttestation,
    metrics: Metrics,
    scan: LatestScan,
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

    // Stable tower identity: loaded from the data dir, generated on first run,
    // so clients keep verifying against the same public key across restarts.
    let sk = sentinel::identity::load_or_create(&args.data_dir)
        .map_err(|e| anyhow::anyhow!("tower identity: {e}"))?;
    let attestor = Arc::new(Attestor::new(sk));

    tracing::info!(tower_pubkey = %attestor.pubkey_hex(), "Sentinel identity");
    tracing::info!(channels = store.channel_count(), "loaded store");

    let latest: LatestAttestation = Arc::new(RwLock::new(None));
    let metrics = Metrics::new();
    let height = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Background accountability loop: bind each attestation to the live CKB tip.
    let ckb = CkbClient::new(args.ckb_rpc_url.clone());
    {
        let attestor = attestor.clone();
        let store = store.clone();
        let latest = latest.clone();
        let metrics = metrics.clone();
        let height = height.clone();
        let interval = args.attest_interval.max(1);
        let ckb_url = args.ckb_rpc_url.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                tick.tick().await;
                let tenants = store.tenant_count();
                metrics.channels_watched.set(store.channel_count() as i64);
                metrics.tenants.set(tenants as i64);
                match ckb.tip().await {
                    Some(tip) => {
                        let att = attestor.attest_liveness(
                            &tip.hash,
                            tip.number,
                            store.channel_count(),
                            unix_now(),
                        );
                        tracing::debug!(height = tip.number, channels = att.channels_watched, "attested");
                        metrics.live.set(1);
                        metrics.ckb_tip_height.set(tip.number as i64);
                        metrics.attestation_age.set(0);
                        height.store(tip.number, std::sync::atomic::Ordering::Relaxed);
                        *latest.write().unwrap_or_else(|p| p.into_inner()) = Some(att);
                    }
                    None => {
                        // CKB unreachable: do NOT emit a fresh attestation. A
                        // stale/absent attestation is exactly the signal a client
                        // should act on — the tower cannot currently prove liveness.
                        tracing::warn!(ckb = %ckb_url, "CKB tip unavailable; withholding attestation");
                        metrics.live.set(0);
                        if let Some(a) = latest.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
                            metrics.attestation_age.set(unix_now().saturating_sub(a.timestamp) as i64);
                        }
                    }
                }
            }
        });
    }

    // Optional penalty config enables active defence.
    let penalty_cfg = args
        .config
        .as_ref()
        .and_then(|p| sentinel::config::Config::load(Some(std::path::Path::new(p))).ok())
        .and_then(|c| c.penalty);
    if penalty_cfg.is_some() {
        tracing::info!("active defence ENABLED — breaches will be punished on-chain");
    } else {
        tracing::info!("detection-only mode — breaches detected and alerted, not punished");
    }

    // Background chain-scan loop: detect breaches across all watched channels.
    let scan: LatestScan = Arc::new(RwLock::new(Vec::new()));
    {
        let mut watcher = ChainWatcher::new(
            store.clone(),
            CkbClient::with_opts(args.ckb_rpc_url.clone(), 10_000, 3),
            WatchParams {
                funding_lock_code_hash: args.funding_lock_code_hash.clone(),
                funding_lock_hash_type: args.funding_lock_hash_type.clone(),
                reorg_safety_blocks: args.reorg_safety_blocks,
            },
        );
        if let Some(pc) = penalty_cfg.clone() {
            match sentinel::penalty::ckb_executor::CkbPenaltyExecutor::new(
                CkbClient::with_opts(args.ckb_rpc_url.clone(), 10_000, 3),
                pc,
            ) {
                Ok(exec) => watcher = watcher.with_executor(Arc::new(exec)),
                Err(e) => tracing::error!(error = %e, "failed to init penalty executor; staying detection-only"),
            }
        }
        let scan = scan.clone();
        let height = height.clone();
        let metrics = metrics.clone();
        let interval = args.scan_interval.max(1);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                tick.tick().await;
                let tip = height.load(std::sync::atomic::Ordering::Relaxed);
                if tip == 0 {
                    continue; // wait until we know the chain tip
                }
                let outcomes = watcher.scan_once(tip).await;
                let breaches = outcomes
                    .iter()
                    .filter(|o| matches!(o.verdict, Verdict::Breach { .. }))
                    .count();
                metrics.breaches_detected.set(breaches as i64);
                if breaches > 0 {
                    tracing::warn!(breaches, "scan: active breaches detected");
                }
                *scan.write().unwrap_or_else(|p| p.into_inner()) = outcomes;
            }
        });
    }

    let state = AppState {
        store: store.clone(),
        attestor: attestor.clone(),
        latest: latest.clone(),
        metrics: metrics.clone(),
        scan: scan.clone(),
    };

    // JSON-RPC watchtower surface — what a Fiber node's
    // `standalone_watchtower_rpc_url` points at.
    let handler = rpc::WatchtowerRpc::new(store.clone(), attestor.clone(), height.clone());
    let rpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.rpc_port).parse()?;
    let (bound, rpc_handle) = rpc::server::serve(handler, rpc_addr).await?;
    tracing::info!(%bound, "JSON-RPC watchtower surface up (7 methods, capture+store)");

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/attestation", get(attestation))
        .route("/channels", get(channels))
        .route("/receipts", get(receipts))
        .route("/breaches", get(breaches))
        .route("/metrics", get(metrics_endpoint))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "HTTP surface up (health, attestation, channels)");

    tokio::select! {
        r = axum::serve(listener, app) => { r?; }
        _ = rpc_handle.stopped() => { tracing::warn!("RPC server stopped"); }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; flushing store and exiting");
            if let Err(e) = store.flush() {
                tracing::error!(error = %e, "store flush on shutdown failed");
            }
        }
    }
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM so the tower shuts down cleanly (flushing the
/// store) instead of being killed mid-write.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

/// The operator watch-console (self-contained HTML, polls the JSON endpoints).
async fn dashboard() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web/index.html"))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "sentinel" }))
}

/// Public proof the tower is awake: the latest attestation bound to the live CKB
/// tip. Content-negotiated — a browser (Accept: text/html) gets a human-facing
/// page that verifies the signature client-side; everything else (the `verify`
/// tool, curl, wallets) gets the raw JSON. `live: false` means "unproven".
async fn attestation(
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        return axum::response::Html(include_str!("../web/attestation.html")).into_response();
    }
    let body = match s.latest.read().unwrap_or_else(|p| p.into_inner()).clone() {
        Some(att) => {
            let age = unix_now().saturating_sub(att.timestamp);
            serde_json::json!({ "live": true, "age_seconds": age, "attestation": att })
        }
        None => serde_json::json!({
            "live": false,
            "reason": "no attestation yet (CKB unreachable or tower just started)",
            "tower_pubkey": s.attestor.pubkey_hex(),
        }),
    };
    Json(body).into_response()
}

async fn channels(State(s): State<AppState>) -> Json<serde_json::Value> {
    let list = s.store.all_channels().unwrap_or_default();
    Json(serde_json::json!({ "count": list.len(), "channels": list }))
}

/// Signed receipts the tower issued when it accepted each channel.
async fn receipts(State(s): State<AppState>) -> Json<serde_json::Value> {
    let list = s.store.all_receipts().unwrap_or_default();
    Json(serde_json::json!({ "count": list.len(), "receipts": list }))
}

/// Current per-channel scan verdicts, with breaches surfaced first.
async fn breaches(State(s): State<AppState>) -> Json<serde_json::Value> {
    let outcomes = s.scan.read().unwrap_or_else(|p| p.into_inner()).clone();
    let rows: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "channel_id": o.channel_id,
                "node_id": o.node_id,
                "verdict": verdict_json(&o.verdict),
            })
        })
        .collect();
    let breach_count = outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Breach { .. }))
        .count();
    Json(serde_json::json!({ "breaches": breach_count, "outcomes": rows }))
}

fn verdict_json(v: &Verdict) -> serde_json::Value {
    match v {
        Verdict::ChannelOpen => serde_json::json!({ "state": "channel_open" }),
        Verdict::LegitimateClose { broadcast_commitment } => {
            serde_json::json!({ "state": "legitimate_close", "commitment": broadcast_commitment })
        }
        Verdict::Breach { commitment_tx, broadcast_commitment, held_commitment, .. } => {
            serde_json::json!({
                "state": "breach",
                "commitment_tx": commitment_tx,
                "broadcast_commitment": broadcast_commitment,
                "held_commitment": held_commitment,
            })
        }
        Verdict::BreachResolved { commitment_tx } => {
            serde_json::json!({ "state": "breach_resolved", "commitment_tx": commitment_tx })
        }
        Verdict::Unactionable { reason } => {
            serde_json::json!({ "state": "unactionable", "reason": reason })
        }
    }
}

/// Prometheus exposition endpoint.
async fn metrics_endpoint(State(s): State<AppState>) -> String {
    s.metrics.encode()
}
