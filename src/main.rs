//! Sentinel — an accountable, standalone watchtower service for Fiber Network.
//!
//! Two servers run side by side:
//!   * a JSON-RPC server on `--rpc-port` that a Fiber node points its
//!     `standalone_watchtower_rpc_url` at (Stage 2), and
//!   * an HTTP server on `--http-port` serving health, metrics, the public
//!     liveness attestation, and the operator dashboard.

mod attest;
mod error;
mod rpc;
mod store;
mod watch;

use attest::Attestor;
use axum::{extract::State, routing::get, Json, Router};
use clap::Parser;
use secp256k1::{rand::rngs::OsRng, Secp256k1};
use std::sync::Arc;
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

    /// CKB node RPC the chain watcher polls.
    #[arg(long, default_value = "http://127.0.0.1:8114")]
    ckb_rpc_url: String,
}

#[derive(Clone)]
struct AppState {
    store: Store,
    attestor: Arc<Attestor>,
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

    // Stage 1: ephemeral identity key. Stage 4 persists this so the tower's
    // public identity is stable across restarts.
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut OsRng);
    let attestor = Arc::new(Attestor::new(sk));

    tracing::info!(tower_pubkey = %attestor.pubkey_hex(), "Sentinel identity");
    tracing::info!(channels = store.channel_count(), "loaded store");

    let state = AppState {
        store: store.clone(),
        attestor: attestor.clone(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/attestation", get(attestation))
        .route("/channels", get(channels))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "HTTP surface up (health, attestation, channels)");
    tracing::info!(
        rpc_port = args.rpc_port,
        ckb = %args.ckb_rpc_url,
        "JSON-RPC watchtower surface + chain watcher: wired in Stage 2/3"
    );

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "sentinel" }))
}

/// Public proof the tower is awake. In Stage 3 the tip fields come from a live
/// CKB poll; here they are placeholders so the endpoint shape is real now.
async fn attestation(State(s): State<AppState>) -> Json<attest::LivenessAttestation> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let att = s
        .attestor
        .attest_liveness("0x00", 0, s.store.channel_count(), ts);
    Json(att)
}

async fn channels(State(s): State<AppState>) -> Json<serde_json::Value> {
    let list = s.store.all_channels().unwrap_or_default();
    Json(serde_json::json!({ "count": list.len(), "channels": list }))
}
