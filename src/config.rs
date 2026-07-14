//! Typed configuration.
//!
//! Everything network- or deployment-specific lives here so the same binary runs
//! against devnet, testnet, or mainnet with only a config file change. Loaded
//! from a TOML file; a few hot fields can be overridden on the CLI.
//!
//! The cell-dep and script-hash fields are what let Sentinel *build* penalty
//! transactions without hard-coding a network: on CKB, spending a
//! commitment-lock cell requires that lock script's code as a `cell_dep`, and
//! those out-points differ per deployment.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub ckb: CkbConfig,
    /// Present only on towers that actively defend (build+broadcast penalties).
    /// A pure monitoring/alerting tower can omit this and run detection-only.
    pub penalty: Option<PenaltyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub data_dir: String,
    pub http_port: u16,
    pub rpc_port: u16,
    pub attest_interval_secs: u64,
    pub scan_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkbConfig {
    pub rpc_url: String,
    /// How many recent blocks to treat as unstable (reorg buffer) before acting
    /// on a detected breach. A larger value trades reaction latency for safety
    /// against short reorgs.
    #[serde(default = "default_confirmations")]
    pub reorg_safety_blocks: u64,
    /// Per-request timeout (ms) and retry budget for CKB RPC calls.
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_retries")]
    pub max_retries: u32,
}

/// What a defending tower needs to assemble and pay for a penalty transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyConfig {
    /// Hex-encoded secp256k1 secret key that funds penalty-transaction fees and
    /// receives the swept balance. Keep this key funded and secured.
    pub fee_signer_key: String,
    /// Cell dep for the commitment-lock script (required to spend a commitment
    /// cell). Out-point is deployment-specific.
    pub commitment_lock_dep: CellDep,
    /// Cell dep for the secp256k1 sighash lock (fee-provider input / change).
    pub secp256k1_lock_dep: CellDep,
    /// Fee rate in shannons per 1000 bytes.
    #[serde(default = "default_fee_rate")]
    pub fee_rate_per_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellDep {
    pub tx_hash: String,
    pub index: u32,
    /// "code" or "dep_group".
    #[serde(default = "default_dep_type")]
    pub dep_type: String,
}

fn default_confirmations() -> u64 { 3 }
fn default_timeout_ms() -> u64 { 10_000 }
fn default_retries() -> u32 { 3 }
fn default_fee_rate() -> u64 { 1000 }
fn default_dep_type() -> String { "code".into() }

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            data_dir: "./sentinel-data".into(),
            http_port: 8080,
            rpc_port: 23456,
            attest_interval_secs: 10,
            scan_interval_secs: 5,
        }
    }
}

impl Default for CkbConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8114".into(),
            reorg_safety_blocks: default_confirmations(),
            request_timeout_ms: default_timeout_ms(),
            max_retries: default_retries(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self { server: ServerConfig::default(), ckb: CkbConfig::default(), penalty: None }
    }
}

impl Config {
    /// Load from a TOML file. Missing file → defaults (detection-only, no penalty).
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)?;
                Ok(toml::from_str(&text)?)
            }
            _ => Ok(Config::default()),
        }
    }

    /// A tower defends (not just monitors) only when penalty config is present.
    pub fn is_defending(&self) -> bool {
        self.penalty.is_some()
    }
}
