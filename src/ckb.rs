//! Resilient CKB JSON-RPC + indexer client.
//!
//! Every call retries with bounded exponential backoff and a per-request
//! timeout, and returns `Result` rather than panicking — the watcher must treat
//! a flaky node as a transient condition, never a crash. Read methods degrade to
//! `Ok(None)` / errors the caller can skip; the write method (`send_transaction`)
//! surfaces failures so a failed penalty broadcast is visible and retried.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Tip {
    pub hash: String,
    pub number: u64,
}

/// A transaction that spent a watched cell, with its confirmation depth.
#[derive(Debug, Clone)]
pub struct SpendingTx {
    pub tx_hash: String,
    pub block_number: u64,
}

#[derive(Clone)]
pub struct CkbClient {
    url: String,
    http: reqwest::Client,
    max_retries: u32,
}

impl CkbClient {
    pub fn new(url: String) -> Self {
        Self::with_opts(url, 10_000, 3)
    }

    pub fn with_opts(url: String, timeout_ms: u64, max_retries: u32) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();
        Self { url, http, max_retries }
    }

    /// One JSON-RPC call with retry/backoff. Returns the `result` value.
    async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({ "id": 1, "jsonrpc": "2.0", "method": method, "params": params });
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.try_call(&body).await {
                Ok(v) => return Ok(v),
                Err(e) if attempt <= self.max_retries => {
                    let backoff = Duration::from_millis(150 * 2u64.pow(attempt - 1));
                    tracing::debug!(method, attempt, ?backoff, error = %e, "CKB call failed; retrying");
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_call(&self, body: &Value) -> anyhow::Result<Value> {
        let resp = self.http.post(&self.url).json(body).send().await?;
        let v: Value = resp.json().await?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            anyhow::bail!("CKB RPC error: {err}");
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn tip(&self) -> Option<Tip> {
        let header = self.call("get_tip_header", json!([])).await.ok()?;
        Some(Tip {
            hash: header.get("hash")?.as_str()?.to_string(),
            number: u64::from_str_radix(
                header.get("number")?.as_str()?.trim_start_matches("0x"),
                16,
            )
            .ok()?,
        })
    }

    /// Find the transaction that spent a cell locked by `lock` as an INPUT — i.e.
    /// the commitment (or closing) transaction for a channel whose funding cell
    /// uses that lock. Uses the indexer `get_transactions`; returns the first
    /// input-side match.
    pub async fn find_spending_tx(&self, lock: &JsonScript) -> anyhow::Result<Option<SpendingTx>> {
        let search_key = json!({
            "script": lock,
            "script_type": "lock",
        });
        // order asc, limit small — the funding cell is spent at most once.
        let res = self
            .call("get_transactions", json!([search_key, "asc", "0x10"]))
            .await?;
        let objs = res.get("objects").and_then(|o| o.as_array()).cloned().unwrap_or_default();
        for o in objs {
            if o.get("io_type").and_then(|v| v.as_str()) == Some("input") {
                let tx_hash = o.get("tx_hash").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let block_number = o
                    .get("block_number")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                if !tx_hash.is_empty() {
                    return Ok(Some(SpendingTx { tx_hash, block_number }));
                }
            }
        }
        Ok(None)
    }

    /// Find a live cell locked by `lock` (indexer `get_cells`). Returns the
    /// out point + capacity of the first match — used to confirm a channel's
    /// funding cell exists and our lock derivation is correct.
    pub async fn find_live_cell(&self, lock: &JsonScript) -> anyhow::Result<Option<(String, u32, u64)>> {
        let search_key = json!({ "script": lock, "script_type": "lock" });
        let res = self.call("get_cells", json!([search_key, "asc", "0x10"])).await?;
        let objs = res.get("objects").and_then(|o| o.as_array()).cloned().unwrap_or_default();
        if let Some(o) = objs.first() {
            let op = o.get("out_point").cloned().unwrap_or_default();
            let tx_hash = op.get("tx_hash").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let index = op
                .get("index")
                .and_then(|v| v.as_str())
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let capacity = o
                .get("output")
                .and_then(|out| out.get("capacity"))
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            return Ok(Some((tx_hash, index, capacity)));
        }
        Ok(None)
    }

    /// Full transaction with status. Returns the raw JSON-RPC `TransactionWithStatus`.
    pub async fn get_transaction(&self, tx_hash: &str) -> anyhow::Result<Option<Value>> {
        let res = self.call("get_transaction", json!([tx_hash])).await?;
        if res.is_null() { Ok(None) } else { Ok(Some(res)) }
    }

    /// Live-cell status for an out point: "live" | "dead" | "unknown".
    pub async fn live_cell_status(&self, tx_hash: &str, index: u32) -> anyhow::Result<String> {
        let out_point = json!({ "tx_hash": tx_hash, "index": format!("0x{index:x}") });
        let res = self.call("get_live_cell", json!([out_point, false])).await?;
        Ok(res.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string())
    }

    /// Broadcast a signed transaction. Returns the tx hash on success.
    pub async fn send_transaction(&self, tx: Value) -> anyhow::Result<String> {
        let res = self.call("send_transaction", json!([tx, "passthrough"])).await?;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("send_transaction returned no hash: {res}"))
    }
}

/// A CKB script in JSON-RPC shape (for indexer search keys).
#[derive(Debug, Clone, serde::Serialize)]
pub struct JsonScript {
    pub code_hash: String,
    pub hash_type: String,
    pub args: String,
}
