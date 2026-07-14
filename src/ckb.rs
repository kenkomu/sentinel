//! Minimal CKB JSON-RPC client — just enough to read the chain tip.
//!
//! The tip (hash + height) is the freshness anchor for liveness attestations:
//! a tower that is not actually following the chain cannot report the current
//! tip, so binding attestations to it is what makes "is my tower awake?"
//! objectively checkable.

use serde_json::json;

#[derive(Debug, Clone)]
pub struct Tip {
    pub hash: String,
    pub number: u64,
}

#[derive(Clone)]
pub struct CkbClient {
    url: String,
    http: reqwest::Client,
}

impl CkbClient {
    pub fn new(url: String) -> Self {
        Self { url, http: reqwest::Client::new() }
    }

    /// `get_tip_header` → (hash, number). Returns None if the node is
    /// unreachable or the response is unexpected, so callers can treat an
    /// unreachable CKB node as "cannot currently attest" rather than crashing.
    pub async fn tip(&self) -> Option<Tip> {
        let body = json!({
            "id": 1, "jsonrpc": "2.0",
            "method": "get_tip_header", "params": []
        });
        let resp = self.http.post(&self.url).json(&body).send().await.ok()?;
        let v: serde_json::Value = resp.json().await.ok()?;
        let header = v.get("result")?;
        let hash = header.get("hash")?.as_str()?.to_string();
        let number_hex = header.get("number")?.as_str()?;
        let number = u64::from_str_radix(number_hex.trim_start_matches("0x"), 16).ok()?;
        Some(Tip { hash, number })
    }
}
