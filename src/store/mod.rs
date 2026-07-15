//! Persistent, multi-tenant storage for watched channels.
//!
//! Every record is namespaced by `node_id`, which is what makes one Sentinel
//! able to protect many independent Fiber nodes at once. Backed by `sled` (a
//! pure-Rust embedded KV store) so the tower is a single self-contained binary
//! with no external database to operate.
//!
//! Stage 1 stores each channel's incoming payloads as raw JSON "parts"
//! (registration, latest revocation, settlement data). Once the wire format is
//! captured and locked, typed accessors are layered on top without changing the
//! on-disk shape.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Everything the tower persists about one channel it is guarding. `parts` holds
/// the raw params of each method the node called for this channel, keyed by a
/// short part name: "create", "revocation", "local_settlement",
/// "pending_remote_settlement".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedChannel {
    pub node_id: String,
    pub channel_id: String,
    pub parts: BTreeMap<String, serde_json::Value>,
    /// Wall-clock unix seconds of the last update, for liveness accounting.
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct Store {
    db: sled::Db,
    channels: sled::Tree,
    preimages: sled::Tree,
    receipts: sled::Tree,
    /// Per-commitment revocation data, keyed by node:channel:commitment_number.
    /// The revocation signature binds to a specific commitment's args, so to
    /// punish a broadcast of commitment N we need the revocation for exactly N,
    /// not merely the latest one.
    revocations: sled::Tree,
}

fn key(node_id: &str, channel_id: &str) -> Vec<u8> {
    format!("{node_id}:{channel_id}").into_bytes()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        let channels = db.open_tree("channels")?;
        let preimages = db.open_tree("preimages")?;
        let receipts = db.open_tree("receipts")?;
        let revocations = db.open_tree("revocations")?;
        Ok(Self { db, channels, preimages, receipts, revocations })
    }

    /// Store a raw params payload under a named part for a channel, merging into
    /// the existing record so one channel keeps its full picture in one row.
    pub fn insert_raw(
        &self,
        node_id: &str,
        channel_id: &str,
        part: &str,
        raw: serde_json::Value,
    ) -> Result<()> {
        let k = key(node_id, channel_id);
        let mut wc: WatchedChannel = match self.channels.get(&k)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => WatchedChannel {
                node_id: node_id.to_string(),
                channel_id: channel_id.to_string(),
                parts: BTreeMap::new(),
                updated_at: 0,
            },
        };
        wc.parts.insert(part.to_string(), raw);
        wc.updated_at = now();
        self.channels.insert(k, serde_json::to_vec(&wc)?)?;
        Ok(())
    }

    pub fn remove_channel(&self, node_id: &str, channel_id: &str) -> Result<()> {
        self.channels.remove(key(node_id, channel_id))?;
        Ok(())
    }

    /// Persist a revocation keyed by its commitment number, so any specific old
    /// commitment can later be punished with the exact matching revocation.
    pub fn insert_revocation(
        &self,
        node_id: &str,
        channel_id: &str,
        commitment_number: u64,
        revocation: &crate::domain::RevocationData,
    ) -> Result<()> {
        let k = format!("{node_id}:{channel_id}:{commitment_number}").into_bytes();
        self.revocations.insert(k, serde_json::to_vec(revocation)?)?;
        Ok(())
    }

    /// The revocation for a specific commitment number, if held.
    pub fn get_revocation_for(
        &self,
        node_id: &str,
        channel_id: &str,
        commitment_number: u64,
    ) -> Result<Option<crate::domain::RevocationData>> {
        let k = format!("{node_id}:{channel_id}:{commitment_number}").into_bytes();
        match self.revocations.get(&k)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn insert_preimage(&self, node_id: &str, payment_hash: &str, preimage: &str) -> Result<()> {
        self.preimages
            .insert(key(node_id, payment_hash), preimage.as_bytes())?;
        Ok(())
    }

    pub fn remove_preimage(&self, node_id: &str, payment_hash: &str) -> Result<()> {
        self.preimages.remove(key(node_id, payment_hash))?;
        Ok(())
    }

    pub fn insert_receipt(
        &self,
        node_id: &str,
        channel_id: &str,
        receipt: &crate::attest::WatchReceipt,
    ) -> Result<()> {
        self.receipts
            .insert(key(node_id, channel_id), serde_json::to_vec(receipt)?)?;
        Ok(())
    }

    pub fn all_receipts(&self) -> Result<Vec<crate::attest::WatchReceipt>> {
        let mut out = Vec::new();
        for item in self.receipts.iter() {
            let (_, v) = item?;
            out.push(serde_json::from_slice(&v)?);
        }
        Ok(out)
    }

    /// Typed view of a watched channel's registration + latest revocation,
    /// parsed from the stored raw parts. Returns `None` if the channel has no
    /// usable `create` part yet.
    pub fn typed(
        &self,
        wc: &WatchedChannel,
    ) -> Option<(crate::domain::CreateWatchChannel, Option<crate::domain::RevocationData>)> {
        let create: crate::domain::CreateWatchChannel =
            crate::domain::from_positional(wc.parts.get("create")?)?;
        let revocation = wc
            .parts
            .get("revocation")
            .and_then(|raw| crate::domain::from_positional::<crate::domain::UpdateRevocation>(raw))
            .map(|u| u.revocation_data);
        Some((create, revocation))
    }

    /// All channels currently under watch — used by the chain watcher's periodic
    /// scan and by the dashboard.
    pub fn all_channels(&self) -> Result<Vec<WatchedChannel>> {
        let mut out = Vec::new();
        for item in self.channels.iter() {
            let (_, v) = item?;
            out.push(serde_json::from_slice(&v)?);
        }
        Ok(out)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Number of distinct nodes (tenants) with at least one watched channel.
    pub fn tenant_count(&self) -> usize {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for item in self.channels.iter().flatten() {
            if let Ok(wc) = serde_json::from_slice::<WatchedChannel>(&item.1) {
                set.insert(wc.node_id);
            }
        }
        set.len()
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}
