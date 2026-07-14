//! Persistent, multi-tenant storage for watched channels.
//!
//! Every record is namespaced by `node_id`, which is what makes one Sentinel
//! able to protect many independent Fiber nodes at once. Backed by `sled` (a
//! pure-Rust embedded KV store) so the tower is a single self-contained binary
//! with no external database to operate.

use crate::error::Result;
use crate::rpc::types::*;
use serde::{Deserialize, Serialize};

/// Everything the tower persists about one channel it is guarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedChannel {
    pub node_id: String,
    pub channel_id: String,
    pub create_params: CreateWatchChannelParams,
    /// Latest revocation data — the secret used to build the penalty tx.
    pub revocation: Option<UpdateRevocationParams>,
    pub local_settlement: Option<UpdateLocalSettlementParams>,
    pub pending_remote_settlement: Option<UpdatePendingRemoteSettlementParams>,
    /// Wall-clock unix seconds of the last update, for liveness accounting.
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct Store {
    db: sled::Db,
    channels: sled::Tree,
    preimages: sled::Tree,
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
        Ok(Self { db, channels, preimages })
    }

    pub fn insert_watch_channel(&self, node_id: &str, p: CreateWatchChannelParams) -> Result<()> {
        let wc = WatchedChannel {
            node_id: node_id.to_string(),
            channel_id: p.channel_id.clone(),
            create_params: p.clone(),
            revocation: None,
            local_settlement: None,
            pending_remote_settlement: None,
            updated_at: now(),
        };
        self.channels
            .insert(key(node_id, &p.channel_id), serde_json::to_vec(&wc)?)?;
        Ok(())
    }

    pub fn remove_watch_channel(&self, node_id: &str, channel_id: &str) -> Result<()> {
        self.channels.remove(key(node_id, channel_id))?;
        Ok(())
    }

    pub fn update_revocation(&self, node_id: &str, p: UpdateRevocationParams) -> Result<()> {
        self.mutate(node_id, &p.channel_id.clone(), |wc| {
            wc.revocation = Some(p);
        })
    }

    pub fn update_local_settlement(
        &self,
        node_id: &str,
        p: UpdateLocalSettlementParams,
    ) -> Result<()> {
        self.mutate(node_id, &p.channel_id.clone(), |wc| {
            wc.local_settlement = Some(p);
        })
    }

    pub fn update_pending_remote_settlement(
        &self,
        node_id: &str,
        p: UpdatePendingRemoteSettlementParams,
    ) -> Result<()> {
        self.mutate(node_id, &p.channel_id.clone(), |wc| {
            wc.pending_remote_settlement = Some(p);
        })
    }

    fn mutate<F: FnOnce(&mut WatchedChannel)>(
        &self,
        node_id: &str,
        channel_id: &str,
        f: F,
    ) -> Result<()> {
        let k = key(node_id, channel_id);
        if let Some(bytes) = self.channels.get(&k)? {
            let mut wc: WatchedChannel = serde_json::from_slice(&bytes)?;
            f(&mut wc);
            wc.updated_at = now();
            self.channels.insert(k, serde_json::to_vec(&wc)?)?;
        }
        Ok(())
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

    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}
