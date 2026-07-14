//! Chain watcher — the loop that turns stored revocation data into a defense.
//!
//! Responsibilities (built out across Stages 2–3):
//!   1. Poll the CKB chain tip (via a CKB RPC node).
//!   2. For every watched channel, check whether the channel's funding cell has
//!      been spent by a commitment transaction.
//!   3. If a commitment appears whose state is OLDER than the latest revocation
//!      we hold, that is a breach: build and broadcast the penalty transaction
//!      that sweeps the entire channel balance to the honest party.
//!
//! The penalty-construction primitives live in Fiber's (unlicensed) `fiber-lib`.
//! To stay MIT-clean we do not vendor that source; the penalty path links
//! `fiber-lib` as an external dependency or drives the node's own force-close
//! settlement. Stage 1 nails down exactly which, against captured wire data.

use crate::store::Store;

pub struct ChainWatcher {
    pub store: Store,
    pub ckb_rpc_url: String,
}

impl ChainWatcher {
    pub fn new(store: Store, ckb_rpc_url: String) -> Self {
        Self { store, ckb_rpc_url }
    }

    /// Placeholder for the periodic scan. Returns the current watched-channel
    /// count so the caller can log progress until real chain polling lands.
    pub fn scan_once(&self) -> usize {
        self.store.channel_count()
    }
}
