//! Channel on-chain identity — deriving the scripts that let the tower find a
//! channel's commitment cell on CKB.
//!
//! A Fiber channel is funded into a cell locked by the **funding lock**, whose
//! args are `blake160(x_only_aggregated_pubkey(local, remote))` — the musig2
//! aggregate of the two funding pubkeys. When a party force-closes, that funding
//! cell is spent by a **commitment** transaction. So to watch a channel we:
//!   1. aggregate the funding pubkeys (musig2, exactly as Fiber does),
//!   2. build the funding lock script, and
//!   3. ask the indexer which tx spent a cell with that lock.
//!
//! The aggregation must match Fiber byte-for-byte or we would compute the wrong
//! lock and never find the breach; this is validated against captured data.

use ckb_hash::blake2b_256;
use musig2::secp::Point;
use musig2::KeyAggContext;

/// blake160 = first 20 bytes of blake2b-256 (CKB's short hash).
pub fn blake160(data: &[u8]) -> [u8; 20] {
    let h = blake2b_256(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

/// Compute the x-only musig2-aggregated pubkey of the two funding pubkeys.
///
/// Fiber sorts the two keys before aggregation for the funding lock; pass the
/// keys already in the order the caller needs. Returns the 32-byte x-only key.
pub fn x_only_aggregated_pubkey(pubkeys: &[Vec<u8>]) -> Option<[u8; 32]> {
    let ctx = KeyAggContext::new(
        pubkeys
            .iter()
            .map(|pk| musig2::secp256k1::PublicKey::from_slice(pk).ok())
            .collect::<Option<Vec<_>>>()?,
    )
    .ok()?;
    Some(ctx.aggregated_pubkey::<Point>().serialize_xonly())
}

/// The funding lock args for a channel: `blake160(x_only_agg_pubkey)` over the
/// two funding pubkeys sorted ascending (Fiber's convention for the funding lock).
pub fn funding_lock_args(local_funding_pubkey: &[u8], remote_funding_pubkey: &[u8]) -> Option<[u8; 20]> {
    let mut keys = [local_funding_pubkey.to_vec(), remote_funding_pubkey.to_vec()];
    keys.sort();
    let agg = x_only_aggregated_pubkey(&keys)?;
    Some(blake160(&agg))
}

/// The x-only aggregated pubkey used in the commitment lock / penalty witness.
/// Fiber orders `[local, remote]` (not sorted) for this one.
pub fn commitment_x_only_pubkey(local_funding_pubkey: &[u8], remote_funding_pubkey: &[u8]) -> Option<[u8; 32]> {
    x_only_aggregated_pubkey(&[local_funding_pubkey.to_vec(), remote_funding_pubkey.to_vec()])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real funding pubkeys from a live devnet channel (captured create_watch_channel).
    const LOCAL: &str = "0323c8ddf1f318c8ed183db274ceba24a69e2ad2d49cd4ce0dcb33796511769baa";
    const REMOTE: &str = "03bc6f43793df35125d01a7eafa7d56b0f06de741e10abf2b7701c9f2b70a1cac1";

    #[test]
    fn aggregation_is_deterministic_and_sort_invariant() {
        let l = hex::decode(LOCAL).unwrap();
        let r = hex::decode(REMOTE).unwrap();
        // funding lock sorts the keys, so arg order must not matter.
        let a = funding_lock_args(&l, &r).expect("aggregate");
        let b = funding_lock_args(&r, &l).expect("aggregate");
        assert_eq!(a, b, "funding lock must be independent of caller key order");
        assert_eq!(a.len(), 20);
    }

    #[test]
    fn commitment_key_is_order_sensitive() {
        let l = hex::decode(LOCAL).unwrap();
        let r = hex::decode(REMOTE).unwrap();
        // commitment/penalty key uses [local, remote] order specifically.
        let lr = commitment_x_only_pubkey(&l, &r).unwrap();
        let rl = commitment_x_only_pubkey(&r, &l).unwrap();
        assert_ne!(lr, rl, "commitment key aggregation is order-sensitive");
        assert_eq!(lr.len(), 32);
    }
}
