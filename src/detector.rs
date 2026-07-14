//! Breach detector — decides, per channel, whether an on-chain commitment is a
//! stale-state theft the tower must punish.
//!
//! The logic mirrors Fiber's own watchtower, kept as a pure decision function so
//! it is unit-testable without a chain:
//!
//!   1. Derive the channel's funding lock from its funding pubkeys.
//!   2. Ask the indexer which tx spent that funding cell (the commitment tx).
//!   3. From the commitment cell's lock args, read the broadcast
//!      `commitment_number` (bytes 28..36) and the committed pubkey hash (0..20).
//!   4. Verify the pubkey hash matches this channel (blake160 of the
//!      commitment-order aggregated pubkey), then compare numbers:
//!        held_revocation.commitment_number >= broadcast  ⇒  BREACH.
//!
//! A broadcast we hold a revocation for, at or below our latest revoked number,
//! is provably an old state — the counterparty is trying to roll back.

use crate::channel_id::{blake160, commitment_x_only_pubkey, funding_lock_args};
use crate::ckb::JsonScript;
use crate::domain::{parse_hex_bytes, CreateWatchChannel, RevocationData};

/// The verdict for one channel on one scan.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Funding cell still live — channel open, nothing to do.
    ChannelOpen,
    /// Commitment broadcast, but it is the latest state (or newer than anything
    /// we can punish) — a legitimate close, not a breach.
    LegitimateClose { broadcast_commitment: u64 },
    /// A stale state was broadcast and we hold the revocation to punish it.
    Breach {
        commitment_tx: String,
        commitment_index: u32,
        broadcast_commitment: u64,
        held_commitment: u64,
    },
    /// Commitment appeared but we cannot act (no revocation held, or the cell is
    /// not the commitment-lock we expected). Surfaced for alerting, not punished.
    Unactionable { reason: String },
}

/// The lock args layout of a commitment cell: pubkey hash then, at offset 28, the
/// commitment number as big-endian u64.
fn parse_commitment_lock_args(args: &[u8]) -> Option<([u8; 20], u64)> {
    if args.len() < 36 {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&args[0..20]);
    let num = u64::from_be_bytes(args[28..36].try_into().ok()?);
    Some((pkh, num))
}

/// Pure decision: given the channel registration, the latest revocation we hold
/// (if any), and the commitment cell's lock args + out point, return a verdict.
/// No chain access — fully unit-testable.
pub fn decide(
    channel: &CreateWatchChannel,
    latest_revocation: Option<&RevocationData>,
    commitment_tx: &str,
    commitment_index: u32,
    commitment_lock_args: &[u8],
) -> Verdict {
    let Some((committed_pkh, broadcast)) = parse_commitment_lock_args(commitment_lock_args) else {
        return Verdict::Unactionable { reason: "commitment lock args too short".into() };
    };

    // Confirm this commitment belongs to the channel we think it does.
    let (Some(local), Some(remote)) = (
        parse_hex_bytes(&channel.local_funding_pubkey),
        parse_hex_bytes(&channel.remote_funding_pubkey),
    ) else {
        return Verdict::Unactionable { reason: "unparseable funding pubkeys".into() };
    };
    let Some(agg) = commitment_x_only_pubkey(&local, &remote) else {
        return Verdict::Unactionable { reason: "musig2 aggregation failed".into() };
    };
    if blake160(&agg) != committed_pkh {
        // The committed key hash doesn't match either aggregation order — this is
        // the remote party's commitment (they force-closed on their own state) or
        // an unrelated cell. Not punishable by us; report for settlement/alerting.
        return Verdict::Unactionable {
            reason: "commitment pubkey hash does not match this channel's local aggregation".into(),
        };
    }

    match latest_revocation.and_then(|r| r.commitment_number_u64()) {
        Some(held) if held >= broadcast => Verdict::Breach {
            commitment_tx: commitment_tx.to_string(),
            commitment_index,
            broadcast_commitment: broadcast,
            held_commitment: held,
        },
        Some(_) => Verdict::LegitimateClose { broadcast_commitment: broadcast },
        None => Verdict::Unactionable {
            reason: "commitment broadcast but no revocation held for this channel".into(),
        },
    }
}

/// The funding lock JSON script for a channel, for indexer lookups.
pub fn funding_lock_script(
    channel: &CreateWatchChannel,
    code_hash: &str,
    hash_type: &str,
) -> Option<JsonScript> {
    let local = parse_hex_bytes(&channel.local_funding_pubkey)?;
    let remote = parse_hex_bytes(&channel.remote_funding_pubkey)?;
    let args = funding_lock_args(&local, &remote)?;
    Some(JsonScript {
        code_hash: code_hash.to_string(),
        hash_type: hash_type.to_string(),
        args: format!("0x{}", hex::encode(args)),
    })
}

/// Read the commitment cell's lock args from a `get_transaction` result:
/// output[0].lock.args of the spending tx.
pub fn commitment_lock_args_from_tx(tx_json: &serde_json::Value) -> Option<Vec<u8>> {
    let outputs = tx_json
        .get("transaction")?
        .get("outputs")
        .and_then(|o| o.as_array())?;
    let first = outputs.first()?;
    let args = first.get("lock")?.get("args")?.as_str()?;
    parse_hex_bytes(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> CreateWatchChannel {
        CreateWatchChannel {
            channel_id: "0x4b4c".into(),
            funding_udt_type_script: None,
            local_funding_pubkey: "0323c8ddf1f318c8ed183db274ceba24a69e2ad2d49cd4ce0dcb33796511769baa".into(),
            remote_funding_pubkey: "03bc6f43793df35125d01a7eafa7d56b0f06de741e10abf2b7701c9f2b70a1cac1".into(),
            local_settlement_key: "7c0d".into(),
            remote_settlement_key: "02c5".into(),
            settlement_data: Default::default(),
        }
    }

    fn revocation(n: u64) -> RevocationData {
        RevocationData {
            aggregated_signature: "0x59c1".into(),
            commitment_number: format!("0x{n:x}"),
            output: "0x6100".into(),
            output_data: "0x00000000".into(),
        }
    }

    // Build commitment lock args = pkh(20) || padding(8) || commitment_number BE(8).
    fn commitment_args(pkh: [u8; 20], num: u64) -> Vec<u8> {
        let mut a = pkh.to_vec();
        a.extend_from_slice(&[0u8; 8]);
        a.extend_from_slice(&num.to_be_bytes());
        a
    }

    fn our_pkh() -> [u8; 20] {
        let c = channel();
        let l = parse_hex_bytes(&c.local_funding_pubkey).unwrap();
        let r = parse_hex_bytes(&c.remote_funding_pubkey).unwrap();
        blake160(&commitment_x_only_pubkey(&l, &r).unwrap())
    }

    #[test]
    fn breach_when_old_state_broadcast() {
        // We hold revocation for state 5; attacker broadcasts state 2.
        let args = commitment_args(our_pkh(), 2);
        let v = decide(&channel(), Some(&revocation(5)), "0xtx", 0, &args);
        assert!(matches!(v, Verdict::Breach { broadcast_commitment: 2, held_commitment: 5, .. }));
    }

    #[test]
    fn legitimate_close_when_latest_state() {
        // Attacker broadcasts state 5; we only hold revocation up to 4 → not punishable.
        let args = commitment_args(our_pkh(), 5);
        let v = decide(&channel(), Some(&revocation(4)), "0xtx", 0, &args);
        assert_eq!(v, Verdict::LegitimateClose { broadcast_commitment: 5 });
    }

    #[test]
    fn unactionable_without_revocation() {
        let args = commitment_args(our_pkh(), 2);
        let v = decide(&channel(), None, "0xtx", 0, &args);
        assert!(matches!(v, Verdict::Unactionable { .. }));
    }

    #[test]
    fn unactionable_when_pubkey_hash_mismatch() {
        let args = commitment_args([0xab; 20], 2); // wrong pkh
        let v = decide(&channel(), Some(&revocation(5)), "0xtx", 0, &args);
        assert!(matches!(v, Verdict::Unactionable { .. }));
    }
}
