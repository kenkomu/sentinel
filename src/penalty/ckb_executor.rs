//! The real penalty executor: assembles, signs, and broadcasts the transaction
//! that sweeps a revoked commitment.
//!
//! Transaction shape (mirrors Fiber's `build_revocation_tx`):
//!   inputs:  [ revoked commitment cell, fee-provider cell ]
//!   outputs: [ penalty output (pre-computed by the node), change ]
//!   witness: [ revocation witness (no key needed), secp sighash sig ]
//!   deps:    [ commitment-lock dep, secp256k1 dep ]
//!
//! The commitment input needs no signature from us — the revocation witness
//! carries the aggregated signature the node already provided. We sign only the
//! fee-provider input, using CKB's secp256k1-blake160 sighash-all.

use super::witness::build_revocation_witness;
use super::{BreachContext, PenaltyExecutor, PenaltyOutcome};
use crate::ckb::{CkbClient, JsonScript};
use crate::config::PenaltyConfig;
use async_trait::async_trait;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{
        CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
    },
    prelude::*,
    H256,
};
use secp256k1::{Message, Secp256k1, SecretKey};

/// secp256k1-blake160 sighash-all system script code hash (same on every CKB
/// network — it is a genesis system script).
const SIGHASH_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

pub struct CkbPenaltyExecutor {
    ckb: CkbClient,
    cfg: PenaltyConfig,
    secp: Secp256k1<secp256k1::All>,
    signer_key: SecretKey,
    signer_lock: Script,
}

impl CkbPenaltyExecutor {
    pub fn new(ckb: CkbClient, cfg: PenaltyConfig) -> anyhow::Result<Self> {
        let secp = Secp256k1::new();
        let key_bytes = hex::decode(cfg.fee_signer_key.trim_start_matches("0x"))?;
        let signer_key = SecretKey::from_slice(&key_bytes)?;
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &signer_key);
        let pubkey_hash = blake160(&pubkey.serialize());

        let signer_lock = Script::new_builder()
            .code_hash(H256(SIGHASH_CODE_HASH).pack())
            .hash_type(ckb_types::packed::Byte::new(ScriptHashType::Type as u8))
            .args(Bytes::from(pubkey_hash.to_vec()).pack())
            .build();

        Ok(Self { ckb, cfg, secp, signer_key, signer_lock })
    }

    fn signer_lock_json(&self) -> JsonScript {
        JsonScript {
            code_hash: format!("0x{}", hex::encode(SIGHASH_CODE_HASH)),
            hash_type: "type".into(),
            args: format!("0x{}", hex::encode(&self.signer_lock.args().raw_data())),
        }
    }

    fn cell_dep(spec: &crate::config::CellDep) -> anyhow::Result<CellDep> {
        let tx_hash = H256::from_trimmed_str(spec.tx_hash.trim_start_matches("0x"))?;
        let dep_type = if spec.dep_type == "dep_group" {
            DepType::DepGroup
        } else {
            DepType::Code
        };
        Ok(CellDep::new_builder()
            .out_point(OutPoint::new(tx_hash.pack(), spec.index))
            .dep_type(ckb_types::packed::Byte::new(dep_type as u8))
            .build())
    }

    /// Assemble the fully-signed penalty transaction.
    async fn build(&self, ctx: &BreachContext) -> anyhow::Result<TransactionView> {
        // 1. Penalty output + data (pre-computed by the node).
        let output_bytes = crate::domain::parse_hex_bytes(&ctx.revocation.output)
            .ok_or_else(|| anyhow::anyhow!("bad penalty output hex"))?;
        let penalty_output = CellOutput::from_slice(&output_bytes)
            .map_err(|e| anyhow::anyhow!("penalty output not a CellOutput: {e}"))?;
        let output_data = crate::domain::parse_hex_bytes(&ctx.revocation.output_data)
            .unwrap_or_default();

        // 2. Revocation witness unlocks the commitment cell (no key needed).
        let revocation_witness = build_revocation_witness(&ctx.revocation, &ctx.x_only_aggregated_pubkey)
            .ok_or_else(|| anyhow::anyhow!("could not build revocation witness"))?;

        // 3. Fee-provider input: one live cell under the signer's lock.
        let (fee_tx, fee_idx, fee_capacity) = self
            .ckb
            .find_live_cell(&self.signer_lock_json())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no fee-provider cell for signer lock; fund the tower key"))?;
        let fee_out_point = OutPoint::new(
            H256::from_trimmed_str(fee_tx.trim_start_matches("0x"))?.pack(),
            fee_idx,
        );

        let commitment_out_point = OutPoint::new(
            H256::from_trimmed_str(ctx.commitment_tx_hash.trim_start_matches("0x"))?.pack(),
            ctx.commitment_index,
        );

        // 4. Change output back to the signer.
        let change_output = CellOutput::new_builder()
            .lock(self.signer_lock.clone())
            .build();
        let change_min = change_output
            .occupied_capacity(Capacity::zero())
            .map_err(|e| anyhow::anyhow!("capacity overflow: {e}"))?
            .as_u64();

        // Rough fee (bytes * rate). Fee cell must cover fee + change min capacity.
        let est_fee = 1_000u64.max(self.cfg.fee_rate_per_kb);
        let change_capacity = fee_capacity
            .checked_sub(est_fee)
            .ok_or_else(|| anyhow::anyhow!("fee cell {fee_capacity} too small for fee {est_fee}"))?;
        if change_capacity < change_min {
            anyhow::bail!("fee cell cannot cover change min capacity");
        }
        let change_output = change_output
            .as_builder()
            .capacity(Capacity::shannons(change_capacity).pack())
            .build();

        // 5. Placeholder secp witness (65 zero bytes) for the fee input signature.
        let placeholder = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();

        let tx = TransactionBuilder::default()
            .cell_dep(Self::cell_dep(&self.cfg.commitment_lock_dep)?)
            .cell_dep(Self::cell_dep(&self.cfg.secp256k1_lock_dep)?)
            .input(CellInput::new(commitment_out_point, 0))
            .input(CellInput::new(fee_out_point, 0))
            .output(penalty_output)
            .output_data(Bytes::from(output_data).pack())
            .output(change_output)
            .output_data(Bytes::new().pack())
            .witness(Bytes::from(revocation_witness).pack())
            .witness(placeholder.as_bytes().pack())
            .build();

        // 6. Sign the fee input (group index 1) with sighash-all.
        let signed = self.sign_fee_input(tx)?;
        Ok(signed)
    }

    /// CKB secp256k1-blake160 sighash-all over the fee-input witness group.
    /// The fee input is the second input; its witness group is signed alone.
    fn sign_fee_input(&self, tx: TransactionView) -> anyhow::Result<TransactionView> {
        let tx_hash = tx.hash();
        let witnesses: Vec<Bytes> = tx.witnesses().into_iter().map(|w| w.unpack()).collect();

        // Signing message: blake2b( tx_hash ‖ len(w1)‖w1 ‖ len(other)‖other... )
        // for the fee group, whose first witness is index 1.
        let mut hasher = new_blake2b();
        hasher.update(tx_hash.as_slice());

        let fee_witness = witnesses
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing fee witness"))?;
        let len_bytes = (fee_witness.len() as u64).to_le_bytes();
        hasher.update(&len_bytes);
        hasher.update(&fee_witness);

        let mut message = [0u8; 32];
        hasher.finalize(&mut message);

        let sig = self
            .secp
            .sign_ecdsa_recoverable(&Message::from_digest(message), &self.signer_key);
        let (rec_id, sig_bytes) = sig.serialize_compact();
        let mut sig65 = sig_bytes.to_vec();
        sig65.push(rec_id.to_i32() as u8);

        let signed_fee_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(sig65)).pack())
            .build();

        let mut new_witnesses = witnesses;
        new_witnesses[1] = signed_fee_witness.as_bytes();

        Ok(tx
            .as_advanced_builder()
            .set_witnesses(new_witnesses.into_iter().map(|w| w.pack()).collect())
            .build())
    }

    fn tx_to_json(tx: &TransactionView) -> serde_json::Value {
        let json: ckb_jsonrpc_types::Transaction = tx.data().into();
        serde_json::to_value(json).unwrap_or(serde_json::Value::Null)
    }
}

fn blake160(data: &[u8]) -> [u8; 20] {
    let h = blake2b_256(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

#[async_trait]
impl PenaltyExecutor for CkbPenaltyExecutor {
    async fn punish(&self, ctx: &BreachContext) -> PenaltyOutcome {
        // Idempotency: only act if the commitment cell is still live.
        match self
            .ckb
            .live_cell_status(&ctx.commitment_tx_hash, ctx.commitment_index)
            .await
        {
            Ok(s) if s != "live" => return PenaltyOutcome::AlreadyResolved,
            Ok(_) => {}
            Err(e) => return PenaltyOutcome::Failed(format!("live-cell check failed: {e}")),
        }

        let tx = match self.build(ctx).await {
            Ok(tx) => tx,
            Err(e) => return PenaltyOutcome::Failed(format!("assemble penalty: {e}")),
        };

        match self.ckb.send_transaction(Self::tx_to_json(&tx)).await {
            Ok(hash) => PenaltyOutcome::Broadcast(hash),
            Err(e) => PenaltyOutcome::Failed(format!("broadcast penalty: {e}")),
        }
    }
}
