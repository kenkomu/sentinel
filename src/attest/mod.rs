//! Accountability layer — the part no watchtower on any payment-channel network
//! has shipped before.
//!
//! A watchtower asks you to trust that it is awake and watching. Normally you
//! cannot verify that; you find out it was asleep only when you get robbed.
//!
//! Sentinel removes the trust. Every `interval` seconds it signs a statement
//! binding the CURRENT chain tip to the set of channels it is guarding:
//!
//!     sign( ckb_tip_hash || ckb_tip_height || channel_count || timestamp )
//!
//! A tower that is asleep cannot produce this, because it does not know the
//! current tip. Any client — or any third party — can fetch the latest
//! attestation and check it against the real CKB chain. If the height is stale,
//! the tower is not watching, and the client can react before it is too late.
//!
//! At registration time the tower also issues a signed receipt, so a client
//! holds cryptographic proof that the tower accepted the job for a specific
//! channel from a specific block height.

use secp256k1::{Message, Secp256k1, SecretKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed proof-of-liveness. Published on an HTTP endpoint and verifiable by
/// anyone against the public CKB chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessAttestation {
    pub tower_pubkey: String,
    pub ckb_tip_hash: String,
    pub ckb_tip_height: u64,
    pub channels_watched: usize,
    pub timestamp: u64,
    /// secp256k1 signature over the canonical digest of the fields above.
    pub signature: String,
}

/// A signed acknowledgement that the tower took responsibility for a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReceipt {
    pub tower_pubkey: String,
    pub node_id: String,
    pub channel_id: String,
    pub since_ckb_height: u64,
    pub timestamp: u64,
    pub signature: String,
}

pub struct Attestor {
    secp: Secp256k1<secp256k1::All>,
    sk: SecretKey,
    pk: PublicKey,
}

impl Attestor {
    /// Load or generate the tower's long-lived identity key.
    pub fn new(sk: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        Self { secp, sk, pk }
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pk.serialize())
    }

    fn digest(parts: &[&[u8]]) -> Message {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let d = h.finalize();
        // secp256k1 messages are exactly 32 bytes; Sha256 gives us that.
        Message::from_digest_slice(&d).expect("sha256 is 32 bytes")
    }

    pub fn attest_liveness(
        &self,
        ckb_tip_hash: &str,
        ckb_tip_height: u64,
        channels_watched: usize,
        timestamp: u64,
    ) -> LivenessAttestation {
        let msg = Self::digest(&[
            ckb_tip_hash.as_bytes(),
            &ckb_tip_height.to_be_bytes(),
            &(channels_watched as u64).to_be_bytes(),
            &timestamp.to_be_bytes(),
        ]);
        let sig = self.secp.sign_ecdsa(&msg, &self.sk);
        LivenessAttestation {
            tower_pubkey: self.pubkey_hex(),
            ckb_tip_hash: ckb_tip_hash.to_string(),
            ckb_tip_height,
            channels_watched,
            timestamp,
            signature: hex::encode(sig.serialize_compact()),
        }
    }

    pub fn issue_receipt(
        &self,
        node_id: &str,
        channel_id: &str,
        since_ckb_height: u64,
        timestamp: u64,
    ) -> WatchReceipt {
        let msg = Self::digest(&[
            node_id.as_bytes(),
            channel_id.as_bytes(),
            &since_ckb_height.to_be_bytes(),
            &timestamp.to_be_bytes(),
        ]);
        let sig = self.secp.sign_ecdsa(&msg, &self.sk);
        WatchReceipt {
            tower_pubkey: self.pubkey_hex(),
            node_id: node_id.to_string(),
            channel_id: channel_id.to_string(),
            since_ckb_height,
            timestamp,
            signature: hex::encode(sig.serialize_compact()),
        }
    }
}

/// Verify a liveness attestation's signature against the public key it carries.
///
/// This proves the attestation was produced by the holder of the tower's key and
/// has not been tampered with. It does NOT prove freshness — the caller must
/// separately check `ckb_tip_height` against a real CKB node (a signature over a
/// stale tip is still a valid signature). That two-part check — signature here,
/// freshness against the chain — is what makes a sleeping tower detectable.
pub fn verify_liveness(att: &LivenessAttestation) -> Result<bool, String> {
    let secp = Secp256k1::verification_only();
    let pk_bytes = hex::decode(&att.tower_pubkey).map_err(|e| e.to_string())?;
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(&att.signature).map_err(|e| e.to_string())?;
    let sig = secp256k1::ecdsa::Signature::from_compact(&sig_bytes).map_err(|e| e.to_string())?;
    let msg = Attestor::digest(&[
        att.ckb_tip_hash.as_bytes(),
        &att.ckb_tip_height.to_be_bytes(),
        &(att.channels_watched as u64).to_be_bytes(),
        &att.timestamp.to_be_bytes(),
    ]);
    Ok(secp.verify_ecdsa(&msg, &sig, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand::rngs::OsRng;

    #[test]
    fn liveness_attestation_verifies() {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let attestor = Attestor::new(sk);

        let att = attestor.attest_liveness("0xdeadbeef", 12345, 3, 1_700_000_000);

        // Re-derive the digest exactly as a verifier would, and check the sig.
        let msg = Attestor::digest(&[
            att.ckb_tip_hash.as_bytes(),
            &att.ckb_tip_height.to_be_bytes(),
            &(att.channels_watched as u64).to_be_bytes(),
            &att.timestamp.to_be_bytes(),
        ]);
        let sig = secp256k1::ecdsa::Signature::from_compact(
            &hex::decode(&att.signature).unwrap(),
        )
        .unwrap();
        assert!(secp.verify_ecdsa(&msg, &sig, &pk).is_ok());
    }
}
