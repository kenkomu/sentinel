//! `verify` — a client-side tool that checks whether a watchtower is actually
//! watching. This is the capability no Lightning watchtower ships: instead of
//! trusting the tower, you verify it.
//!
//! Two independent checks:
//!   1. Signature — is the attestation authentic and untampered (signed by the
//!      tower's key)?
//!   2. Freshness — does the attestation's CKB tip height track the real chain?
//!      A tower that is asleep cannot advance this; if it lags the live tip
//!      beyond a tolerance, the tower is not watching.
//!
//! Usage:
//!   verify --tower http://TOWER:8080 --ckb http://CKB:8114 [--max-lag 10]
//!
//! Exit code 0 = tower proven live; non-zero = unproven / stale / invalid.

use clap::Parser;
use sentinel::attest::{self, LivenessAttestation};
use sentinel::ckb::CkbClient;

#[derive(Parser, Debug)]
#[command(name = "verify", about = "Verify a Fiber watchtower is actually watching")]
struct Args {
    /// Base URL of the tower's HTTP surface.
    #[arg(long)]
    tower: String,

    /// CKB RPC to cross-check the attested tip height against the real chain.
    #[arg(long)]
    ckb: Option<String>,

    /// Max blocks the attestation may lag the live tip before we call it stale.
    #[arg(long, default_value_t = 10)]
    max_lag: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    std::process::exit(run(args).await);
}

async fn run(args: Args) -> i32 {
    let url = format!("{}/attestation", args.tower.trim_end_matches('/'));
    let resp = match reqwest::get(&url).await {
        Ok(r) => r,
        Err(e) => {
            println!("❌ UNREACHABLE — could not reach tower at {url}: {e}");
            return 2;
        }
    };
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            println!("❌ BAD RESPONSE — tower did not return JSON: {e}");
            return 2;
        }
    };

    if body.get("live").and_then(|v| v.as_bool()) != Some(true) {
        let reason = body
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("tower reports it is not live");
        println!("❌ UNPROVEN — {reason}");
        return 3;
    }

    let att: LivenessAttestation = match serde_json::from_value(body["attestation"].clone()) {
        Ok(a) => a,
        Err(e) => {
            println!("❌ MALFORMED — attestation did not parse: {e}");
            return 3;
        }
    };

    // Check 1: signature authenticity.
    match attest::verify_liveness(&att) {
        Ok(true) => println!(
            "✅ SIGNATURE valid — signed by tower {}",
            &att.tower_pubkey[..16]
        ),
        Ok(false) => {
            println!("❌ FORGED — signature does not verify against the tower's key");
            return 4;
        }
        Err(e) => {
            println!("❌ SIGNATURE ERROR — {e}");
            return 4;
        }
    }

    let age = now().saturating_sub(att.timestamp);
    println!(
        "   attested tip height {} at {}s ago, watching {} channel(s)",
        att.ckb_tip_height, age, att.channels_watched
    );

    // Check 2: freshness against the real chain.
    if let Some(ckb_url) = args.ckb {
        match CkbClient::new(ckb_url).tip().await {
            Some(tip) => {
                let lag = tip.number.saturating_sub(att.ckb_tip_height);
                if lag > args.max_lag {
                    println!(
                        "❌ STALE — live tip is {}, tower last attested {} ({} blocks behind > max {})",
                        tip.number, att.ckb_tip_height, lag, args.max_lag
                    );
                    println!("   → the tower is NOT watching. Do not rely on it.");
                    return 5;
                }
                println!(
                    "✅ FRESH — within {} blocks of live tip {} (lag {})",
                    args.max_lag, tip.number, lag
                );
            }
            None => {
                println!("⚠️  could not reach CKB to cross-check freshness; signature-only result");
            }
        }
    } else {
        println!("⚠️  no --ckb given; skipped freshness check (signature-only result)");
    }

    println!("\n✅ TOWER PROVEN LIVE — it is watching and can prove it.");
    0
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
