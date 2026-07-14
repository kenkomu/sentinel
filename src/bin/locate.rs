//! `locate` — an operator/diagnostic tool that resolves a channel's on-chain
//! footprint from its funding pubkeys: derives the funding lock, then reports
//! whether the funding cell is still live or has been spent (force-closed).
//!
//! It doubles as the validation harness for Sentinel's lock derivation: if
//! `locate` finds the real funding cell on a live network, the musig2
//! aggregation and lock construction are correct end-to-end.
//!
//! Usage:
//!   locate --ckb http://127.0.0.1:8114 \
//!          --local <funding_pubkey> --remote <funding_pubkey> \
//!          --funding-code-hash 0x9bd7... --hash-type type

use clap::Parser;
use sentinel::channel_id::funding_lock_args;
use sentinel::ckb::{CkbClient, JsonScript};

#[derive(Parser, Debug)]
#[command(name = "locate", about = "Locate a Fiber channel's on-chain funding cell")]
struct Args {
    #[arg(long)]
    ckb: String,
    #[arg(long)]
    local: String,
    #[arg(long)]
    remote: String,
    #[arg(long)]
    funding_code_hash: String,
    #[arg(long, default_value = "type")]
    hash_type: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let local = hex::decode(args.local.trim_start_matches("0x")).expect("local hex");
    let remote = hex::decode(args.remote.trim_start_matches("0x")).expect("remote hex");

    let fargs = funding_lock_args(&local, &remote).expect("aggregate funding pubkeys");
    let lock = JsonScript {
        code_hash: args.funding_code_hash.clone(),
        hash_type: args.hash_type.clone(),
        args: format!("0x{}", hex::encode(fargs)),
    };
    println!("derived funding lock:");
    println!("  code_hash: {}", lock.code_hash);
    println!("  hash_type: {}", lock.hash_type);
    println!("  args:      {}", lock.args);

    let ckb = CkbClient::new(args.ckb);

    match ckb.find_live_cell(&lock).await {
        Ok(Some((tx, idx, cap))) => {
            println!("\n✅ funding cell LIVE — channel open");
            println!("   out_point: {tx}:{idx}");
            println!("   capacity:  {} CKB", cap / 100_000_000);
            println!("\n   → lock derivation is correct (found the real funding cell).");
        }
        Ok(None) => match ckb.find_spending_tx(&lock).await {
            Ok(Some(sp)) => {
                println!("\n⚠  funding cell SPENT — channel force-closed");
                println!("   commitment tx: {} (block {})", sp.tx_hash, sp.block_number);
                println!("\n   → this is the tx a watchtower inspects for a stale-state breach.");
            }
            Ok(None) => println!("\n❌ no live cell and no spending tx found for this lock."),
            Err(e) => eprintln!("error searching spends: {e}"),
        },
        Err(e) => eprintln!("error searching cells: {e}"),
    }
}
