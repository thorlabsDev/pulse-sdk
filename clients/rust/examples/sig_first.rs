//! Subscribe to the sig-first tier and print `(slot, signature)` as they arrive.
//!
//!   PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' cargo run -p thornode-pulse --example sig_first

use thornode_pulse::Filter;

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("PULSE_ADDR").expect("set PULSE_ADDR to host:port from dashboard");
    let token =
        std::env::var("PULSE_TOKEN").expect("set PULSE_TOKEN from the same dashboard location");
    let client = common::connect(&addr, Some(token)).await?;
    let account =
        std::env::var("PULSE_ACCOUNT").expect("set PULSE_ACCOUNT to an account or program pubkey");
    println!("connected to {addr}; subscribing sig-first…");

    let mut sub = client
        .subscribe_sig_first(&Filter::accounts([account]))
        .await?;

    let mut n: u64 = 0;
    while let Some(item) = sub.next().await? {
        println!(
            "slot {:>12}  seq={}  {}",
            item.slot,
            item.seq,
            bs58::encode(item.signature).into_string()
        );
        n += 1;
        if n >= 20 {
            break;
        }
    }
    println!(
        "done ({n} txs); dropped={} gaps={}",
        sub.dropped(),
        sub.gaps()
    );
    Ok(())
}
