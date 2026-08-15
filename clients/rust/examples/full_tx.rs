//! Subscribe to the full-tx tier and print decoded transactions.
//!
//!   PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' cargo run -p thornode-pulse --example full_tx

use thornode_pulse::{Filter, Frame};

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("PULSE_ADDR").expect("set PULSE_ADDR to host:port from dashboard");
    let token =
        std::env::var("PULSE_TOKEN").expect("set PULSE_TOKEN from the same dashboard location");
    let client = common::connect(&addr, Some(token)).await?;
    let account =
        std::env::var("PULSE_ACCOUNT").expect("set PULSE_ACCOUNT to an account or program pubkey");
    println!("connected to {addr}; subscribing full-tx…");

    // Pass &["alt"] instead of &[] to also receive each frame's ALT-loaded
    // addresses (FullSub::next still only ever hands back Frame::Tx — see its
    // doc comment for why heartbeats and unknown frame types never reach here).
    let mut sub = client
        .subscribe_full(&Filter::accounts([account]), &[])
        .await?;

    let mut n: u64 = 0;
    while let Some(Frame::Tx(v2)) = sub.next().await? {
        let tx = v2.tx;
        let sig = tx
            .signatures
            .first()
            .map(|s| bs58::encode(s).into_string())
            .unwrap_or_default();
        println!(
            "slot {:>12}  v0={}  sigs={} keys={} ix={} atl={}  {}",
            tx.slot,
            tx.versioned,
            tx.signatures.len(),
            tx.account_keys.len(),
            tx.instructions.len(),
            tx.address_table_lookups.len(),
            sig,
        );
        n += 1;
        if n >= 20 {
            break;
        }
    }
    println!("done ({n} txs); last heartbeat = {:?}", sub.heartbeat());
    Ok(())
}
