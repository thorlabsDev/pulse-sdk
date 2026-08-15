# thornode-pulse (Rust)

Rust client SDK for the **pulse** QUIC decoded-shred transaction stream.

> **Upgrading a v1 client?** See
> [the v1-to-v2 migration guide](https://github.com/thorlabsDev/pulse-sdk/blob/main/docs/MIGRATION-v1-to-v2.md)
> for the change list, and [the protocol specification](https://github.com/thorlabsDev/pulse-sdk/blob/main/docs/PROTOCOL.md)
> for the normative wire contract.

Add the SDK and the dependencies used by this example:

```sh
cargo add thornode-pulse
cargo add tokio --features rt-multi-thread,macros
cargo add bs58
```

Inside a source checkout, Cargo also supports
`thornode-pulse = { path = "clients/rust" }`.

The SDK depends on `thornode-pulse-wire` (the zero-dependency wire codec) and
nothing else from the server — not the shred decoder, FEC, or filtering.

## Sig-first tier (lowest latency)

One QUIC DATAGRAM per tx: a [`SigFirstItem`] (`slot`, per-subscriber `seq`,
`signature`), fire-and-forget, no head-of-line blocking. Use it when you just
need early observed signatures. Sig-first can drop, reorder, or duplicate
transactions; it makes no landed, lossless, or at-least-once promise.
`SigFirstSub::gaps()` is a **provisional** loss indicator
(item-to-item `seq` gaps plus trailing loss revealed by a heartbeat). It can
over-report under reordering, since QUIC datagrams are unordered by
definition — read a non-zero count as "loss happened, or reordering did", and
see the method's doc comment for the exact guarantee.

```rust
use thornode_pulse::{PulseClient, Filter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = PulseClient::connect_with_token(
        "<HOST:PORT_FROM_DASHBOARD>",
        "<TOKEN_FROM_SAME_LOCATION>",
    ).await?;
    let mut sub = client.subscribe_sig_first(&Filter::accounts([
        "<ACCOUNT_OR_PROGRAM_PUBKEY>",
    ])).await?;
    while let Some(item) = sub.next().await? {
        println!("slot {} seq {} {}", item.slot, item.seq, bs58::encode(item.signature).into_string());
    }
    Ok(())
}
```

## Full-tx tier (fully decoded)

An ordered QUIC stream of fully-decoded transactions (slot, signatures, account
keys, instructions, address-table lookups). Frames are transport-reliable only
after the server enqueues them; its bounded queue can shed before that point.
This is not an end-to-end lossless, at-least-once, landed, or completeness
guarantee. The stream opens with a 6-byte
preamble this SDK reads and verifies before `subscribe_full` ever returns —
a mismatch fails loudly (`Error::BadPreamble`), not silently.

```rust
use thornode_pulse::{Filter, Frame, PulseClient};

let client = PulseClient::connect_with_token(
    "<HOST:PORT_FROM_DASHBOARD>",
    "<TOKEN_FROM_SAME_LOCATION>",
).await?;
let mut sub = client.subscribe_full(
    &Filter::accounts(["<ACCOUNT_OR_PROGRAM_PUBKEY>"]),
    &[],
).await?;
while let Some(Frame::Tx(v2)) = sub.next().await? {
    let tx = v2.tx;
    println!("slot {} sigs={} ix={}", tx.slot, tx.signatures.len(), tx.instructions.len());
}
```

Pass `&["alt"]` instead of `&[]` to also receive each frame's ALT-loaded
addresses (`v2.loaded_writable` / `v2.loaded_readonly`). `sub.heartbeat()`
returns the most recent `(server_ts_ms, highest_seq)` observed on the stream —
heartbeats and any message type this SDK doesn't recognize are filtered out of
`next()` itself, never returned as an item and never an error.

## Filters

`Filter::all()` requests the unfiltered non-vote feed; the access selected for
the connection determines whether that feed is available.
`Filter::accounts([pubkey, …])` applies an account or program filter. The full
predicate model (`account_include` / `account_exclude` / `account_required`) is
on [`Filter`]. Sig-first uses `sub.update_filter(&f).await?`; full-tx uses
`sub.update_filter(&f, &["alt"]).await?` when changing its filter and
enrichment list. Both return the server's parsed `Ack`.

## Derived fields

`thornode_pulse::{fee_payer, program_ids, static_writable_accounts,
compute_unit_price, compute_unit_limit}` compute fields from a decoded
transaction that are deliberately not on the wire (re-exported from
`thornode_pulse_wire`).

## Examples

```sh
PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' cargo run -p thornode-pulse --example sig_first
PULSE_ADDR='<HOST:PORT_FROM_DASHBOARD>' PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>' PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>' cargo run -p thornode-pulse --example full_tx
```

For an explicitly local self-signed server, also set
`PULSE_INSECURE_LOCAL_DEV=1`; the SDK rejects that mode for non-loopback
addresses.

`ssh -L` is a TCP forward and cannot tunnel this UDP/QUIC protocol. Connect to
the UDP/QUIC target shown in the dashboard and allow outbound UDP to its port.

## Notes

- `connect` / `connect_with_token` validate the certificate and DNS hostname.
  `dangerous_connect_insecure_local_dev` is deliberately explicit and only for
  a local self-signed development endpoint.
- Private PKI remains verified: use
  `PulseClient::builder(target).with_token(token).add_custom_ca_der(der).connect()`;
  the endpoint hostname is still checked and native roots remain enabled.
- A terminal server close is `Error::ApplicationClosed(CloseInfo { code,
  reason })`. `retryable()` is true only for transient code 3; code 2 requires
  new credentials, and codes 1, 4, and 5 must not be retried unchanged. If a
  close interrupts an announced full-tx frame, `BadFrameWithClose(CloseInfo)`
  preserves both the truncation and close; use `error.is_bad_frame()` and
  `error.close_info()` to inspect them uniformly.
- The full tier streams transactions that arrive **after** you subscribe — it is
  a live feed, not a backfill.
- The wire protocol is specified in the
  [public protocol document](https://github.com/thorlabsDev/pulse-sdk/blob/main/docs/PROTOCOL.md).
