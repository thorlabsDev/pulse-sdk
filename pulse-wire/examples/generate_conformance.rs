//! Prints the shared wire-v2 golden vectors as deterministic JSON.
//!
//! Regenerate from the repository root with:
//! `cargo run -q -p thornode-pulse-wire --example generate_conformance`.

use serde_json::json;
use thornode_pulse_wire::frame::{
    self, encode_dg_heartbeat, encode_dg_sig_first, encode_frame_tx, put_tlv, FullAtl,
    FullInstruction, FullTx,
};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("write to String");
    }
    out
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn sample_tx() -> FullTx {
    FullTx {
        slot: 438_690_000,
        versioned: true,
        num_required_signatures: 1,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 1,
        recent_blockhash: [0xcc; 32],
        signatures: vec![[0x07; 64]],
        account_keys: vec![[0xa1; 32], [0xb2; 32]],
        instructions: vec![FullInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: vec![9, 9],
        }],
        address_table_lookups: vec![FullAtl {
            account_key: [0xee; 32],
            writable_indexes: vec![0],
            readonly_indexes: vec![1],
        }],
    }
}

fn main() {
    let mut sig = [0u8; frame::DG_SIG_FIRST_MIN];
    encode_dg_sig_first(&mut sig, 438_690_000, 12_345, &[0x09; 64]);

    let mut dg_heartbeat = [0u8; frame::DG_HEARTBEAT_MIN];
    encode_dg_heartbeat(&mut dg_heartbeat, 1_700_000_000_123, 999);

    let tx = sample_tx();
    let bare = encode_frame_tx(&tx, false, &[], &[]);
    let enriched = encode_frame_tx(&tx, true, &[[0x11; 32], [0x22; 32]], &[[0x33; 32]]);
    let mut enriched_unknown_tlv = enriched.clone();
    put_tlv(&mut enriched_unknown_tlv, 200, &[9, 8, 7, 6]);

    let mut stream_heartbeat = vec![frame::MSG_HEARTBEAT, 0];
    put_tlv(
        &mut stream_heartbeat,
        frame::TLV_SERVER_TS_MS,
        &1_700_000_000_123u64.to_le_bytes(),
    );
    put_tlv(
        &mut stream_heartbeat,
        frame::TLV_HIGHEST_SEQ,
        &999u64.to_le_bytes(),
    );

    let document = json!({
        "schema": "thornode.pulse.wire-v2.conformance",
        "schema_version": 1,
        "wire_version": thornode_pulse_wire::protocol::WIRE_VERSION,
        "vectors": {
            "stream_preamble": {
                "hex": hex(frame::PREAMBLE)
            },
            "sig_first_datagram": {
                "hex": hex(&sig),
                "slot": 438_690_000u64,
                "seq": 12_345u64,
                "signature_hex": hex(&[0x09; 64])
            },
            "datagram_heartbeat": {
                "hex": hex(&dg_heartbeat),
                "server_ts_ms": 1_700_000_000_123u64,
                "highest_seq": 999u64
            },
            "full_tx_bare": {
                "frame_hex": hex(&bare),
                "stream_record_hex": hex(&framed(&bare)),
                "slot": tx.slot,
                "alt_incomplete": false,
                "loaded_writable_hex": [],
                "loaded_readonly_hex": []
            },
            "full_tx_enriched": {
                "frame_hex": hex(&enriched),
                "stream_record_hex": hex(&framed(&enriched)),
                "slot": tx.slot,
                "alt_incomplete": true,
                "loaded_writable_hex": [hex(&[0x11; 32]), hex(&[0x22; 32])],
                "loaded_readonly_hex": [hex(&[0x33; 32])]
            },
            "full_tx_unknown_tlv": {
                "frame_hex": hex(&enriched_unknown_tlv),
                "unknown_type": 200,
                "unknown_value_hex": "09080706"
            },
            "stream_heartbeat": {
                "frame_hex": hex(&stream_heartbeat),
                "stream_record_hex": hex(&framed(&stream_heartbeat)),
                "server_ts_ms": 1_700_000_000_123u64,
                "highest_seq": 999u64
            }
        },
        "control": {
            "initial_sig_first_json": "{\"token\":\"example-token\",\"account_include\":[],\"account_exclude\":[],\"account_required\":[],\"full\":false,\"v\":2,\"fields\":[]}",
            "initial_ack_framed_hex": hex(&framed(br#"{"type":"ack","ok":true,"v":2}"#)),
            "update_ack_framed_hex": hex(&framed(br#"{"type":"ack","ok":true}"#)),
            "update_ack_with_version_framed_hex": hex(&framed(br#"{"type":"ack","ok":true,"v":2}"#))
        },
        "application_close": {
            "0": "normal",
            "1": "non_retryable",
            "2": "credentials_required",
            "3": "transient",
            "4": "non_retryable",
            "5": "non_retryable"
        }
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("serialize vectors")
    );
}
