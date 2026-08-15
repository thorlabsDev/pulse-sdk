use std::path::PathBuf;

use serde_json::Value;
use thornode_pulse_wire::{frame, protocol};

fn fixture() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance/wire-v2/vectors.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("read shared fixture {}: {error}", path.display()));
    serde_json::from_slice(&bytes).expect("valid conformance JSON")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn sample_tx() -> frame::FullTx {
    frame::FullTx {
        slot: 438_690_000,
        versioned: true,
        num_required_signatures: 1,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 1,
        recent_blockhash: [0xcc; 32],
        signatures: vec![[0x07; 64]],
        account_keys: vec![[0xa1; 32], [0xb2; 32]],
        instructions: vec![frame::FullInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: vec![9, 9],
        }],
        address_table_lookups: vec![frame::FullAtl {
            account_key: [0xee; 32],
            writable_indexes: vec![0],
            readonly_indexes: vec![1],
        }],
    }
}

#[test]
fn checked_in_vectors_are_generated_by_the_canonical_codec() {
    let root = fixture();
    assert_eq!(root["schema"], "thornode.pulse.wire-v2.conformance");
    assert_eq!(root["wire_version"], protocol::WIRE_VERSION);
    let vectors = &root["vectors"];

    assert_eq!(
        decode_hex(vectors["stream_preamble"]["hex"].as_str().unwrap()),
        frame::PREAMBLE
    );

    let mut sig = [0u8; frame::DG_SIG_FIRST_MIN];
    frame::encode_dg_sig_first(&mut sig, 438_690_000, 12_345, &[0x09; 64]);
    assert_eq!(
        sig.as_slice(),
        decode_hex(vectors["sig_first_datagram"]["hex"].as_str().unwrap())
    );

    let mut heartbeat = [0u8; frame::DG_HEARTBEAT_MIN];
    frame::encode_dg_heartbeat(&mut heartbeat, 1_700_000_000_123, 999);
    assert_eq!(
        heartbeat.as_slice(),
        decode_hex(vectors["datagram_heartbeat"]["hex"].as_str().unwrap())
    );

    let tx = sample_tx();
    let bare = frame::encode_frame_tx(&tx, false, &[], &[]);
    assert_eq!(
        bare,
        decode_hex(vectors["full_tx_bare"]["frame_hex"].as_str().unwrap())
    );

    let enriched = frame::encode_frame_tx(&tx, true, &[[0x11; 32], [0x22; 32]], &[[0x33; 32]]);
    assert_eq!(
        enriched,
        decode_hex(vectors["full_tx_enriched"]["frame_hex"].as_str().unwrap())
    );
}

#[test]
fn fixture_locks_additive_decode_and_retry_semantics() {
    let root = fixture();
    let ack = decode_hex(root["control"]["initial_ack_framed_hex"].as_str().unwrap());
    let declared = u32::from_be_bytes(ack[..4].try_into().unwrap()) as usize;
    assert_eq!(
        declared,
        ack.len() - 4,
        "control prefix is u32 BE body length"
    );
    let envelope: Value = serde_json::from_slice(&ack[4..]).expect("ack body is JSON");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["v"], protocol::WIRE_VERSION);

    let unknown = decode_hex(
        root["vectors"]["full_tx_unknown_tlv"]["frame_hex"]
            .as_str()
            .unwrap(),
    );
    let frame::Frame::Tx(decoded) = frame::decode_frame(&unknown).expect("unknown TLV is additive")
    else {
        panic!("expected transaction frame");
    };
    assert!(decoded.alt_incomplete);
    assert_eq!(decoded.loaded_writable, vec![[0x11; 32], [0x22; 32]]);
    assert_eq!(decoded.loaded_readonly, vec![[0x33; 32]]);

    let close = &root["application_close"];
    for (code, expected) in [
        (0, protocol::RetryClass::Normal),
        (1, protocol::RetryClass::NonRetryable),
        (2, protocol::RetryClass::CredentialsRequired),
        (3, protocol::RetryClass::Transient),
        (4, protocol::RetryClass::NonRetryable),
        (5, protocol::RetryClass::NonRetryable),
    ] {
        assert_eq!(protocol::classify_close_code(code), expected);
        assert!(close[code.to_string()].is_string());
    }
}
