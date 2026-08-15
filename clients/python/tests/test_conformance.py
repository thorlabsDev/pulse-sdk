"""Decode the shared Rust-generated wire-v2 golden vectors."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from thornode_pulse.client import CloseInfo, _check_ack, _parse_ack
from thornode_pulse.frame import (
    PREAMBLE,
    WIRE_VERSION,
    DatagramHeartbeat,
    DatagramSigFirst,
    FrameHeartbeat,
    FullTxV2,
    decode_datagram,
    decode_frame,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[3] / "conformance" / "wire-v2" / "vectors.json"
)


def _fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _bytes(vector):
    return bytes.fromhex(vector["hex"])


def test_shared_fixture_schema_and_protocol_constants():
    fixture = _fixture()
    assert fixture["schema"] == "thornode.pulse.wire-v2.conformance"
    assert fixture["schema_version"] == 1
    assert fixture["wire_version"] == WIRE_VERSION == 2
    assert _bytes(fixture["vectors"]["stream_preamble"]) == PREAMBLE


def test_shared_sig_first_and_heartbeat_datagrams():
    vectors = _fixture()["vectors"]

    sig_vector = vectors["sig_first_datagram"]
    sig = decode_datagram(_bytes(sig_vector))
    assert isinstance(sig, DatagramSigFirst)
    assert sig.slot == sig_vector["slot"]
    assert sig.seq == sig_vector["seq"]
    assert sig.signature.hex() == sig_vector["signature_hex"]

    heartbeat_vector = vectors["datagram_heartbeat"]
    heartbeat = decode_datagram(_bytes(heartbeat_vector))
    assert isinstance(heartbeat, DatagramHeartbeat)
    assert heartbeat.server_ts_ms == heartbeat_vector["server_ts_ms"]
    assert heartbeat.highest_seq == heartbeat_vector["highest_seq"]


def test_shared_full_tx_frames_and_big_endian_stream_records():
    vectors = _fixture()["vectors"]
    for name in ("full_tx_bare", "full_tx_enriched"):
        vector = vectors[name]
        encoded_frame = bytes.fromhex(vector["frame_hex"])
        frame = decode_frame(encoded_frame)
        assert isinstance(frame, FullTxV2)
        assert frame.tx.slot == vector["slot"]
        assert frame.alt_incomplete is vector["alt_incomplete"]
        assert [value.hex() for value in frame.loaded_writable] == vector[
            "loaded_writable_hex"
        ]
        assert [value.hex() for value in frame.loaded_readonly] == vector[
            "loaded_readonly_hex"
        ]

        record = bytes.fromhex(vector["stream_record_hex"])
        length = struct.unpack(">I", record[:4])[0]
        assert length == len(encoded_frame)
        assert record[4:] == encoded_frame


def test_shared_unknown_tlv_is_additive_not_fatal():
    vector = _fixture()["vectors"]["full_tx_unknown_tlv"]
    frame = decode_frame(bytes.fromhex(vector["frame_hex"]))
    assert isinstance(frame, FullTxV2)
    assert frame.alt_incomplete is True


def test_shared_stream_heartbeat_and_control_ack():
    fixture = _fixture()
    heartbeat_vector = fixture["vectors"]["stream_heartbeat"]
    frame_bytes = bytes.fromhex(heartbeat_vector["frame_hex"])
    heartbeat = decode_frame(frame_bytes)
    assert isinstance(heartbeat, FrameHeartbeat)
    assert heartbeat.server_ts_ms == heartbeat_vector["server_ts_ms"]
    assert heartbeat.highest_seq == heartbeat_vector["highest_seq"]

    record = bytes.fromhex(heartbeat_vector["stream_record_hex"])
    assert struct.unpack(">I", record[:4])[0] == len(frame_bytes)
    assert record[4:] == frame_bytes

    ack_record = bytes.fromhex(fixture["control"]["initial_ack_framed_hex"])
    ack_length = struct.unpack(">I", ack_record[:4])[0]
    ack = _parse_ack(ack_record[4 : 4 + ack_length])
    _check_ack(ack, initial=True)
    assert ack.ok is True
    assert ack.v == WIRE_VERSION

    initial = json.loads(fixture["control"]["initial_sig_first_json"])
    assert initial["token"] == "example-token"
    assert initial["full"] is False
    assert initial["v"] == WIRE_VERSION
    assert initial["fields"] == []


def test_shared_update_ack_vectors_accept_omitted_or_matching_version():
    control = _fixture()["control"]
    for key, expected_version in (
        ("update_ack_framed_hex", None),
        ("update_ack_with_version_framed_hex", WIRE_VERSION),
    ):
        record = bytes.fromhex(control[key])
        length = struct.unpack(">I", record[:4])[0]
        assert length == len(record) - 4
        ack = _check_ack(_parse_ack(record[4:]), initial=False)
        assert ack.ok is True
        assert ack.v == expected_version


def test_shared_application_close_retry_classification():
    fixture = _fixture()
    actual = {
        code: CloseInfo(int(code)).retry_disposition.value
        for code in fixture["application_close"]
    }
    assert actual == fixture["application_close"]
