"""Frame-codec tests — pure, no aioquic / no network required."""

import struct

import pytest

from thornode_pulse.frame import (
    DG_HEARTBEAT_MIN,
    DG_SIG_FIRST,
    DG_SIG_FIRST_MIN,
    FLAG_ALT_INCOMPLETE,
    MSG_HEARTBEAT,
    MSG_TX,
    PREAMBLE,
    TLV_HIGHEST_SEQ,
    TLV_LOADED_READONLY,
    TLV_LOADED_WRITABLE,
    TLV_SERVER_TS_MS,
    WIRE_VERSION,
    AddressTableLookup,
    BadFrame,
    BadPreamble,
    DatagramHeartbeat,
    DatagramSigFirst,
    DatagramUnknown,
    FrameHeartbeat,
    FrameUnknown,
    FullTx,
    FullTxV2,
    Instruction,
    _verify_preamble,
    decode_datagram,
    decode_frame,
    decode_full_tx,
    encode_dg_heartbeat,
    encode_dg_sig_first,
    encode_frame_tx,
    encode_full_tx,
    parse_tlvs,
    put_tlv,
)


def sample(versioned: bool) -> FullTx:
    return FullTx(
        slot=7,
        versioned=versioned,
        num_required_signatures=1,
        num_readonly_signed_accounts=0,
        num_readonly_unsigned_accounts=0,
        recent_blockhash=b"\xcc" * 32,
        signatures=[b"\x07" * 64],
        account_keys=[b"\xa1" * 32],
        instructions=[Instruction(1, b"\x00", b"\xde\xad\xbe")],
        address_table_lookups=(
            [AddressTableLookup(b"\xee" * 32, b"\x05", b"\x07")] if versioned else []
        ),
    )


def _valid_v1_body() -> bytes:
    return encode_full_tx(sample(False))


def _tlv(t: int, value: bytes) -> bytes:
    buf = bytearray()
    put_tlv(buf, t, value)
    return bytes(buf)


# ---- full-tx body (v1 positional layout) ------------------------------------


@pytest.mark.parametrize("versioned", [False, True])
def test_full_tx_round_trip(versioned):
    ft = sample(versioned)
    got = decode_full_tx(encode_full_tx(ft))
    assert got == ft


def test_vector_matches_documented_layout():
    b = bytearray()
    b += struct.pack("<Q", 42)  # slot
    b += bytes([1, 0, 0, 0])  # numReqSigs, roSigned, roUnsigned, versioned=0
    b += b"\xcc" * 32  # recent blockhash
    b += struct.pack("<H", 1) + b"\x11" * 64  # 1 signature
    b += struct.pack("<H", 1) + b"\xa1" * 32  # 1 account key
    b += struct.pack("<H", 0)  # 0 instructions
    b += struct.pack("<H", 0)  # 0 ATLs
    ft = decode_full_tx(bytes(b))
    assert ft.slot == 42
    assert ft.signatures == [b"\x11" * 64]
    assert ft.account_keys == [b"\xa1" * 32]
    assert ft.versioned is False


def test_rejects_truncated_and_trailing():
    body = encode_full_tx(sample(True))
    with pytest.raises(BadFrame):
        decode_full_tx(body[:-3])
    with pytest.raises(BadFrame):
        decode_full_tx(body + b"\x00")


# ---- stream preamble ---------------------------------------------------------


def test_preamble_is_six_bytes_and_starts_nonzero():
    # A v1 stream's first byte is ALWAYS 0x00 (u32 BE length prefix, frames
    # <= 64 KiB), so a non-zero first byte is what makes the preamble
    # unambiguous. Guard that property.
    assert len(PREAMBLE) == 6
    assert PREAMBLE[0] != 0x00
    assert PREAMBLE[0:4] == b"PLS2"
    assert PREAMBLE[4] == WIRE_VERSION
    assert PREAMBLE[5] == 0


def test_preamble_mismatch_raises():
    with pytest.raises(BadPreamble):
        _verify_preamble(b"XXXX\x02\x00")


def test_preamble_accepts_the_real_preamble():
    _verify_preamble(PREAMBLE)  # must not raise


def test_preamble_short_read_raises():
    with pytest.raises(BadPreamble):
        _verify_preamble(PREAMBLE[:5])


# ---- TLV trailer --------------------------------------------------------------


def test_tlv_round_trips_in_order():
    b = bytearray()
    put_tlv(b, TLV_LOADED_WRITABLE, b"\x01" * 64)
    put_tlv(b, TLV_LOADED_READONLY, b"\x02" * 32)
    got = parse_tlvs(bytes(b))
    assert len(got) == 2
    assert got[0] == (TLV_LOADED_WRITABLE, b"\x01" * 64)
    assert got[1] == (TLV_LOADED_READONLY, b"\x02" * 32)


def test_tlv_length_is_u16_so_a_large_value_fits():
    # 100 addresses x 32 bytes = 3200 -- impossible with a u8 length.
    big = b"\x07" * 3200
    b = bytearray()
    put_tlv(b, TLV_LOADED_WRITABLE, big)
    got = parse_tlvs(bytes(b))
    assert len(got[0][1]) == 3200


def test_tlv_unknown_type_is_kept_for_the_caller_to_skip():
    b = bytearray()
    put_tlv(b, 200, b"\x09" * 4)
    got = parse_tlvs(bytes(b))
    assert got[0][0] == 200


def test_tlv_duplicate_type_is_rejected():
    b = bytearray()
    put_tlv(b, TLV_LOADED_WRITABLE, b"\x01" * 32)
    put_tlv(b, TLV_LOADED_WRITABLE, b"\x02" * 32)
    with pytest.raises(BadFrame):
        parse_tlvs(bytes(b))


def test_tlv_duplicate_unknown_type_is_also_rejected():
    # The dup check applies across ALL entries, recognized or not -- an
    # unknown type is still skipped for interpretation, but two records
    # claiming the same type tag is still an ambiguity the wire must reject.
    b = bytearray()
    put_tlv(b, 200, b"\x01")
    put_tlv(b, 200, b"\x02")
    with pytest.raises(BadFrame):
        parse_tlvs(bytes(b))


def test_tlv_truncated_is_rejected():
    b = bytearray()
    put_tlv(b, TLV_LOADED_WRITABLE, b"\x01" * 32)
    for cut in range(1, len(b)):
        with pytest.raises(BadFrame):
            parse_tlvs(bytes(b[:cut]))
    assert parse_tlvs(b"") == []


def test_tlv_length_overrunning_the_buffer_is_rejected():
    # type=1, len=0xFFFF, but no payload
    b = bytes([1, 0xFF, 0xFF])
    with pytest.raises(BadFrame):
        parse_tlvs(b)


def test_duplicate_tlv_rejected_unknown_skipped():
    body = _valid_v1_body()
    ok = bytes([MSG_TX, 0]) + body + _tlv(200, b"\x01\x02")
    decode_frame(ok)  # must not raise
    dup = bytes([MSG_TX, 0]) + body + _tlv(TLV_LOADED_WRITABLE, b"\x00" * 32) * 2
    with pytest.raises(BadFrame):
        decode_frame(dup)


# ---- v2 stream frames ---------------------------------------------------------


def test_v2_tx_frame_round_trips_bare():
    tx = sample(True)
    enc = encode_frame_tx(tx, False, [], [])
    assert enc[0] == MSG_TX
    assert enc[1] == 0
    got = decode_frame(enc)
    assert isinstance(got, FullTxV2)
    assert got.tx == tx
    assert got.alt_incomplete is False
    assert got.loaded_writable == []
    assert got.loaded_readonly == []


def test_v2_tx_frame_round_trips_enriched():
    tx = sample(True)
    w = [b"\x11" * 32, b"\x22" * 32]
    r = [b"\x33" * 32]
    enc = encode_frame_tx(tx, True, w, r)
    assert enc[1] & FLAG_ALT_INCOMPLETE == FLAG_ALT_INCOMPLETE
    got = decode_frame(enc)
    assert isinstance(got, FullTxV2)
    assert got.alt_incomplete is True
    assert got.loaded_writable == w
    assert got.loaded_readonly == r


def test_v2_body_is_byte_identical_to_v1_encoding():
    # The v1 positional body is reused unchanged; only the framing is new.
    tx = sample(True)
    v1 = encode_full_tx(tx)
    v2 = encode_frame_tx(tx, False, [], [])
    assert v2[2 : 2 + len(v1)] == v1


def test_unknown_msg_type_is_reported_not_rejected():
    enc = bytearray(encode_frame_tx(sample(False), False, [], []))
    enc[0] = 99
    got = decode_frame(bytes(enc))
    assert isinstance(got, FrameUnknown)
    assert got.msg_type == 99


def test_reserved_flag_bits_are_rejected():
    enc = bytearray(encode_frame_tx(sample(False), False, [], []))
    enc[1] = 0x02  # bit 1 reserved
    with pytest.raises(BadFrame):
        decode_frame(bytes(enc))


def test_loaded_address_tlv_with_a_non_multiple_of_32_is_rejected():
    enc = bytearray()
    enc.append(MSG_TX)
    enc.append(0)
    enc += encode_full_tx(sample(False))
    put_tlv(enc, TLV_LOADED_WRITABLE, b"\x00" * 33)
    with pytest.raises(BadFrame):
        decode_frame(bytes(enc))


def test_heartbeat_frame_round_trips():
    enc = bytearray()
    enc.append(MSG_HEARTBEAT)
    enc.append(0)
    put_tlv(enc, TLV_SERVER_TS_MS, struct.pack("<Q", 1_700_000_000_123))
    put_tlv(enc, TLV_HIGHEST_SEQ, struct.pack("<Q", 4242))
    got = decode_frame(bytes(enc))
    assert isinstance(got, FrameHeartbeat)
    assert got.server_ts_ms == 1_700_000_000_123
    assert got.highest_seq == 4242


def test_heartbeat_frame_rejects_any_nonzero_flags():
    # Unlike MSG_TX, alt_incomplete (bit 0) has no meaning on a heartbeat, so
    # every bit is reserved for this message type -- not just bits 1-7.
    for flags in (FLAG_ALT_INCOMPLETE, 0x02, 0xFF):
        enc = bytearray()
        enc.append(MSG_HEARTBEAT)
        enc.append(flags)
        put_tlv(enc, TLV_SERVER_TS_MS, struct.pack("<Q", 1))
        with pytest.raises(BadFrame):
            decode_frame(bytes(enc))


def test_frame_too_short_is_rejected():
    with pytest.raises(BadFrame):
        decode_frame(b"")
    with pytest.raises(BadFrame):
        decode_frame(bytes([MSG_TX]))


# ---- typed datagrams ----------------------------------------------------------


def test_dg_sig_first_round_trips():
    buf = encode_dg_sig_first(438_690_000, 12345, b"\x09" * 64)
    assert buf[0] == DG_SIG_FIRST
    got = decode_datagram(buf)
    assert isinstance(got, DatagramSigFirst)
    assert got.slot == 438_690_000
    assert got.seq == 12345
    assert got.signature == b"\x09" * 64


def test_dg_heartbeat_round_trips():
    buf = encode_dg_heartbeat(1_700_000_000_123, 999)
    got = decode_datagram(buf)
    assert isinstance(got, DatagramHeartbeat)
    assert got.server_ts_ms == 1_700_000_000_123
    assert got.highest_seq == 999


def test_datagram_minimum_length_not_exact():
    buf = bytearray(DG_SIG_FIRST_MIN + 8)
    buf[0] = DG_SIG_FIRST
    buf[1:9] = (42).to_bytes(8, "little")
    buf[9:17] = (7).to_bytes(8, "little")
    d = decode_datagram(bytes(buf))
    assert d.slot == 42 and d.seq == 7


def test_dg_minimum_length_not_exact_length():
    # THE forward-compatibility rule: a longer datagram of a known type must
    # parse, ignoring the trailing bytes. Without this, v2 re-freezes the
    # format exactly as v1 did and the next field is another break.
    buf = encode_dg_sig_first(7, 8, b"\x03" * 64)
    longer = buf + b"\xab" * 16
    got = decode_datagram(longer)
    assert isinstance(got, DatagramSigFirst)
    assert got.slot == 7 and got.seq == 8


def test_dg_heartbeat_minimum_length_not_exact():
    buf = encode_dg_heartbeat(1, 2)
    longer = buf + b"\xcd" * 5
    got = decode_datagram(longer)
    assert isinstance(got, DatagramHeartbeat)
    assert got.server_ts_ms == 1 and got.highest_seq == 2


def test_dg_below_minimum_is_rejected():
    buf = encode_dg_sig_first(1, 2, b"\x00" * 64)
    assert decode_datagram(buf[: DG_SIG_FIRST_MIN - 1]) is None
    hb = encode_dg_heartbeat(1, 2)
    assert decode_datagram(hb[: DG_HEARTBEAT_MIN - 1]) is None
    assert decode_datagram(b"") is None


def test_dg_unknown_type_is_reported_not_rejected():
    buf = bytes([200, 1, 2, 3])
    got = decode_datagram(buf)
    assert isinstance(got, DatagramUnknown)
    assert got.dg_type == 200


def test_a_v1_72_byte_datagram_is_rejected_by_the_length_rule():
    # v1 datagrams began with the low byte of the slot, so their first byte
    # can be 1 -- colliding with DG_SIG_FIRST. The length rule is what
    # separates them: 72 < DG_SIG_FIRST_MIN (81), so a known type that is
    # too short returns None rather than a garbage decode.
    v1 = bytes([1]) * 72
    assert decode_datagram(v1) is None
