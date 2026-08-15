"""Client-control and framing tests — no network / no live QUIC required.

Everything the client does with a decoded frame or datagram is pulled out
into pure functions/classes (`_next_tx_frame`, `_FullStreamState`,
`_GapTracker`, `_apply_datagram`, `_parse_ack`/`_check_ack`) specifically so
it is testable this way -- mirroring how the Rust SDK's `next_frame`/
`verify_preamble` are generic over `AsyncRead` and the Go SDK's `nextFrame`/
`verifyPreamble` are generic over `io.Reader` for the same reason.
"""

from __future__ import annotations

import asyncio
import gc
import struct

import pytest
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    StreamDataReceived,
)

from thornode_pulse.client import (
    MAX_ACK_BYTES,
    NO_SEQ_ASSIGNED,
    WIRE_VERSION,
    Ack,
    CloseInfo,
    Filter,
    FullSub,
    Heartbeat,
    MissingVersion,
    PulseClient,
    PulseConnectionClosed,
    PulseStreamTruncated,
    Rejected,
    RetryDisposition,
    SigFirstItem,
    SigFirstSub,
    Timeouts,
    VersionMismatch,
    _apply_datagram,
    _check_ack,
    _FullStreamState,
    _FullTerminal,
    _GapTracker,
    _next_tx_frame,
    _parse_ack,
    _PreambleGate,
    _PulseProtocol,
)
from thornode_pulse.frame import (
    MSG_HEARTBEAT,
    MSG_TX,
    PREAMBLE,
    TLV_HIGHEST_SEQ,
    TLV_SERVER_TS_MS,
    BadFrame,
    BadPreamble,
    FullTx,
    FullTxV2,
    encode_dg_heartbeat,
    encode_dg_sig_first,
    encode_frame_tx,
    put_tlv,
)

# ---- control message shape ---------------------------------------------------


def test_control_omits_empty_token():
    control = Filter.all()._to_control(False)
    assert control == {"full": False, "v": WIRE_VERSION, "fields": []}


def test_control_includes_token_when_set():
    control = Filter.accounts("acct")._to_control(True, "rpc_test")
    assert control["token"] == "rpc_test"
    assert control["full"] is True
    assert control["account_include"] == ["acct"]


def test_control_omits_vote_when_unset():
    assert "vote" not in Filter.all()._to_control(False)


def test_control_includes_vote_when_set():
    assert Filter.all().with_vote(True)._to_control(False)["vote"] is True
    assert Filter.all().with_vote(False)._to_control(False)["vote"] is False


def test_control_declares_wire_v2():
    assert Filter.all()._to_control(False)["v"] == 2


def test_control_fields_opts_into_enrichment():
    control = Filter.all()._to_control(True, fields=["alt"])
    assert control["fields"] == ["alt"]


def test_control_fields_defaults_to_empty_list_not_null():
    # The wire must always carry a JSON array, never a bare `null`, where the
    # server expects a list.
    control = Filter.all()._to_control(False)
    assert control["fields"] == []


# ---- control ack: parse + interpret ------------------------------------------


def test_parse_ack_first_message_success_envelope_with_version():
    ack = _parse_ack(b'{"type":"ack","ok":true,"v":2}')
    assert ack.ok is True
    assert ack.v == 2


def test_parse_ack_rejection_envelope_with_reason():
    ack = _parse_ack(b'{"type":"ack","ok":false,"reason":"invalid control message"}')
    assert ack.ok is False
    assert ack.reason == "invalid control message"


def test_parse_ack_update_success_envelope_without_version():
    ack = _parse_ack(b'{"type":"ack","ok":true}')
    assert ack.ok is True
    assert ack.v is None


def test_parse_ack_rejects_malformed_json():
    with pytest.raises(BadFrame):
        _parse_ack(b"not json")


def test_check_ack_surfaces_a_rejection_with_its_reason():
    with pytest.raises(Rejected) as exc_info:
        _check_ack(Ack(ok=False, reason="bad token", kind="ack"))
    assert exc_info.value.reason == "bad token"


def test_check_ack_succeeds_on_an_ok_ack_and_does_not_raise():
    ack = _check_ack(
        Ack(ok=True, v=WIRE_VERSION, kind="ack"),
        initial=True,
    )
    assert ack.ok is True


def test_check_ack_succeeds_on_an_update_ack_with_no_version():
    # An update ack must not spuriously fail the version check just because
    # the field is absent.
    ack = _check_ack(Ack(ok=True, v=None, kind="ack"))
    assert ack.ok is True


def test_check_ack_accepts_a_matching_version_on_an_update_ack():
    ack = _check_ack(Ack(ok=True, v=WIRE_VERSION, kind="ack"))
    assert ack.v == WIRE_VERSION


def test_check_ack_surfaces_a_version_mismatch_on_the_first_ack():
    with pytest.raises(VersionMismatch) as exc_info:
        _check_ack(
            Ack(ok=True, v=WIRE_VERSION - 1, kind="ack"),
            initial=True,
        )
    assert exc_info.value.negotiated == WIRE_VERSION - 1


def test_check_ack_requires_version_on_the_first_success_ack():
    with pytest.raises(MissingVersion):
        _check_ack(Ack(ok=True, kind="ack"), initial=True)


@pytest.mark.parametrize("kind", [None, "future"])
def test_check_ack_rejects_missing_or_unknown_envelope_type(kind):
    with pytest.raises(BadFrame):
        _check_ack(Ack(ok=True, v=WIRE_VERSION, kind=kind), initial=True)


def test_parse_ack_rejects_a_missing_envelope_type():
    with pytest.raises(BadFrame):
        _parse_ack(b'{"ok":true,"v":2}')


def test_check_update_ack_rejects_a_conflicting_version():
    with pytest.raises(VersionMismatch):
        _check_ack(Ack(ok=True, v=WIRE_VERSION - 1, kind="ack"))


# ---- sig-first gap tracking ---------------------------------------------------


def test_note_item_seq_counts_missed_numbers_between_consecutive_items():
    t = _GapTracker()
    t.note_item_seq(0)
    assert t.gaps == 0, "first item establishes the baseline"
    t.note_item_seq(3)  # missed 1 and 2
    assert t.gaps == 2


def test_note_item_seq_out_of_order_never_goes_negative():
    # A later item with a LOWER seq than the last one seen must not produce
    # a negative/underflowed gap count.
    t = _GapTracker()
    t.note_item_seq(10)
    t.note_item_seq(3)
    assert t.gaps == 0, "no underflow, no bogus gap"
    assert t._last_seq == 10, "watermark must not regress on reorder"
    t.note_item_seq(11)
    assert t.gaps == 0, "seq 11 directly follows the watermark of 10"
    assert t._last_seq == 11


def test_note_item_seq_reordering_does_not_double_count_the_same_gap():
    # Concrete scenario: seqs 0,1,2,3 arrive in wire order 0,2,1,3 -- zero
    # actual loss. A scalar watermark can't tell "1 is late" from "1 is
    # lost" at the moment 2 arrives, so charging 1 gap there is unavoidable
    # with this model (that provisional count is not a bug). What WOULD be
    # a real bug: an unconditional `last_seq = seq` on the late arrival of 1
    # regressing the watermark to 1, so the following in-order 3 gets
    # charged AGAIN for the already-counted 2->3 range.
    t = _GapTracker()
    for seq in (0, 2, 1, 3):
        t.note_item_seq(seq)
    assert t.gaps == 1, "one provisional gap from the 0->2 jump, never double-charged"
    assert t._last_seq == 3, (
        "watermark tracks the highest seq seen, not the latest arrival"
    )


def test_note_item_seq_sentinel_seq_does_not_blow_up():
    # A corrupt or hostile datagram could carry seq == NO_SEQ_ASSIGNED. The
    # "+1" computed against the previous watermark must not misbehave.
    t = _GapTracker()
    t.note_item_seq(NO_SEQ_ASSIGNED)
    t.note_item_seq(NO_SEQ_ASSIGNED)
    assert t.gaps == 0
    assert t._last_seq == NO_SEQ_ASSIGNED


def test_note_heartbeat_seq_sentinel_is_never_a_gap():
    # THE required property: NO_SEQ_ASSIGNED must never be treated as a
    # real value. A naive `highest_seq - last` here would compute an
    # astronomical, nonsensical gap.
    t = _GapTracker()
    t.note_item_seq(5)
    t.note_heartbeat_seq(NO_SEQ_ASSIGNED)
    assert t.gaps == 0
    assert t._last_seq == 5, "the sentinel must not overwrite a real baseline either"


def test_note_heartbeat_seq_reveals_trailing_loss():
    # This is the case item-to-item comparison can never see: datagrams
    # dropped AFTER the last one actually received, with nothing since to
    # reveal the hole. Only a heartbeat's highest_seq can tell us.
    t = _GapTracker()
    t.note_item_seq(2)
    t.note_heartbeat_seq(7)
    assert t.gaps == 5
    assert t._last_seq == 7


def test_note_heartbeat_seq_first_observation_establishes_a_baseline_not_a_gap():
    # No prior item to compare against: no evidence anything was actually
    # lost, so don't allege a number we can't justify.
    t = _GapTracker()
    t.note_heartbeat_seq(9)
    assert t.gaps == 0
    assert t._last_seq == 9


def test_apply_datagram_skips_an_unknown_type():
    t = _GapTracker()
    buf = bytes([200, 1, 2, 3])
    assert _apply_datagram(buf, t) is None
    assert t.gaps == 0


def test_apply_datagram_forwards_sig_first_and_tracks_gaps():
    t = _GapTracker()
    item = _apply_datagram(encode_dg_sig_first(100, 0, b"\x01" * 64), t)
    assert isinstance(item, SigFirstItem)
    assert (item.slot, item.seq) == (100, 0)

    item = _apply_datagram(encode_dg_sig_first(100, 3, b"\x01" * 64), t)
    assert item.seq == 3
    assert t.gaps == 2, "missed seq 1 and 2"


def test_apply_datagram_heartbeat_is_never_forwarded_as_an_item():
    t = _GapTracker()
    t.note_item_seq(1)
    assert _apply_datagram(encode_dg_heartbeat(123, 4), t) is None
    assert t.gaps == 3


def test_apply_datagram_corrupt_bytes_are_skipped_not_fatal():
    # Unlike a malformed STREAM frame, a corrupt DATAGRAM is expected, lossy
    # transport behavior -- skip it, never raise.
    t = _GapTracker()
    assert _apply_datagram(b"", t) is None
    assert _apply_datagram(bytes([1, 2, 3]), t) is None  # known type, too short
    assert t.gaps == 0


# ---- full-tx frame decode loop: unknown skipped, heartbeat folded, not returned


def sample_full_tx() -> FullTx:
    return FullTx(
        slot=438_690_000,
        versioned=False,
        num_required_signatures=1,
        num_readonly_signed_accounts=0,
        num_readonly_unsigned_accounts=0,
        recent_blockhash=b"\xcc" * 32,
        signatures=[b"\x07" * 64],
        account_keys=[b"\xa1" * 32],
        instructions=[],
        address_table_lookups=[],
    )


def _framed(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def test_next_tx_frame_skips_unknown_and_folds_heartbeat_without_surfacing_it():
    buf = bytearray()
    buf += _framed(bytes([99, 0]))  # unknown message type: must be skipped

    hb = bytearray()
    hb.append(MSG_HEARTBEAT)
    hb.append(0)
    put_tlv(hb, TLV_SERVER_TS_MS, struct.pack("<Q", 123))
    put_tlv(hb, TLV_HIGHEST_SEQ, struct.pack("<Q", 7))
    buf += _framed(bytes(hb))

    tx = sample_full_tx()
    buf += _framed(encode_frame_tx(tx, False, [], []))

    holder = [None]
    got = _next_tx_frame(buf, holder)
    assert isinstance(got, FullTxV2)
    assert got.tx == tx
    assert holder[0] == Heartbeat(123, 7), "heartbeat captured, not returned as an item"
    assert buf == bytearray(), "all three frames were consumed"


def test_next_tx_frame_returns_none_when_buffer_exhausted():
    buf = bytearray()
    holder = [None]
    assert _next_tx_frame(buf, holder) is None


def test_next_tx_frame_returns_none_on_a_partial_frame():
    tx = sample_full_tx()
    full = _framed(encode_frame_tx(tx, False, [], []))
    buf = bytearray(full[:-1])  # one byte short
    holder = [None]
    assert _next_tx_frame(buf, holder) is None
    assert len(buf) == len(full) - 1, "partial frame stays buffered, not consumed"


def test_next_tx_frame_raises_on_a_malformed_frame():
    # msg_type=MSG_TX with a body far too short to hold a full-tx prefix.
    buf = bytearray(_framed(bytes([MSG_TX, 0])))
    holder = [None]
    with pytest.raises(BadFrame):
        _next_tx_frame(buf, holder)


# ---- _FullStreamState: preamble then frames, both loud on failure ------------


def test_full_stream_state_buffers_until_the_preamble_is_complete():
    state = _FullStreamState()
    assert state.feed(PREAMBLE[:3]) == []
    assert state.heartbeat is None
    txs = state.feed(
        PREAMBLE[3:] + _framed(encode_frame_tx(sample_full_tx(), False, [], []))
    )
    assert len(txs) == 1


def test_full_stream_state_rejects_a_bad_preamble_loudly():
    state = _FullStreamState()
    with pytest.raises(BadPreamble):
        state.feed(b"XXXXXX")


def test_full_stream_state_rejects_a_short_stream_as_bad_preamble():
    state = _FullStreamState()
    assert state.feed(PREAMBLE[:5]) == []  # not enough bytes yet, no error
    # No more bytes ever arrive (as at a clean EOF short of 6 bytes): the
    # caller simply never gets a preamble-ok state. Feeding one more
    # mismatching byte demonstrates the loud failure path directly.
    with pytest.raises(BadPreamble):
        state.feed(b"Q")


def test_full_stream_state_propagates_a_malformed_frame_as_fatal():
    state = _FullStreamState()
    state.feed(PREAMBLE)
    with pytest.raises(BadFrame):
        state.feed(_framed(bytes([MSG_TX, 0])))


def test_full_stream_state_folds_multiple_heartbeats():
    state = _FullStreamState()
    state.feed(PREAMBLE)
    for ts, seq in [(1, 2), (3, 4)]:
        hb = bytearray([MSG_HEARTBEAT, 0])
        put_tlv(hb, TLV_SERVER_TS_MS, struct.pack("<Q", ts))
        put_tlv(hb, TLV_HIGHEST_SEQ, struct.pack("<Q", seq))
        assert state.feed(_framed(bytes(hb))) == []
    assert state.heartbeat == Heartbeat(3, 4)
    assert state.heartbeats == 2


# ---- _PreambleGate: subscribe_full must not hand back a subscription -------
# ---- until the preamble is actually verified --------------------------------


def test_preamble_gate_resolve_ok_lets_wait_return():
    async def run():
        gate = _PreambleGate()
        gate.resolve_ok()
        await gate.wait()  # must not raise

    asyncio.run(run())


def test_preamble_gate_resolve_error_makes_wait_raise():
    async def run():
        gate = _PreambleGate()
        gate.resolve_error(BadPreamble("boom"))
        with pytest.raises(BadPreamble):
            await gate.wait()

    asyncio.run(run())


def test_preamble_gate_wait_blocks_until_resolved_from_elsewhere():
    async def run():
        gate = _PreambleGate()
        order = []

        async def resolver():
            await asyncio.sleep(0)
            order.append("resolved")
            gate.resolve_ok()

        task = asyncio.ensure_future(resolver())
        await gate.wait()
        order.append("waited")
        await task
        assert order == ["resolved", "waited"]

    asyncio.run(run())


def test_preamble_gate_first_resolution_wins():
    # A successfully-verified preamble must not be retroactively turned into
    # an error by an unrelated later event (e.g. the connection eventually
    # closing after a long, healthy subscription).
    async def run():
        gate = _PreambleGate()
        gate.resolve_ok()
        gate.resolve_error(BadPreamble("must be ignored"))
        await gate.wait()  # must not raise

    asyncio.run(run())


def test_preamble_gate_resolve_error_on_a_never_awaited_gate_logs_nothing():
    # quic_event_received's ConnectionTerminated handler calls
    # resolve_error() on EVERY connection close, including the common case
    # where nobody ever called subscribe_full()/wait() at all (a
    # sig-first-only connection). Poisoning a Future that nobody retrieves
    # the exception from makes asyncio log an "exception was never
    # retrieved" traceback at garbage-collection time -- a false
    # BadPreamble alarm on the majority path. Exercise that GC-time callback
    # directly through a custom exception handler.
    async def run():
        loop = asyncio.get_running_loop()
        contexts = []
        loop.set_exception_handler(lambda _loop, context: contexts.append(context))

        gate = _PreambleGate()
        gate.resolve_error(BadPreamble("connection closed before preamble"))
        del gate
        gc.collect()
        await asyncio.sleep(0)  # let any exception-handler callback land

        assert contexts == [], f"unexpected exception-handler calls: {contexts}"

    asyncio.run(run())


# ---- quic_event_received: the real dispatch pipeline, offline -----------------
#
# Constructs a `_PulseProtocol`-shaped object WITHOUT calling
# `QuicConnectionProtocol.__init__` (which needs a live QUIC transport), so
# `quic_event_received` -- the actual production dispatch code, not just the
# pure helpers it delegates to -- can be driven end-to-end with aioquic's own
# (plain, constructible) event dataclasses and no network.


def _bare_proto() -> _PulseProtocol:
    proto = _PulseProtocol.__new__(_PulseProtocol)
    proto.timeouts = Timeouts()
    proto.sig_queue_len = 4096
    proto.full_queue_len = 1024
    proto.datagrams = asyncio.Queue(maxsize=4096)
    proto.full = asyncio.Queue(maxsize=1025)
    proto.dropped = 0
    proto.full_dropped = 0
    proto._full_queued = 0
    proto._full_terminal_enqueued = False
    proto._full_terminal_slot = None
    proto._sig_terminal_enqueued = False
    proto._terminal_error = None
    proto._sig_gap_tracker = _GapTracker()
    proto._feed_kind = None
    proto._full_state = None
    proto._full_truncation = None
    proto._full_poisoned = False
    proto._full_last_activity = 0.0
    proto._preamble_gate = _PreambleGate()
    proto._ack_waiters = {}
    proto._ack_bufs = {}
    proto.close = lambda **kwargs: None
    return proto


def _get_full_nowait(proto: _PulseProtocol):
    item = proto.full.get_nowait()
    return item.error if isinstance(item, _FullTerminal) else item


# Server-initiated unidirectional stream id (bit 1 set): the full-tx push
# stream. Client-initiated bidirectional stream ids (bit 1 clear, e.g. 0, 4)
# are control/ack streams -- see quic_event_received's dispatch comment.
_SERVER_UNI_STREAM_ID = 3
_CLIENT_BIDI_STREAM_ID = 0


def test_quic_event_received_routes_datagrams_into_the_queue_with_gaps_tracked():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            DatagramFrameReceived(data=encode_dg_sig_first(1, 0, b"\x01" * 64))
        )
        proto.quic_event_received(
            DatagramFrameReceived(data=encode_dg_sig_first(1, 2, b"\x01" * 64))
        )
        assert proto.datagrams.qsize() == 2
        assert proto._sig_gap_tracker.gaps == 1, "missed seq 1"

    asyncio.run(run())


def test_quic_event_received_routes_full_tx_stream_data_through_preamble_and_frames():
    # quic_event_received is only ever invoked by aioquic while its event
    # loop is running (it's a transport callback), and it touches
    # `_preamble_gate`, which needs a running loop to create its Future --
    # so, like the real client, this whole flow runs inside asyncio.run.
    async def run():
        proto = _bare_proto()
        tx = sample_full_tx()
        payload = PREAMBLE + _framed(encode_frame_tx(tx, False, [], []))
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=payload, end_stream=False
            )
        )
        assert proto.full.qsize() == 1
        got = _get_full_nowait(proto)
        assert isinstance(got, FullTxV2)
        assert got.tx == tx
        await proto._preamble_gate.wait()  # must not raise -- preamble verified

    asyncio.run(run())


def test_a_stream_fin_before_the_preamble_completes_fails_the_gate_not_hangs():
    # The connection stays UP -- only the uni stream FINs. Nothing else will
    # ever unblock `subscribe_full`, so if _end_full_stream leaves the gate
    # pending here the caller waits forever on a live connection. This is the
    # same silent-hang shape as the ack-FIN bug, one stream over.
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=PREAMBLE[:3], end_stream=True
            )
        )
        with pytest.raises(BadPreamble):
            await asyncio.wait_for(proto._preamble_gate.wait(), timeout=1.0)

    asyncio.run(run())


def test_a_stream_fin_with_no_bytes_at_all_fails_the_gate():
    # The server accepted the subscribe and opened nothing: same failure for a
    # caller blocked on the preamble, and `_full_state` is still None here.
    async def run():
        proto = _bare_proto()
        proto._end_full_stream()
        with pytest.raises(BadPreamble):
            await asyncio.wait_for(proto._preamble_gate.wait(), timeout=1.0)
        assert isinstance(_get_full_nowait(proto), BadPreamble)

    asyncio.run(run())


def test_quic_event_received_a_bad_preamble_poisons_the_stream_and_fails_the_gate():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=b"XXXXXX", end_stream=False
            )
        )
        assert proto._full_poisoned is True
        got = _get_full_nowait(proto)
        assert isinstance(got, BadPreamble)
        with pytest.raises(BadPreamble):
            await proto._preamble_gate.wait()

        # A poisoned stream must ignore further bytes rather than
        # reinterpreting them as fresh frames from a corrupted offset.
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=PREAMBLE, end_stream=False
            )
        )
        assert proto.full.qsize() == 0

    asyncio.run(run())


def test_complete_bad_preamble_is_not_reclassified_as_truncation_on_close():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=b"XXXXXX",
                end_stream=False,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=0,
                frame_type=None,
                reason_phrase="invalid full-tx stream",
            )
        )

        got = _get_full_nowait(proto)
        assert isinstance(got, BadPreamble)
        assert not isinstance(got, PulseStreamTruncated)
        with pytest.raises(BadPreamble) as gate_error:
            await proto._preamble_gate.wait()
        assert gate_error.value is got

    asyncio.run(run())


def test_quic_event_received_a_malformed_frame_is_pushed_not_swallowed():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=PREAMBLE, end_stream=False
            )
        )
        bad = _framed(bytes([MSG_TX, 0]))  # too short to hold a full-tx prefix
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=bad, end_stream=False
            )
        )
        assert proto._full_poisoned is True
        got = _get_full_nowait(proto)
        assert isinstance(got, BadFrame)

    asyncio.run(run())


def test_quic_event_received_ack_stream_resolves_the_waiting_future():
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        ack_body = b'{"type":"ack","ok":true,"v":2}'
        payload = struct.pack(">I", len(ack_body)) + ack_body
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID, data=payload, end_stream=True
            )
        )
        got = await fut
        assert got == ack_body

    asyncio.run(run())


def test_connection_close_preserves_code_even_when_a_frame_was_partial():
    # A frame whose 4-byte length prefix arrived but whose body never did is
    # truncated, not a clean close: the sender declared a body length and then
    # closed before delivering all of it.
    async def run():
        proto = _bare_proto()
        tx = sample_full_tx()
        whole = _framed(encode_frame_tx(tx, False, [], []))
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE + whole + whole[:-3],  # last frame cut short
                end_stream=False,
            )
        )
        assert _get_full_nowait(proto).tx == tx, "the COMPLETE frame still arrives"
        proto.quic_event_received(
            ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )
        got = _get_full_nowait(proto)
        assert isinstance(got, PulseStreamTruncated)
        assert got.close == CloseInfo(0, "")
        assert isinstance(got.truncation, BadFrame)
        assert got.__cause__ is got.truncation

    asyncio.run(run())


def test_connection_close_preserves_close_and_incomplete_preamble_errors():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE[:3],
                end_stream=False,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=3,
                frame_type=None,
                reason_phrase="upstream unavailable",
            )
        )

        got = _get_full_nowait(proto)
        assert isinstance(got, PulseStreamTruncated)
        assert got.close == CloseInfo(3, "upstream unavailable")
        assert isinstance(got.truncation, BadPreamble)
        assert got.__cause__ is got.truncation
        with pytest.raises(PulseStreamTruncated) as gate_error:
            await proto._preamble_gate.wait()
        assert gate_error.value is got

    asyncio.run(run())


def test_fin_then_connection_close_upgrades_a_partial_frame_terminal():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE + struct.pack(">I", 10) + b"ab",
                end_stream=True,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=3,
                frame_type=None,
                reason_phrase="capacity",
            )
        )

        got = _get_full_nowait(proto)
        assert isinstance(got, PulseStreamTruncated)
        assert got.close == CloseInfo(3, "capacity")
        assert isinstance(got.truncation, BadFrame)
        assert got.__cause__ is got.truncation

    asyncio.run(run())


def test_fin_then_connection_close_upgrades_an_incomplete_preamble_terminal():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE[:3],
                end_stream=True,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=3,
                frame_type=None,
                reason_phrase="capacity",
            )
        )

        got = _get_full_nowait(proto)
        assert isinstance(got, PulseStreamTruncated)
        assert got.close == CloseInfo(3, "capacity")
        assert isinstance(got.truncation, BadPreamble)
        with pytest.raises(PulseStreamTruncated) as gate_error:
            await proto._preamble_gate.wait()
        assert gate_error.value is got

    asyncio.run(run())


def test_quic_event_received_a_frame_boundary_close_is_typed_not_generic_eof():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE
                + _framed(encode_frame_tx(sample_full_tx(), False, [], [])),
                end_stream=False,
            )
        )
        _get_full_nowait(proto)  # the tx
        proto.quic_event_received(
            ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )
        got = _get_full_nowait(proto)
        assert isinstance(got, PulseConnectionClosed)
        assert got.code == 0

    asyncio.run(run())


def test_quic_event_received_uni_stream_fin_mid_frame_is_a_bad_frame():
    # Same rule when the server FINs only the uni stream, leaving the
    # connection itself up -- no ConnectionTerminated will ever arrive.
    async def run():
        proto = _bare_proto()
        whole = _framed(encode_frame_tx(sample_full_tx(), False, [], []))
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE + whole[:-3],
                end_stream=True,
            )
        )
        got = _get_full_nowait(proto)
        assert isinstance(got, BadFrame), f"expected BadFrame, got {got!r}"

    asyncio.run(run())


def test_quic_event_received_zero_byte_fin_on_the_ack_stream_fails_the_waiter():
    # A zero-byte FIN is not an acknowledgement. The connection can remain
    # open after this stream ends, so the pending waiter must fail directly.
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID, data=b"", end_stream=True
            )
        )
        with pytest.raises(ConnectionError):
            await fut

    asyncio.run(run())


def test_quic_event_received_truncated_ack_at_fin_fails_the_waiter():
    # Same rule one step further along: a length prefix that arrives with a
    # body that never does is a failure at FIN, not an unfinished read.
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID,
                data=struct.pack(">I", 32) + b'{"type":"ack"',
                end_stream=True,
            )
        )
        with pytest.raises(ConnectionError):
            await fut

    asyncio.run(run())


def test_quic_event_received_partial_ack_without_fin_keeps_waiting():
    # The complement, so the FIN check cannot degrade into "any short read is
    # fatal": an incomplete envelope with the stream still open is normal --
    # the rest is in flight.
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        ack_body = b'{"type":"ack","ok":true,"v":2}'
        payload = struct.pack(">I", len(ack_body)) + ack_body
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID, data=payload[:6], end_stream=False
            )
        )
        assert not fut.done(), "a partial ack on an open stream is not a failure"
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID, data=payload[6:], end_stream=True
            )
        )
        assert await fut == ack_body

    asyncio.run(run())


def test_unknown_or_completed_ack_stream_data_never_allocates_a_buffer():
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(stream_id=1, data=b"x" * 100_000, end_stream=False)
        )
        proto.quic_event_received(
            StreamDataReceived(stream_id=5, data=b"y" * 100_000, end_stream=True)
        )

        completed = asyncio.get_running_loop().create_future()
        completed.set_result(b"done")
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = completed
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID,
                data=b"late",
                end_stream=True,
            )
        )
        assert proto._ack_bufs == {}

    asyncio.run(run())


def test_active_ack_stream_buffer_is_bounded_before_copying_peer_data():
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_CLIENT_BIDI_STREAM_ID,
                data=b"x" * (MAX_ACK_BYTES + 5),
                end_stream=False,
            )
        )

        with pytest.raises(BadFrame):
            await fut
        assert proto._ack_bufs == {}

    asyncio.run(run())


def test_pending_full_subscribe_receives_composite_close_for_partial_stream():
    async def run():
        proto = _bare_proto()

        class Quic:
            def get_next_available_stream_id(self):
                return _CLIENT_BIDI_STREAM_ID

            def send_stream_data(self, stream_id, body, end_stream):
                assert stream_id == _CLIENT_BIDI_STREAM_ID
                assert end_stream is True

        proto._quic = Quic()
        proto.transmit = lambda: None
        client = PulseClient(proto, token="invalid-for-test")
        subscribe = asyncio.create_task(
            client.subscribe_full(Filter.accounts("program"))
        )
        await asyncio.sleep(0)
        assert _CLIENT_BIDI_STREAM_ID in proto._ack_waiters

        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=PREAMBLE + struct.pack(">I", 10) + b"ab",
                end_stream=False,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=3,
                frame_type=None,
                reason_phrase="capacity",
            )
        )

        with pytest.raises(PulseStreamTruncated) as exc_info:
            await subscribe
        assert exc_info.value.close == CloseInfo(3, "capacity")
        assert isinstance(exc_info.value.truncation, BadFrame)

    asyncio.run(run())


def test_pending_full_subscribe_without_a_uni_stream_gets_plain_typed_close():
    async def run():
        proto = _bare_proto()

        class Quic:
            def get_next_available_stream_id(self):
                return _CLIENT_BIDI_STREAM_ID

            def send_stream_data(self, stream_id, body, end_stream):
                assert stream_id == _CLIENT_BIDI_STREAM_ID
                assert end_stream is True

        proto._quic = Quic()
        proto.transmit = lambda: None
        client = PulseClient(proto, token="invalid-for-test")
        subscribe = asyncio.create_task(
            client.subscribe_full(Filter.accounts("program"))
        )
        await asyncio.sleep(0)

        proto.quic_event_received(
            ConnectionTerminated(
                error_code=5,
                frame_type=None,
                reason_phrase="tier not entitled",
            )
        )

        with pytest.raises(PulseConnectionClosed) as exc_info:
            await subscribe
        assert type(exc_info.value) is PulseConnectionClosed
        assert exc_info.value.close == CloseInfo(5, "tier not entitled")
        assert exc_info.value.retry_disposition is RetryDisposition.NON_RETRYABLE

    asyncio.run(run())


def test_pending_full_subscribe_prefers_complete_bad_preamble_over_local_close():
    async def run():
        proto = _bare_proto()

        class Quic:
            def get_next_available_stream_id(self):
                return _CLIENT_BIDI_STREAM_ID

            def send_stream_data(self, stream_id, body, end_stream):
                assert stream_id == _CLIENT_BIDI_STREAM_ID
                assert end_stream is True

        proto._quic = Quic()
        proto.transmit = lambda: None
        client = PulseClient(proto, token="test-token")
        subscribe = asyncio.create_task(
            client.subscribe_full(Filter.accounts("program"))
        )
        await asyncio.sleep(0)

        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID,
                data=b"XXXXXX",
                end_stream=False,
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=0,
                frame_type=None,
                reason_phrase="invalid full-tx stream",
            )
        )

        with pytest.raises(BadPreamble) as exc_info:
            await subscribe
        assert not isinstance(exc_info.value, PulseConnectionClosed)
        assert proto.close_info == CloseInfo(0, "invalid full-tx stream")
        assert _get_full_nowait(proto) is exc_info.value

    asyncio.run(run())


def test_quic_event_received_connection_terminated_unblocks_both_queues_and_the_gate():
    async def run():
        proto = _bare_proto()
        fut = asyncio.get_running_loop().create_future()
        proto._ack_waiters[_CLIENT_BIDI_STREAM_ID] = fut
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=3,
                frame_type=None,
                reason_phrase="max concurrent subscriptions reached",
            )
        )
        sig_error = proto.datagrams.get_nowait()
        full_error = _get_full_nowait(proto)
        assert isinstance(sig_error, PulseConnectionClosed)
        assert isinstance(full_error, PulseConnectionClosed)
        assert sig_error.code == full_error.code == 3
        assert sig_error.retry_disposition is RetryDisposition.TRANSIENT
        with pytest.raises(PulseConnectionClosed) as ack_exc:
            await fut
        assert ack_exc.value.reason == "max concurrent subscriptions reached"
        with pytest.raises(PulseConnectionClosed):
            await proto._preamble_gate.wait()

    asyncio.run(run())


def test_quic_event_received_connection_terminated_after_healthy_preamble_leaves_gate_ok():
    # A subscription that already completed its preamble and ran for a while
    # must not have that success retroactively turned into an error just
    # because the connection eventually closed.
    async def run():
        proto = _bare_proto()
        proto.quic_event_received(
            StreamDataReceived(
                stream_id=_SERVER_UNI_STREAM_ID, data=PREAMBLE, end_stream=False
            )
        )
        proto.quic_event_received(
            ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )
        await proto._preamble_gate.wait()  # must not raise

    asyncio.run(run())


def test_sig_first_only_connection_close_does_not_log_an_unretrieved_preamble_exception():
    # THE regression this fix closes: a sig-first-only subscriber never
    # calls subscribe_full()/awaits the preamble gate at all, so a plain,
    # ordinary connection close must not spam an ERROR-level "exception was
    # never retrieved" traceback about a BadPreamble that never meant
    # anything to this connection.
    async def run():
        loop = asyncio.get_running_loop()
        contexts = []
        loop.set_exception_handler(lambda _loop, context: contexts.append(context))

        proto = _bare_proto()
        proto.quic_event_received(
            ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )
        del proto
        gc.collect()
        await asyncio.sleep(0)

        assert contexts == [], f"unexpected exception-handler calls: {contexts}"

    asyncio.run(run())


# ---- the swallow removal: THE bug this task exists to fix --------------------


def _client_with_injected_stream(data: bytes):
    """Test-only harness: drives the SAME decode path the real async client
    uses (`_next_tx_frame`) directly over an in-memory buffer, without a live
    QUIC connection. Deliberately preamble-agnostic -- preamble handling is
    `_FullStreamState`'s job and is covered separately above; this harness
    isolates the frame-decode-failure-must-propagate behavior on its own.
    """
    buf = bytearray(data)
    holder = [None]

    class _Iter:
        def __iter__(self):
            return self

        def __next__(self):
            tx = _next_tx_frame(buf, holder)
            if tx is None:
                raise StopIteration
            return tx

    return _Iter()


def test_bad_frame_is_raised_not_swallowed():
    """A client fed an unparseable frame must fail loudly.

    Silent loss here is worse than a crash: the stream stays open, the
    iterator never yields, and nothing is logged.

    Note: the brief's original example bytes for this test,
    ``b"\\x00\\x00\\x00\\x02\\xff\\xff"``, decode as msg_type=0xFF -- an
    UNKNOWN message type, which "The wire, precisely" section requires this
    decoder to SKIP, not reject (see `test_unknown_msg_type_is_reported_not_
    rejected` in test_frame.py, and Rust's own
    `unknown_msg_type_is_reported_not_rejected`). Skipping that frame and
    then hitting a clean end of buffer would raise `StopIteration`, not
    `BadFrame` -- so those bytes do not actually exercise "a client fed an
    unparseable frame". Substituted a genuinely malformed frame instead
    (msg_type=MSG_TX with a body too short to hold a full-tx prefix), which
    keeps the same length prefix (2) and the same intent while actually
    triggering the decode failure the test's name describes.
    """
    c = _client_with_injected_stream(bytes([0, 0, 0, 2, MSG_TX, 0]))
    with pytest.raises(BadFrame):
        next(iter(c))


# ---- the join: FullSub/SigFirstSub __anext__ ---------------------------------
#
# `_next_tx_frame` raising and `quic_event_received` pushing the exception
# onto `proto.full` are only half of "a bad frame is raised, not swallowed":
# the other half is `FullSub.__anext__` at the consumer's own `async for`
# boundary, which is what decides whether that reaches the caller as a raise
# (correct) or an indistinguishable-from-clean end of iteration (the
# original bug, one layer up). Nothing above this line calls `__anext__` at
# all, so cover it directly, plus the sibling None-sentinel -> clean-stop
# path on both subs.


def test_full_sub_anext_raises_a_pre_queued_bad_frame():
    async def run():
        proto = _bare_proto()
        proto.full.put_nowait(BadFrame("boom"))
        sub = FullSub(proto)
        with pytest.raises(BadFrame):
            await sub.__anext__()

    asyncio.run(run())


def test_full_sub_anext_raises_a_pre_queued_bad_preamble():
    async def run():
        proto = _bare_proto()
        proto.full.put_nowait(BadPreamble("boom"))
        sub = FullSub(proto)
        with pytest.raises(BadPreamble):
            await sub.__anext__()

    asyncio.run(run())


def test_full_sub_anext_returns_a_real_transaction():
    async def run():
        proto = _bare_proto()
        frame = FullTxV2(tx=sample_full_tx())
        proto.full.put_nowait(frame)
        sub = FullSub(proto)
        got = await sub.__anext__()
        assert got is frame

    asyncio.run(run())


def test_full_sub_anext_stops_cleanly_on_the_none_sentinel():
    async def run():
        proto = _bare_proto()
        proto.full.put_nowait(None)
        sub = FullSub(proto)
        with pytest.raises(StopAsyncIteration):
            await sub.__anext__()

    asyncio.run(run())


def test_sig_first_sub_anext_stops_cleanly_on_the_none_sentinel():
    async def run():
        proto = _bare_proto()
        proto.datagrams.put_nowait(None)
        sub = SigFirstSub(proto)
        with pytest.raises(StopAsyncIteration):
            await sub.__anext__()

    asyncio.run(run())


def test_sig_first_sub_anext_returns_a_real_item():
    async def run():
        proto = _bare_proto()
        item = SigFirstItem(slot=1, seq=2, signature=b"\x00" * 64)
        proto.datagrams.put_nowait(item)
        sub = SigFirstSub(proto)
        got = await sub.__anext__()
        assert got is item

    asyncio.run(run())
