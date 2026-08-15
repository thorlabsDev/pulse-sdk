"""Public SDK security, lifecycle, and bounded-resource regression tests."""

from __future__ import annotations

import asyncio
import inspect
import ssl
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import certifi
import pytest
from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived

import thornode_pulse
from thornode_pulse.client import (
    AckTimeout,
    AlreadySubscribedError,
    CertificatePinMismatch,
    CloseInfo,
    Filter,
    FullQueueOverflow,
    FullStreamTimeout,
    FullSub,
    Heartbeat,
    MissingVersion,
    PreambleTimeout,
    PulseClient,
    PulseConnectionClosed,
    RetryDisposition,
    SigFirstSub,
    Timeouts,
    _build_quic_configuration,
    _check_ack,
    _GapTracker,
    _normalize_certificate_pin,
    _parse_ack,
    _parse_target,
    _PreambleGate,
    _PulseProtocol,
    _verify_certificate_pin,
)
from thornode_pulse.frame import FullTxV2, encode_dg_heartbeat


def _protocol_stub(
    *,
    timeouts=None,
    sig_queue_len: int = 4,
    full_queue_len: int = 4,
) -> _PulseProtocol:
    proto = _PulseProtocol.__new__(_PulseProtocol)
    proto.timeouts = timeouts or Timeouts()
    proto.sig_queue_len = sig_queue_len
    proto.full_queue_len = full_queue_len
    proto.datagrams = asyncio.Queue(maxsize=sig_queue_len)
    proto.full = asyncio.Queue(maxsize=full_queue_len + 1)
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


def test_distribution_and_import_names_are_public_names():
    assert Path(thornode_pulse.__file__).parent.name == "thornode_pulse"
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    metadata = pyproject.read_text(encoding="utf-8")
    assert 'name = "thornode-pulse"' in metadata
    assert 'include = ["thornode_pulse*"]' in metadata


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("pulse.example.com:8443", ("pulse.example.com", 8443)),
        ("192.0.2.10:443", ("192.0.2.10", 443)),
        ("[2001:db8::10]:8443", ("2001:db8::10", 8443)),
    ],
)
def test_dashboard_target_parser_is_ipv6_safe(target, expected):
    assert _parse_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "pulse.example.com",
        "pulse.example.com:",
        ":8443",
        "pulse.example.com:not-a-port",
        "pulse.example.com:0",
        "pulse.example.com:65536",
        "2001:db8::10:8443",
        "[2001:db8::10]8443",
        "quic://pulse.example.com:8443",
        " pulse.example.com:8443",
    ],
)
def test_dashboard_target_parser_rejects_ambiguous_or_invalid_values(target):
    with pytest.raises(ValueError):
        _parse_target(target)


def test_connect_pulse_public_signature_takes_one_target_not_host_and_port():
    parameters = inspect.signature(thornode_pulse.connect_pulse).parameters
    assert list(parameters)[:2] == ["target", "token"]
    assert parameters["token"].kind is inspect.Parameter.KEYWORD_ONLY


def test_tls_defaults_verify_chain_and_hostname_with_bundled_roots():
    config = _build_quic_configuration("pulse.example.com")
    assert config.verify_mode == ssl.CERT_REQUIRED
    assert config.server_name == "pulse.example.com"
    assert config.cafile == certifi.where()
    assert config.capath is None
    assert config.cadata is None


def test_tls_custom_ca_augments_bundled_roots_and_server_name_can_be_overridden():
    custom = b"-----BEGIN CERTIFICATE-----\nprivate-ca\n-----END CERTIFICATE-----\n"
    config = _build_quic_configuration(
        "192.0.2.10",
        server_name="pulse.example.com",
        ca_data=custom,
    )
    assert config.verify_mode == ssl.CERT_REQUIRED
    assert config.server_name == "pulse.example.com"
    assert config.cafile == certifi.where()
    assert config.cadata == custom


def test_tls_custom_ca_file_is_added_without_replacing_bundled_roots(tmp_path):
    custom = b"-----BEGIN CERTIFICATE-----\nprivate-ca\n-----END CERTIFICATE-----\n"
    custom_path = tmp_path / "private-ca.pem"
    custom_path.write_bytes(custom)

    config = _build_quic_configuration(
        "pulse.example.com",
        ca_file=str(custom_path),
    )

    assert config.verify_mode == ssl.CERT_REQUIRED
    assert config.cafile == certifi.where()
    assert config.cadata == custom


def test_insecure_local_development_is_explicit_and_loopback_only():
    local = _build_quic_configuration(
        "127.0.0.1",
        insecure_local_development=True,
    )
    assert local.verify_mode == ssl.CERT_NONE

    with pytest.raises(ValueError, match="loopback"):
        _build_quic_configuration(
            "pulse.example.com",
            insecure_local_development=True,
        )
    with pytest.raises(ValueError, match="custom CA"):
        _build_quic_configuration(
            "localhost",
            ca_data=b"unused",
            insecure_local_development=True,
        )


def test_certificate_pin_accepts_common_hex_forms_and_mismatch_is_typed():
    digest = bytes(range(32))

    class Certificate:
        def fingerprint(self, algorithm):
            assert algorithm.name == "sha256"
            return digest

    proto = SimpleNamespace(
        _quic=SimpleNamespace(
            tls=SimpleNamespace(_peer_certificate=Certificate()),
        )
    )
    colon_hex = ":".join(f"{byte:02x}" for byte in digest)
    assert _normalize_certificate_pin(f"sha256/{colon_hex}") == digest.hex()
    _verify_certificate_pin(proto, digest)

    with pytest.raises(CertificatePinMismatch) as exc_info:
        _verify_certificate_pin(proto, "00" * 32)
    assert exc_info.value.actual == digest.hex()


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (1, RetryDisposition.NON_RETRYABLE),
        (2, RetryDisposition.CREDENTIALS_REQUIRED),
        (3, RetryDisposition.TRANSIENT),
        (4, RetryDisposition.NON_RETRYABLE),
        (5, RetryDisposition.NON_RETRYABLE),
    ],
)
def test_close_retry_classification(code, expected):
    close = CloseInfo(code, "server reason")
    assert close.retry_disposition is expected
    assert close.retryable is (expected is RetryDisposition.TRANSIENT)


def test_control_error_envelope_surfaces_typed_close_code_and_reason():
    ack = _parse_ack(
        b'{"type":"error","code":4,"reason":"unsupported protocol version"}'
    )
    with pytest.raises(PulseConnectionClosed) as exc_info:
        _check_ack(ack)
    assert exc_info.value.close == CloseInfo(4, "unsupported protocol version")


def test_control_error_envelope_without_an_integer_code_is_a_bad_frame():
    with pytest.raises(thornode_pulse.BadFrame):
        _check_ack(_parse_ack(b'{"type":"error","reason":"missing code"}'))

    with pytest.raises(thornode_pulse.BadFrame):
        _parse_ack(b'{"type":"error","code":true,"reason":"bad code"}')


def test_initial_subscribe_requires_v2_but_update_ack_may_omit_version():
    async def run():
        proto = _protocol_stub()

        async def initial_without_version(control):
            return b'{"type":"ack","ok":true}'

        proto.send_control = initial_without_version
        client = PulseClient(proto, token="secret")
        with pytest.raises(MissingVersion):
            await client.subscribe_sig_first(Filter.accounts("program"))
        assert client.subscription_kind == "sig-first"
        with pytest.raises(AlreadySubscribedError):
            await client.subscribe_full(Filter.accounts("other-program"))

        sub = SigFirstSub(proto)
        ack = await sub.update_filter(Filter.accounts("updated-program"))
        assert ack.ok is True
        assert ack.v is None

    asyncio.run(run())


def test_connection_close_reaches_both_subscription_iterators_as_typed_error():
    async def run():
        proto = _protocol_stub()
        sig = SigFirstSub(proto)
        full = FullSub(proto)
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=5,
                frame_type=None,
                reason_phrase="tier pro is not entitled",
            )
        )

        with pytest.raises(PulseConnectionClosed) as sig_exc:
            await sig.__anext__()
        with pytest.raises(PulseConnectionClosed) as full_exc:
            await full.__anext__()
        assert sig_exc.value.code == full_exc.value.code == 5
        with pytest.raises(PulseConnectionClosed) as repeated_sig:
            await sig.__anext__()
        with pytest.raises(PulseConnectionClosed) as repeated_full:
            await full.__anext__()
        assert repeated_sig.value is sig_exc.value
        assert repeated_full.value is full_exc.value
        assert (
            sig.close_info
            == full.close_info
            == CloseInfo(
                5,
                "tier pro is not entitled",
            )
        )

    asyncio.run(run())


def test_transport_close_is_not_classified_as_a_pulse_application_code():
    async def run():
        proto = _protocol_stub()
        proto.quic_event_received(
            ConnectionTerminated(
                error_code=1,
                frame_type=0,
                reason_phrase="Idle timeout",
            )
        )

        error = proto.datagrams.get_nowait()
        assert isinstance(error, PulseConnectionClosed)
        assert error.close == CloseInfo(1, "Idle timeout", frame_type=0)
        assert error.close.is_application_close is False
        assert error.close.meaning == "QUIC transport close"
        assert error.retry_disposition is RetryDisposition.UNKNOWN
        assert error.retryable is False

    asyncio.run(run())


def test_one_feed_per_connection_and_sig_first_has_no_fields_parameter():
    async def run():
        proto = _protocol_stub()
        controls = []

        async def send_control(control):
            controls.append(control)
            return b'{"type":"ack","ok":true,"v":2}'

        proto.send_control = send_control
        client = PulseClient(proto, token="secret")
        sub = await client.subscribe_sig_first(Filter.accounts("program"))
        assert isinstance(sub, SigFirstSub)
        assert controls[0]["token"] == "secret"
        assert controls[0]["full"] is False
        assert client.subscription_kind == "sig-first"

        with pytest.raises(AlreadySubscribedError):
            await client.subscribe_sig_first(Filter.accounts("other"))
        with pytest.raises(AlreadySubscribedError):
            await client.subscribe_full(Filter.accounts("other"))

    asyncio.run(run())
    assert "fields" not in inspect.signature(PulseClient.subscribe_sig_first).parameters
    assert "fields" not in inspect.signature(SigFirstSub.update_filter).parameters


def test_filter_is_immutable_and_sig_first_rejects_enrichment_fields():
    original = Filter.accounts("a")
    updated = original.excluding("b").requiring("c").with_vote(True)
    assert original.account_exclude == ()
    assert updated.account_exclude == ("b",)
    assert updated.account_required == ("c",)
    assert updated.vote is True
    with pytest.raises(FrozenInstanceError):
        original.vote = False
    with pytest.raises(ValueError, match="full-tx"):
        original._to_control(False, fields=("alt",))


def test_full_queue_is_bounded_and_overflow_is_loud_after_queued_frames():
    async def run():
        proto = _protocol_stub(full_queue_len=2)
        proto._full_last_activity = asyncio.get_running_loop().time()
        first = FullTxV2(tx=None)  # decoding is irrelevant to queue behavior
        second = FullTxV2(tx=None)
        third = FullTxV2(tx=None)

        assert proto._enqueue_full_tx(first)
        assert proto._enqueue_full_tx(second)
        assert not proto._enqueue_full_tx(third)
        sub = FullSub(proto)
        assert sub.metrics.queued == 2
        assert sub.metrics.queue_capacity == 2
        assert sub.metrics.dropped == 1
        assert await sub.__anext__() is first
        assert await sub.__anext__() is second
        with pytest.raises(FullQueueOverflow) as exc_info:
            await sub.__anext__()
        assert exc_info.value.capacity == 2

    asyncio.run(run())


def test_control_ack_wait_is_bounded():
    async def run():
        proto = _protocol_stub(
            timeouts=Timeouts(ack=0.01, preamble=1, full_stream_idle=1)
        )

        class Quic:
            def get_next_available_stream_id(self):
                return 0

            def send_stream_data(self, stream_id, body, end_stream):
                assert stream_id == 0
                assert end_stream is True

        proto._quic = Quic()
        proto.transmit = lambda: None
        with pytest.raises(AckTimeout):
            await proto.send_control({"full": False, "v": 2, "fields": []})

    asyncio.run(run())


def test_full_preamble_wait_is_bounded():
    async def run():
        proto = _protocol_stub(
            timeouts=Timeouts(ack=1, preamble=0.01, full_stream_idle=1)
        )

        async def send_control(control):
            return b'{"type":"ack","ok":true,"v":2}'

        proto.send_control = send_control
        client = PulseClient(proto, token="secret")
        with pytest.raises(PreambleTimeout):
            await client.subscribe_full(Filter.accounts("program"))
        assert client.subscription_kind == "full"

    asyncio.run(run())


def test_full_stream_idle_wait_is_bounded_and_terminal():
    async def run():
        proto = _protocol_stub(
            timeouts=Timeouts(ack=1, preamble=1, full_stream_idle=0.01)
        )
        proto._full_last_activity = asyncio.get_running_loop().time()
        sub = FullSub(proto)
        with pytest.raises(FullStreamTimeout) as first:
            await sub.__anext__()
        with pytest.raises(FullStreamTimeout) as second:
            await sub.__anext__()
        assert first.value is second.value

    asyncio.run(run())


def test_sig_first_metrics_expose_queue_drop_and_heartbeat_state():
    async def run():
        proto = _protocol_stub(sig_queue_len=2)
        proto.quic_event_received(
            DatagramFrameReceived(data=encode_dg_heartbeat(123, 9))
        )
        sub = SigFirstSub(proto)
        assert sub.metrics == thornode_pulse.SubscriptionMetrics(
            dropped=0,
            queued=0,
            queue_capacity=2,
            heartbeats=1,
            last_heartbeat=Heartbeat(123, 9),
        )

    asyncio.run(run())


@pytest.mark.parametrize("field", ["ack", "preamble", "full_stream_idle"])
def test_timeouts_must_be_positive_and_finite(field):
    values = {"ack": 1, "preamble": 1, "full_stream_idle": 1}
    values[field] = 0
    with pytest.raises(ValueError):
        Timeouts(**values)
