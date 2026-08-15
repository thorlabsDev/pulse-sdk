"""Async client for the Pulse QUIC transaction stream (aioquic),
wire v2.

Two feeds are available, and exactly one can be selected per connection (the
server selects the feed from the first control message, which this SDK always
negotiates to wire v2 -- :data:`thornode_pulse.frame.WIRE_VERSION`):

* :meth:`PulseClient.subscribe_sig_first` -- the low-latency **sig-first**
  tier. One QUIC DATAGRAM per tx (:class:`SigFirstItem`: slot, per-subscriber
  ``seq``, signature), fire-and-forget, no head-of-line blocking.
  :attr:`SigFirstSub.gaps` counts sequence numbers this subscriber may not
  have received (see its docstring for the exact, honest guarantee).
* :meth:`PulseClient.subscribe_full` -- the **full-tx** feed. A single ordered
  QUIC stream that opens with a 6-byte preamble (this SDK
  reads and verifies it before the subscription is ever handed back -- see
  :class:`thornode_pulse.frame.BadPreamble`), then length-delimited,
  fully-decoded transaction frames (:class:`thornode_pulse.frame.FullTxV2`).

Both tiers also carry periodic heartbeats (idle-stream liveness, plus
``highest_seq`` -- the highest sequence number assigned to this subscriber so
far; :data:`NO_SEQ_ASSIGNED` means none yet). A heartbeat is folded into
:attr:`FullSub.heartbeat` / :attr:`SigFirstSub.gaps` rather than handed back
as an item, and a message or datagram type this SDK doesn't recognize is
skipped rather than treated as an error -- that is what keeps a future wire
addition from breaking this client.

**A decode error that is not an unrecognized type is fatal to the stream.**
:class:`thornode_pulse.frame.BadFrame` propagates out of the iterator because
a client cannot safely resynchronize after malformed or truncated framing.

The wire protocol is specified in ``../../docs/PROTOCOL.md``.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import math
import ssl
import struct
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import partial
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Sequence, Tuple, Union, cast

import certifi
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    QuicEvent,
    StreamDataReceived,
)
from cryptography.hazmat.primitives import hashes

from .frame import (
    MAX_FULL_TX_BODY,
    PREAMBLE,
    WIRE_VERSION,
    BadFrame,
    BadPreamble,
    DatagramHeartbeat,
    DatagramSigFirst,
    FrameHeartbeat,
    FullTxV2,
    _verify_preamble,
    decode_datagram,
    decode_frame,
)

__all__ = [
    "ACK_TIMEOUT",
    "FULL_QUEUE_LEN",
    "FULL_STREAM_TIMEOUT",
    "PREAMBLE_TIMEOUT",
    "Ack",
    "AckTimeout",
    "AlreadySubscribedError",
    "CertificatePinMismatch",
    "CloseInfo",
    "Filter",
    "FullSub",
    "FullQueueOverflow",
    "FullStreamTimeout",
    "Heartbeat",
    "MissingVersion",
    "NO_SEQ_ASSIGNED",
    "PreambleTimeout",
    "PulseClient",
    "PulseConnectionClosed",
    "PulseStreamTruncated",
    "Rejected",
    "RetryDisposition",
    "SIG_QUEUE_LEN",
    "SigFirstItem",
    "SigFirstSub",
    "SubscriptionMetrics",
    "Timeouts",
    "VersionMismatch",
    "connect_pulse",
]


@dataclass(frozen=True)
class Filter:
    """Immutable account-predicate subscription model.

    An empty filter requests the unfiltered non-vote feed. The access selected
    for the connection determines whether that feed is available.
    """

    account_include: Tuple[str, ...] = field(default_factory=tuple)
    account_exclude: Tuple[str, ...] = field(default_factory=tuple)
    account_required: Tuple[str, ...] = field(default_factory=tuple)
    # Vote-transaction inclusion (Yellowstone parity): None omits the field, in
    # which case the server default applies -- exclude (drop) votes. False
    # explicitly excludes; True includes. The predicate ANDs with the account
    # ones (account_include=[Vote111...] with vote=False yields the empty set).
    vote: Optional[bool] = None

    def __post_init__(self) -> None:
        # Lists are accepted for convenience but copied so a frozen Filter
        # cannot be mutated later through a caller-owned reference.
        object.__setattr__(self, "account_include", tuple(self.account_include))
        object.__setattr__(self, "account_exclude", tuple(self.account_exclude))
        object.__setattr__(self, "account_required", tuple(self.account_required))

    def _to_control(
        self,
        full: bool,
        token: Optional[str] = None,
        fields: Sequence[str] = (),
    ) -> dict:
        """Builds the JSON control message. `v` always declares wire v2
        (this SDK speaks no other version); `full` selects the tier and is
        only honored on the connection's FIRST control message; `fields`
        opts into per-frame enrichment groups (currently just `"alt"`) and
        is only meaningful on the full-tx tier -- the sig-first tier
        carries no enrichment under any subscription, so the server simply
        ignores it there. `fields` is always serialized as a JSON array
        (`[]`, never a bare `null`, when empty)."""
        if not full and fields:
            raise ValueError("fields are only supported by the full-tx feed")
        d: dict = {"full": full, "v": WIRE_VERSION, "fields": list(fields)}
        if token:
            d["token"] = token
        if self.account_include:
            d["account_include"] = list(self.account_include)
        if self.account_exclude:
            d["account_exclude"] = list(self.account_exclude)
        if self.account_required:
            d["account_required"] = list(self.account_required)
        if self.vote is not None:
            d["vote"] = self.vote
        return d

    @staticmethod
    def all() -> "Filter":
        return Filter()

    @staticmethod
    def accounts(*keys: str) -> "Filter":
        return Filter(account_include=keys)

    def with_vote(self, include: bool) -> "Filter":
        """Set vote-transaction inclusion (Yellowstone parity). True opts into
        votes; False explicitly excludes them. Without it the field is omitted
        and the server default applies (exclude/drop votes). Returns a new
        filter, so ``Filter`` values remain safe to share."""
        return replace(self, vote=include)

    def excluding(self, *keys: str) -> "Filter":
        """Return a copy that excludes transactions touching ``keys``."""
        return replace(self, account_exclude=self.account_exclude + tuple(keys))

    def requiring(self, *keys: str) -> "Filter":
        """Return a copy that requires every key in ``keys``."""
        return replace(self, account_required=self.account_required + tuple(keys))


class RetryDisposition(str, Enum):
    """Whether retrying the same subscription can succeed."""

    NORMAL = "normal"
    TRANSIENT = "transient"
    CREDENTIALS_REQUIRED = "credentials_required"
    NON_RETRYABLE = "non_retryable"
    UNKNOWN = "unknown"


_CLOSE_MEANINGS = {
    0: "normal close",
    1: "invalid control message",
    2: "unauthenticated",
    3: "quota exceeded",
    4: "unsupported protocol version",
    5: "tier not entitled",
}


@dataclass(frozen=True)
class CloseInfo:
    """A QUIC close, preserving whether it was application or transport.

    ``frame_type`` is ``None`` for Pulse application closes. aioquic supplies
    the triggering QUIC frame type for transport closes, whose numeric error
    codes must not be interpreted as Pulse application-close codes.
    """

    code: int
    reason: str = ""
    frame_type: Optional[int] = None

    @property
    def is_application_close(self) -> bool:
        return self.frame_type is None

    @property
    def meaning(self) -> str:
        if not self.is_application_close:
            return "QUIC transport close"
        return _CLOSE_MEANINGS.get(self.code, "unknown application close")

    @property
    def retry_disposition(self) -> RetryDisposition:
        if not self.is_application_close:
            return RetryDisposition.UNKNOWN
        if self.code == 0:
            return RetryDisposition.NORMAL
        if self.code == 3:
            return RetryDisposition.TRANSIENT
        if self.code == 2:
            return RetryDisposition.CREDENTIALS_REQUIRED
        if self.code in (1, 4, 5):
            return RetryDisposition.NON_RETRYABLE
        return RetryDisposition.UNKNOWN

    @property
    def retryable(self) -> bool:
        return self.retry_disposition is RetryDisposition.TRANSIENT


class PulseConnectionClosed(ConnectionError):
    """Terminal connection error preserving the server's code and reason."""

    def __init__(self, close: CloseInfo):
        self.close = close
        self.code = close.code
        self.reason = close.reason
        self.retry_disposition = close.retry_disposition
        self.retryable = close.retryable
        detail = f": {close.reason}" if close.reason else ""
        super().__init__(
            f"pulse connection closed with code {close.code} "
            f"({close.meaning}, {close.retry_disposition.value}){detail}"
        )


class PulseStreamTruncated(PulseConnectionClosed):
    """Connection close plus the partial preamble/frame it interrupted."""

    def __init__(
        self,
        close: CloseInfo,
        truncation: Union[BadFrame, BadPreamble],
    ):
        self.truncation = truncation
        super().__init__(close)
        self.__cause__ = truncation

    def __str__(self) -> str:
        return f"{super().__str__()}; full-tx stream truncated: {self.truncation}"


class AlreadySubscribedError(RuntimeError):
    """Raised when a second feed is selected on the same connection."""


class CertificatePinMismatch(ssl.SSLCertVerificationError):
    """Raised when the peer certificate does not match the configured pin."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            "Pulse certificate SHA-256 pin mismatch: "
            f"expected {expected}, received {actual}"
        )


@dataclass(frozen=True)
class Heartbeat:
    """Latest liveness and subscriber sequence watermark from the server."""

    server_ts_ms: int
    highest_seq: int


@dataclass(frozen=True)
class SubscriptionMetrics:
    """A point-in-time snapshot of local queue and heartbeat counters."""

    dropped: int
    queued: int
    queue_capacity: int
    heartbeats: int
    last_heartbeat: Optional[Heartbeat]


# ---- control-channel ack -----------------------------------------------------


@dataclass(frozen=True)
class Ack:
    """A parsed ``{"type":"ack","ok":bool,...}`` control-channel envelope --
    the server's answer to any control message (first or update)."""

    ok: bool
    #: Present when `ok` is False: why the message was rejected.
    reason: Optional[str] = None
    #: Present only on the FIRST control message's ack: the wire version the
    #: server actually negotiated (`min(client_max, SERVER_WIRE_VERSION)`).
    v: Optional[int] = None
    #: Envelope kind. The server uses ``error`` for code-4 negotiation closes.
    #: Missing and unknown kinds are retained for validation as bad frames.
    kind: Optional[str] = None
    #: Application close code carried by an ``error`` envelope.
    code: Optional[int] = None


class Rejected(Exception):
    """Raised when the server answers a control message with
    ``{"ok": false, ...}``. Carries the server's stated reason so a caller
    learns *why* a subscribe or `update_filter` call was refused, rather
    than getting no error and simply receiving nothing forever."""

    def __init__(self, reason: str):
        super().__init__(f"control message rejected: {reason}")
        self.reason = reason


class VersionMismatch(Exception):
    """Raised when the server's first-control-message ack names a
    negotiated wire version this SDK does not speak. In practice the server
    closes the connection outright rather than acking success with a
    version it can't actually serve, so this is a defensive backstop, not
    the primary version-mismatch signal.

    For the sig-first tier this ack is the ONLY channel that carries the
    negotiated version at all -- sig-first datagrams carry no per-datagram
    preamble the way the full-tx stream does -- so this check is what
    catches a version mismatch there.
    """

    def __init__(self, negotiated: int):
        super().__init__(
            f"server negotiated wire v{negotiated}, this SDK speaks only "
            f"wire v{WIRE_VERSION}"
        )
        self.negotiated = negotiated


class MissingVersion(BadFrame):
    """Raised when an initial success ack omits its negotiated version.

    Sig-first datagrams have no other wire-version marker, so accepting this
    envelope would begin decoding without proof that the server selected v2.
    """

    def __init__(self):
        super().__init__(
            "successful initial control ack omitted the negotiated wire version"
        )


#: Bound on a control-ack envelope's length prefix: acks are a few dozen
#: bytes of JSON, so this is generous headroom against a corrupted length
#: rather than a realistic ack size.
MAX_ACK_BYTES = 16 * 1024

#: Seconds a control round-trip waits for the server's ack before raising
#: :class:`AckTimeout`.
#:
#: This bounds control-stream opening, writing, and acknowledgement reading.
ACK_TIMEOUT = 10.0
PREAMBLE_TIMEOUT = 10.0
# The server emits an idle heartbeat every 10 seconds. Three missed heartbeat
# windows provide useful headroom without allowing a dead full stream to wait
# forever.
FULL_STREAM_TIMEOUT = 30.0


@dataclass(frozen=True)
class Timeouts:
    """Bounded waits used by control and full-stream operations."""

    ack: float = ACK_TIMEOUT
    preamble: float = PREAMBLE_TIMEOUT
    full_stream_idle: float = FULL_STREAM_TIMEOUT

    def __post_init__(self) -> None:
        for name in ("ack", "preamble", "full_stream_idle"):
            value = getattr(self, name)
            if (
                not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    f"{name} timeout must be a finite number greater than zero"
                )


_DEFAULT_TIMEOUTS = Timeouts()


class AckTimeout(TimeoutError):
    """Raised when the server does not answer a control message with a
    complete ack envelope within :data:`ACK_TIMEOUT` seconds.

    This is the "peer accepted the stream, then went quiet" case: nothing at
    the QUIC layer is wrong, so no connection event will ever arrive to
    release the waiter. Failing loudly beats a subscribe call that never
    returns while data flows past."""


class PreambleTimeout(TimeoutError):
    """Raised when a full-tx stream preamble does not arrive in time."""


class FullStreamTimeout(TimeoutError):
    """Terminal error raised when full-tx frames and heartbeats both stop."""


class FullQueueOverflow(RuntimeError):
    """Terminal error raised instead of silently dropping ordered frames."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        super().__init__(
            f"full-tx queue reached its capacity of {capacity}; "
            "the consumer cannot keep up"
        )


def _parse_ack(raw: bytes) -> Ack:
    """Decodes an ack envelope's JSON body. Split out from the async I/O so
    it is unit-testable without a live connection."""
    try:
        obj = json.loads(raw)
    except ValueError as e:
        raise BadFrame(f"malformed control ack JSON: {e}") from e
    if not isinstance(obj, dict):
        raise BadFrame("control ack body is not a JSON object")
    kind = obj.get("type")
    ok = obj.get("ok", False)
    reason = obj.get("reason")
    negotiated = obj.get("v")
    code = obj.get("code")
    if not isinstance(kind, str):
        raise BadFrame("control ack type is not a string")
    if not isinstance(ok, bool):
        raise BadFrame("control ack ok field is not a boolean")
    if reason is not None and not isinstance(reason, str):
        raise BadFrame("control ack reason is not a string")
    if negotiated is not None and (
        not isinstance(negotiated, int) or isinstance(negotiated, bool)
    ):
        raise BadFrame("control ack version is not an integer")
    if code is not None and (not isinstance(code, int) or isinstance(code, bool)):
        raise BadFrame("control error code is not an integer")
    return Ack(
        ok=ok,
        reason=reason,
        v=negotiated,
        kind=kind,
        code=code,
    )


def _check_ack(ack: Ack, *, initial: bool = False) -> Ack:
    """Interprets an already-decoded :class:`Ack`: a rejection surfaces as
    :class:`Rejected` (never silently treated as success), and a version
    mismatch on the FIRST control message's ack surfaces as
    :class:`VersionMismatch`. Split out from the I/O so this decision logic
    is unit-testable without a live connection."""
    if ack.kind == "error":
        if ack.code is None:
            raise BadFrame("control error envelope is missing its code")
        raise PulseConnectionClosed(CloseInfo(ack.code, ack.reason or ""))
    if ack.kind != "ack":
        raise BadFrame(f"unknown control envelope type: {ack.kind!r}")
    if not ack.ok:
        raise Rejected(ack.reason or "")
    if initial and ack.v is None:
        raise MissingVersion()
    if ack.v is not None and ack.v != WIRE_VERSION:
        raise VersionMismatch(ack.v)
    return ack


async def _control_round_trip(
    proto: "_PulseProtocol",
    control: dict,
    *,
    initial: bool = False,
) -> Ack:
    raw = await proto.send_control(control)
    return _check_ack(_parse_ack(raw), initial=initial)


# ---- sig-first gap tracking ---------------------------------------------

#: Wire sentinel for a heartbeat's `highest_seq` meaning "nothing has been
#: assigned to this subscriber yet". 0 is a real, already-assigned sequence
#: number (the FIRST delivery on any connection is `seq == 0`), so 0 cannot
#: double as "none" -- conflating the two would tell a client it already
#: missed transaction 0 the instant it connected.
NO_SEQ_ASSIGNED = (1 << 64) - 1


class _GapTracker:
    """Running (last-seen, gap-count) state for one sig-first subscription.

    QUIC DATAGRAMs are explicitly unordered, so out-of-order arrival is
    expected traffic, not a pathology -- the watermark MUST be monotonic
    (``max(last, seq)``), never just overwritten with whatever arrived most
    recently. An unconditional overwrite would let a reordered item drag the
    watermark backwards and over-count gaps on the next in-order item.

    See :attr:`SigFirstSub.gaps` for the honest, carried-forward wording of
    what this counter actually guarantees.
    """

    __slots__ = ("_last_seq", "_gaps", "_heartbeat", "_heartbeats")

    def __init__(self) -> None:
        self._last_seq: Optional[int] = None
        self._gaps = 0
        self._heartbeat: Optional[Heartbeat] = None
        self._heartbeats = 0

    @property
    def gaps(self) -> int:
        return self._gaps

    @property
    def heartbeat(self) -> Optional[Heartbeat]:
        return self._heartbeat

    @property
    def heartbeats(self) -> int:
        return self._heartbeats

    def note_item_seq(self, seq: int) -> None:
        """Folds one sig-first item's own `seq` into the running state. A
        gap is exactly the count of sequence numbers skipped between the
        previous (highest-seen) item and this one."""
        if self._last_seq is not None:
            last = self._last_seq
            # A corrupt or hostile datagram could carry seq == the sentinel
            # as a real item seq -- nothing on this path has reason to
            # reject that value (the sentinel is only reserved on the
            # heartbeat side) -- so guard the "next expected" computation
            # the same way the Rust/Go SDKs do (saturating, never wrapping
            # into a fabricated gap).
            next_expected = last if last == NO_SEQ_ASSIGNED else last + 1
            self._gaps += max(seq - next_expected, 0)
            self._last_seq = max(last, seq)
        else:
            self._last_seq = seq

    def note_heartbeat_seq(self, highest_seq: int) -> None:
        """Folds a heartbeat's `highest_seq` into the running state. This is
        what reveals TRAILING loss -- datagrams dropped after the last item
        this subscriber actually received, which item-to-item comparison
        alone can never see."""
        if highest_seq == NO_SEQ_ASSIGNED:
            return
        if self._last_seq is not None:
            if highest_seq > self._last_seq:
                self._gaps += highest_seq - self._last_seq
                self._last_seq = highest_seq
            # else: heartbeat is stale/equal to what item traffic already
            # told us -- nothing new to fold in.
        else:
            # First observation ever, with no item to compare against:
            # establish a baseline rather than alleging a gap we have no
            # evidence for.
            self._last_seq = highest_seq

    def note_heartbeat(self, server_ts_ms: int, highest_seq: int) -> None:
        self._heartbeat = Heartbeat(server_ts_ms, highest_seq)
        self._heartbeats += 1
        self.note_heartbeat_seq(highest_seq)


@dataclass(frozen=True)
class SigFirstItem:
    """One sig-first delivery: the transaction's slot, this subscriber's
    per-connection sequence number (see :attr:`SigFirstSub.gaps`), and its
    signature."""

    slot: int
    seq: int
    signature: bytes


def _apply_datagram(dg: bytes, tracker: _GapTracker) -> Optional[SigFirstItem]:
    """Applies one raw datagram to the running gap-tracking state, returning
    the item to forward (if any). An unknown type and an undecodable datagram
    (corrupt bytes, or a known type too short to parse) both mean "skip" --
    never an error, never a reason to tear the stream down; that is what
    keeps a future datagram type -- or ordinary transport-level corruption --
    from breaking this client. A heartbeat updates the gap counter but is
    never forwarded as an item."""
    decoded = decode_datagram(dg)
    if isinstance(decoded, DatagramSigFirst):
        tracker.note_item_seq(decoded.seq)
        return SigFirstItem(
            slot=decoded.slot,
            seq=decoded.seq,
            signature=decoded.signature,
        )
    if isinstance(decoded, DatagramHeartbeat):
        tracker.note_heartbeat(decoded.server_ts_ms, decoded.highest_seq)
        return None
    return None  # DatagramUnknown, or None (undecodable): skip


# ---- full-tx frame stream ------------------------------------------------

#: Sanity cap on a single v2 frame's total length prefix -- generous enough
#: for MAX_FULL_TX_BODY plus the largest possible TLV trailer (two
#: loaded-address lists, each up to 65535 bytes long) plus the 2-byte
#: msg_type/flags header. A plain v1-sized cap here would wrongly reject a
#: legitimately large fields=["alt"]-enriched frame.
MAX_FULL_TX_FRAME = MAX_FULL_TX_BODY + 2 * (65535 + 3) + 2


def _next_tx_frame(
    buf: bytearray,
    heartbeat_holder: List[Optional[Heartbeat]],
    heartbeat_count_holder: Optional[List[int]] = None,
) -> Optional[FullTxV2]:
    """Consumes complete, length-delimited frames from the front of `buf`,
    skipping unrecognized message types and folding heartbeat frames into
    ``heartbeat_holder[0]``, until a transaction frame is found or there
    isn't a complete frame left. Returns `None` if `buf` was exhausted
    without a transaction frame (the caller should feed more bytes, or treat
    it as a clean end of stream if no more are coming).

    Raises :class:`BadFrame` on a malformed frame -- this is fatal to the
    stream by design (see :class:`BadFrame`'s docstring): the caller must
    not call this again on the same buffer afterward, since the byte
    boundaries beyond a failed decode can no longer be trusted the way an
    *unrecognized* frame's boundaries can.

    This decode path is shared by the async client and the in-memory stream
    harness.
    """
    while len(buf) >= 4:
        n = struct.unpack_from(">I", buf, 0)[0]
        if n > MAX_FULL_TX_FRAME:
            raise BadFrame(f"frame length {n} exceeds max {MAX_FULL_TX_FRAME}")
        if len(buf) < 4 + n:
            break
        body = bytes(buf[4 : 4 + n])
        del buf[: 4 + n]
        frame = decode_frame(body)
        if isinstance(frame, FullTxV2):
            return frame
        if isinstance(frame, FrameHeartbeat):
            heartbeat_holder[0] = Heartbeat(frame.server_ts_ms, frame.highest_seq)
            if heartbeat_count_holder is not None:
                heartbeat_count_holder[0] += 1
            continue
        # FrameUnknown: skip, never an error.
    return None


class _FullStreamState:
    """Per full-tx-stream decode state: preamble verification, then framed
    tx/heartbeat/unknown dispatch. Pure and IO-free so it can be exercised
    without a live QUIC connection.
    """

    __slots__ = (
        "_buf",
        "_preamble_ok",
        "heartbeat",
        "heartbeats",
        "activity_count",
    )

    def __init__(self) -> None:
        self._buf = bytearray()
        self._preamble_ok = False
        self.heartbeat: Optional[Heartbeat] = None
        self.heartbeats = 0
        self.activity_count = 0

    @property
    def preamble_ok(self) -> bool:
        return self._preamble_ok

    @property
    def pending(self) -> int:
        """Bytes buffered but not yet forming a complete frame. Nonzero at
        end-of-stream means the stream stopped MID-frame -- see
        `_end_full_stream`."""
        return len(self._buf)

    def feed(self, data: bytes) -> List[FullTxV2]:
        """Feeds newly-arrived bytes and returns any complete transaction
        frames now available (possibly none). Raises :class:`BadPreamble` or
        :class:`BadFrame` -- both fatal; the caller must stop calling `feed`
        on this instance afterward."""
        self._buf += data
        if not self._preamble_ok:
            if len(self._buf) < len(PREAMBLE):
                return []
            preamble = bytes(self._buf[: len(PREAMBLE)])
            del self._buf[: len(PREAMBLE)]
            _verify_preamble(preamble)  # raises BadPreamble on mismatch
            self._preamble_ok = True

        out: List[FullTxV2] = []
        holder: List[Optional[Heartbeat]] = [self.heartbeat]
        heartbeat_count_holder = [self.heartbeats]
        try:
            while True:
                tx = _next_tx_frame(
                    self._buf,
                    holder,
                    heartbeat_count_holder,
                )
                if tx is None:
                    break
                out.append(tx)
        finally:
            self.heartbeat = holder[0]
            new_heartbeats = heartbeat_count_holder[0] - self.heartbeats
            self.heartbeats = heartbeat_count_holder[0]
            self.activity_count += len(out) + new_heartbeats
        return out


class _PreambleGate:
    """A one-shot future gate for "the full-tx stream preamble has been
    verified".

    :meth:`PulseClient.subscribe_full` awaits this before ever handing back
    a :class:`FullSub` -- matching the Rust/Go SDKs, where `accept_uni()`
    followed by `verify_preamble()` are blocking, synchronous steps inside
    their own `subscribe_full`, so a bad (or missing -- connection closed
    before 6 bytes ever arrived) preamble fails the subscribe call itself
    rather than surfacing later, silently, on the caller's first iteration.
    aioquic's event-driven model has no direct equivalent of "block until
    the stream is open and N bytes have arrived", so this reconstructs it
    with a future that :class:`_PulseProtocol` resolves from
    `quic_event_received`.
    """

    def __init__(self) -> None:
        self._fut: "Optional[asyncio.Future[None]]" = None
        self._error: Optional[BaseException] = None

    def _future(self) -> "asyncio.Future[None]":
        if self._fut is None:
            self._fut = asyncio.get_running_loop().create_future()
        return self._fut

    async def wait(self) -> None:
        await self._future()
        if self._error is not None:
            raise self._error

    def resolve_ok(self) -> None:
        fut = self._future()
        if not fut.done():
            self._error = None
            fut.set_result(None)

    def resolve_error(self, exc: BaseException) -> None:
        # First resolution wins: once the preamble is verified OK, a later
        # unrelated connection-close must not retroactively turn a
        # successful, already-returned FullSub subscription into an error.
        fut = self._future()
        if not fut.done():
            # The Future only signals readiness; the error remains mutable
            # state. This lets a later ConnectionTerminated event enrich an
            # earlier stream-FIN truncation with CloseInfo before a scheduled
            # waiter resumes, without creating never-retrieved Future errors
            # on sig-first-only connections.
            self._error = exc
            fut.set_result(None)

    def replace_error(self, exc: BaseException) -> None:
        """Upgrade an already-resolved error without replacing prior success."""
        if self._error is not None:
            self._error = exc


#: Depth of the sig-first handoff queue. Bounded on purpose: an unbounded queue
#: turns a slow consumer into unbounded memory and latency growth, which is
#: harder to notice than loss and worse for a latency product.
SIG_QUEUE_LEN = 4096
# Full-tx frames are ordered. The queue is bounded, but an overflow is a loud
# terminal error rather than a silent eviction which would create an
# undetectable hole in the stream.
FULL_QUEUE_LEN = 1024


@dataclass
class _FullTerminal:
    """Mutable queue marker so a later connection close can enrich a FIN."""

    error: Optional[BaseException]


def _put_dropping_oldest(q: "asyncio.Queue", item) -> int:
    """Put ``item``, evicting the oldest entry if ``q`` is full.

    Returns the number of entries dropped (0 or 1). Evicting the oldest rather
    than refusing the newest is deliberate: a stale item is worth less than
    the one that just arrived.
    """
    try:
        q.put_nowait(item)
        return 0
    except asyncio.QueueFull:
        try:
            q.get_nowait()
        except asyncio.QueueEmpty:  # pragma: no cover - consumer raced us
            pass
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:  # pragma: no cover - consumer raced us
            pass
        return 1


class _PulseProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        *args,
        timeouts: Timeouts = _DEFAULT_TIMEOUTS,
        sig_queue_len: int = SIG_QUEUE_LEN,
        full_queue_len: int = FULL_QUEUE_LEN,
        **kwargs,
    ):
        if not isinstance(sig_queue_len, int) or sig_queue_len <= 0:
            raise ValueError("sig_queue_len must be a positive integer")
        if not isinstance(full_queue_len, int) or full_queue_len <= 0:
            raise ValueError("full_queue_len must be a positive integer")
        super().__init__(*args, **kwargs)
        self.timeouts = timeouts
        self.sig_queue_len = sig_queue_len
        self.full_queue_len = full_queue_len
        self.datagrams: asyncio.Queue = asyncio.Queue(maxsize=sig_queue_len)
        # Reserve one extra slot for a terminal marker. Data admission is
        # capped explicitly at `full_queue_len`, so close/overflow can always
        # wake a consumer without evicting an already-received frame.
        self.full: asyncio.Queue = asyncio.Queue(maxsize=full_queue_len + 1)
        self.dropped = 0
        self.full_dropped = 0
        self._full_queued = 0
        self._full_terminal_enqueued = False
        self._full_terminal_slot: Optional[_FullTerminal] = None
        self._sig_terminal_enqueued = False
        self._terminal_error: Optional[PulseConnectionClosed] = None
        self._sig_gap_tracker = _GapTracker()
        self._feed_kind: Optional[str] = None
        self._full_state: Optional[_FullStreamState] = None
        self._full_truncation: Optional[Union[BadFrame, BadPreamble]] = None
        self._full_poisoned = False
        self._full_last_activity = asyncio.get_running_loop().time()
        self._preamble_gate = _PreambleGate()
        self._ack_waiters: Dict[int, "asyncio.Future[bytes]"] = {}
        self._ack_bufs: Dict[int, bytearray] = {}

    @property
    def close_info(self) -> Optional[CloseInfo]:
        return self._terminal_error.close if self._terminal_error else None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, DatagramFrameReceived):
            item = _apply_datagram(event.data, self._sig_gap_tracker)
            if item is not None:
                self.dropped += _put_dropping_oldest(self.datagrams, item)
        elif isinstance(event, StreamDataReceived):
            # QUIC stream IDs encode direction in bit 1 (0=bidi, 1=uni; RFC
            # 9000 S2.1). This client only ever opens bidirectional streams
            # itself (control messages) and the server only ever opens a
            # unidirectional one (the full-tx push stream), so this bit
            # alone -- not transient `_ack_waiters` membership, which a
            # stray/late packet after we've already popped our waiter could
            # misroute -- reliably tells the two apart.
            if event.stream_id & 0x02:
                self._handle_full_stream_data(event.data, event.end_stream)
            else:
                self._handle_ack_data(event.stream_id, event.data, event.end_stream)
        elif isinstance(event, ConnectionTerminated):
            if self._terminal_error is not None:
                return
            close = CloseInfo(
                int(event.error_code),
                event.reason_phrase or "",
                None if event.frame_type is None else int(event.frame_type),
            )
            terminal = PulseConnectionClosed(close)
            full_terminal = self._end_full_stream(terminal=terminal) or terminal
            self._terminal_error = (
                full_terminal
                if isinstance(full_terminal, PulseConnectionClosed)
                else terminal
            )
            if not self._sig_terminal_enqueued:
                self.dropped += _put_dropping_oldest(
                    self.datagrams,
                    self._terminal_error,
                )
                self._sig_terminal_enqueued = True
            self._fail_pending_acks(
                full_terminal if self._feed_kind == "full" else self._terminal_error
            )

    def _handle_full_stream_data(self, data: bytes, end_stream: bool = False) -> None:
        if self._full_poisoned:
            return
        # A server-initiated unidirectional stream can race the initial ack.
        # Record its feed identity so a simultaneous connection close can
        # distinguish an interrupted full stream from an unused full queue on
        # a sig-first connection.
        self._feed_kind = "full"
        if self._full_state is None:
            self._full_state = _FullStreamState()
        activity_before = self._full_state.activity_count
        preamble_before = self._full_state.preamble_ok
        try:
            for tx in self._full_state.feed(data):
                if not self._enqueue_full_tx(tx):
                    break
        except (BadFrame, BadPreamble) as exc:
            # A malformed known frame is terminal because the decoder cannot
            # safely resynchronize.
            self._full_poisoned = True
            self._enqueue_full_terminal(exc)
            self._preamble_gate.resolve_error(exc)
            self.close(error_code=0, reason_phrase="invalid full-tx stream")
            return
        if self._full_state.activity_count != activity_before:
            self._full_last_activity = asyncio.get_running_loop().time()
        if self._full_state.preamble_ok and not preamble_before:
            self._full_last_activity = asyncio.get_running_loop().time()
        if self._full_state.preamble_ok:
            self._preamble_gate.resolve_ok()
        if end_stream:
            self._end_full_stream()

    def _enqueue_full_tx(self, tx: FullTxV2) -> bool:
        if self._full_queued >= self.full_queue_len:
            self.full_dropped += 1
            self._full_poisoned = True
            self._enqueue_full_terminal(FullQueueOverflow(self.full_queue_len))
            self.close(error_code=0, reason_phrase="full-tx consumer queue overflow")
            return False
        self.full.put_nowait(tx)
        self._full_queued += 1
        return True

    def _enqueue_full_terminal(self, item: Optional[BaseException]) -> None:
        if self._full_terminal_enqueued:
            return
        # The queue has one slot reserved specifically for this marker.
        self._full_terminal_slot = _FullTerminal(item)
        self.full.put_nowait(self._full_terminal_slot)
        self._full_terminal_enqueued = True

    def _replace_full_terminal(self, item: Optional[BaseException]) -> None:
        """Upgrade a queued FIN marker without reordering preceding frames."""
        if self._full_terminal_slot is not None:
            self._full_terminal_slot.error = item

    def _end_full_stream(
        self,
        terminal: Optional[PulseConnectionClosed] = None,
    ) -> Optional[BaseException]:
        """Pushes the full-tx queue's end-of-stream sentinel -- or a
        :class:`BadFrame`, if the stream stopped mid-frame.

        A frame whose 4-byte length prefix arrived but whose body never did is
        truncated, not a clean close. A clean close lands on a frame boundary.

        An incomplete PREAMBLE is the other end-of-stream failure, and it is
        handled here too: the gate `subscribe_full` is blocked on gets
        resolved with :class:`BadPreamble` so the caller fails instead of
        awaiting a stream that has already ended. This path covers a bare
        uni-stream FIN with the connection still alive. `resolve_error` is a no-op on a gate
        already resolved OK, so a healthy long-running subscription that
        simply ends is unaffected."""
        if terminal is not None:
            if (
                self._full_terminal_enqueued
                and self._full_terminal_slot is not None
                and self._full_terminal_slot.error is not None
                and self._full_truncation is None
            ):
                # A complete-but-malformed preamble/frame is a decode error,
                # not a truncation. Preserve the original Bad* terminal when
                # our resulting local close event arrives.
                self._full_poisoned = True
                return self._full_terminal_slot.error
            truncation = self._full_truncation
            if truncation is None and self._feed_kind == "full":
                state = self._full_state
                if state is not None and not state.preamble_ok:
                    truncation = BadPreamble(
                        "bad stream preamble: the connection closed before "
                        "the 6-byte full-tx preamble was complete"
                    )
                elif state is not None and state.pending:
                    truncation = BadFrame(
                        f"connection closed mid-frame with {state.pending} byte(s) "
                        "buffered: truncated frame, not a clean close"
                    )
            if truncation is not None:
                self._full_truncation = truncation
                terminal = PulseStreamTruncated(terminal.close, truncation)
            self._full_poisoned = True
            if self._full_terminal_enqueued:
                # A uni-stream FIN can be delivered before the connection
                # close which explains it. Upgrade that already-queued marker
                # in place so callers observe both the truncation and close.
                if self._full_truncation is not None or (
                    self._full_terminal_slot is not None
                    and self._full_terminal_slot.error is None
                ):
                    self._replace_full_terminal(terminal)
                    self._preamble_gate.replace_error(terminal)
                return terminal
            self._preamble_gate.resolve_error(terminal)
            self._enqueue_full_terminal(terminal)
            return terminal
        if self._full_poisoned:
            return None
        state = self._full_state
        if state is None or not state.preamble_ok:
            truncation = BadPreamble(
                "bad stream preamble: the full-tx stream ended before "
                "the 6-byte preamble was complete"
            )
            self._full_truncation = truncation
            self._full_poisoned = True
            self._preamble_gate.resolve_error(truncation)
            self._enqueue_full_terminal(truncation)
            return None
        if state.pending:
            truncation = BadFrame(
                f"stream ended mid-frame with {state.pending} byte(s) "
                "buffered: truncated frame, not a clean close"
            )
            self._full_truncation = truncation
            self._full_poisoned = True
            self._enqueue_full_terminal(truncation)
            return None
        self._enqueue_full_terminal(None)
        return None

    def _handle_ack_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        fut = self._ack_waiters.get(stream_id)
        if fut is None or fut.done():
            return
        buf = self._ack_bufs.setdefault(stream_id, bytearray())
        if len(buf) + len(data) > 4 + MAX_ACK_BYTES:
            self._ack_bufs.pop(stream_id, None)
            fut.set_exception(
                BadFrame("control ack stream exceeds its maximum framed envelope size")
            )
            return
        buf += data
        if len(buf) < 4:
            self._fail_if_ended(fut, end_stream, len(buf))
            return
        n = struct.unpack_from(">I", buf, 0)[0]
        if n > MAX_ACK_BYTES:
            fut.set_exception(BadFrame(f"ack length {n} exceeds max {MAX_ACK_BYTES}"))
            return
        if len(buf) < 4 + n:
            self._fail_if_ended(fut, end_stream, len(buf))
            return
        fut.set_result(bytes(buf[4 : 4 + n]))

    @staticmethod
    def _fail_if_ended(
        fut: "asyncio.Future[bytes]", end_stream: bool, have: int
    ) -> None:
        """Resolves `fut` with an error when the control stream FINs before a
        complete ack envelope arrived.

        This is the pre-upgrade-server case, and it is silent without this
        check: a server that does not answer control messages drops its send
        half, quinn *finishes* a dropped SendStream, and the client sees a
        clean 0-byte FIN. The connection stays up (datagrams keep flowing), so
        `ConnectionTerminated` never fires -- the waiter would simply never be
        resolved and `subscribe_*` would hang forever with data going past.
        Rust's `read_ack` and Go's `readAck` both error on the short read;
        this makes Python agree."""
        if not end_stream:
            return
        fut.set_exception(
            ConnectionError(
                f"pulse: control stream closed after {have} byte(s) without a "
                "complete ack envelope; the peer may not speak wire v2"
            )
        )

    def _fail_pending_acks(self, exc: BaseException) -> None:
        for fut in self._ack_waiters.values():
            if not fut.done():
                fut.set_exception(exc)

    async def send_control(self, control: dict) -> bytes:
        """Writes one control message on a fresh client-initiated bidi
        stream and awaits the server's length-delimited ack body (raw JSON
        bytes, not yet parsed)."""
        if self._terminal_error is not None:
            raise self._terminal_error
        body = json.dumps(control).encode()
        stream_id = self._quic.get_next_available_stream_id()
        fut: "asyncio.Future[bytes]" = asyncio.get_running_loop().create_future()
        self._ack_waiters[stream_id] = fut
        # end_stream=True only finishes OUR write side; the server's response
        # on the same (bidirectional) stream id is unaffected.
        self._quic.send_stream_data(stream_id, body, end_stream=True)
        self.transmit()
        try:
            # Bounded (see ACK_TIMEOUT): a peer that accepts the stream and
            # then neither writes nor closes produces no event at all, so
            # without this the await never returns.
            return await asyncio.wait_for(fut, self.timeouts.ack)
        except asyncio.TimeoutError:
            raise AckTimeout(
                f"pulse: no control ack within {self.timeouts.ack}s"
            ) from None
        finally:
            self._ack_waiters.pop(stream_id, None)
            self._ack_bufs.pop(stream_id, None)


class SigFirstSub:
    """Live sig-first subscription. Iterate with ``async for`` or call
    :meth:`next` in a loop.

    aioquic buffers only a small budget of datagrams itself and evicts on
    overflow, so this SDK drains it continuously into a bounded queue rather
    than leaving datagrams there until the caller happens to iterate. A slow
    consumer costs you the OLDEST items (counted by :attr:`dropped`) rather
    than silently losing whatever arrives while you work.
    """

    def __init__(self, proto: _PulseProtocol):
        self._proto = proto
        self._terminal_error: Optional[BaseException] = None
        self._ended = False

    @property
    def dropped(self) -> int:
        """Items evicted because this consumer fell behind. Watch it: no
        kernel or NIC counter will show this loss."""
        return self._proto.dropped

    @property
    def queued(self) -> int:
        """Current handoff-queue depth. Sustained depth near
        :data:`SIG_QUEUE_LEN` means loss is about to start."""
        terminal = int(self._proto._sig_terminal_enqueued)
        return max(self._proto.datagrams.qsize() - terminal, 0)

    @property
    def queue_capacity(self) -> int:
        return self._proto.sig_queue_len

    @property
    def heartbeat(self) -> Optional[Heartbeat]:
        """The most recent heartbeat, or ``None`` before the first one."""
        return self._proto._sig_gap_tracker.heartbeat

    @property
    def heartbeats(self) -> int:
        return self._proto._sig_gap_tracker.heartbeats

    @property
    def close_info(self) -> Optional[CloseInfo]:
        return self._proto.close_info

    @property
    def metrics(self) -> SubscriptionMetrics:
        return SubscriptionMetrics(
            dropped=self.dropped,
            queued=self.queued,
            queue_capacity=self.queue_capacity,
            heartbeats=self.heartbeats,
            last_heartbeat=self.heartbeat,
        )

    @property
    def gaps(self) -> int:
        """A provisional loss indicator: item-to-item `seq` gaps plus
        trailing loss revealed by a heartbeat's `highest_seq`.
        :data:`NO_SEQ_ASSIGNED` on the wire never contributes to this
        counter.

        It can OVER-report under reordering. QUIC DATAGRAMs are unordered
        by definition, so a scalar high-watermark cannot distinguish "this
        seq is late" from "this seq is lost" at the moment a later one
        arrives out of order -- it charges one provisional gap on that
        jump, and never reverses the charge if the late item shows up
        afterward. A perfectly lossless but reordered stream can therefore
        report `gaps > 0`. Treat this as "loss happened, or reordering
        did" rather than an exact count of sequence numbers that never
        arrived on the wire at all.
        """
        return self._proto._sig_gap_tracker.gaps

    def __aiter__(self) -> "SigFirstSub":
        return self

    async def __anext__(self) -> SigFirstItem:
        if self._terminal_error is not None:
            raise self._terminal_error
        if self._ended:
            raise StopAsyncIteration
        item = await self._proto.datagrams.get()
        if item is None:
            self._ended = True
            raise StopAsyncIteration
        if isinstance(item, BaseException):
            self._terminal_error = item
            raise item
        return item

    async def next(self) -> Optional[SigFirstItem]:
        try:
            return await self.__anext__()
        except StopAsyncIteration:
            return None

    async def update_filter(self, flt: Optional[Filter] = None) -> Ack:
        """Updates the active filter live (opens a fresh control stream).

        Returns the server's parsed ack. Raises
        :class:`Rejected` if the server refused it. The tier cannot change
        after the first control message -- this never re-sends a token."""
        control = (flt or Filter())._to_control(False)
        return await _control_round_trip(self._proto, control)


class FullSub:
    """Live full-tx subscription. Iterate with ``async for`` or call
    :meth:`next` in a loop.

    A malformed frame raises :class:`thornode_pulse.frame.BadFrame` out of
    iteration -- see the module docstring. `Unknown` message types are
    skipped transparently, and heartbeat frames update :attr:`heartbeat`
    instead of being yielded.
    """

    def __init__(self, proto: _PulseProtocol):
        self._proto = proto
        self._terminal_error: Optional[BaseException] = None
        self._ended = False

    def __aiter__(self) -> "FullSub":
        return self

    async def __anext__(self) -> FullTxV2:
        if self._terminal_error is not None:
            raise self._terminal_error
        if self._ended:
            raise StopAsyncIteration
        loop = asyncio.get_running_loop()
        while self._proto.full.empty():
            elapsed = loop.time() - self._proto._full_last_activity
            remaining = self._proto.timeouts.full_stream_idle - elapsed
            if remaining <= 0:
                self._terminal_error = FullStreamTimeout(
                    "pulse: no full-tx frame or heartbeat within "
                    f"{self._proto.timeouts.full_stream_idle}s"
                )
                self._proto.close(
                    error_code=0,
                    reason_phrase="full-tx stream idle timeout",
                )
                raise self._terminal_error
            try:
                item = await asyncio.wait_for(self._proto.full.get(), remaining)
                break
            except asyncio.TimeoutError:
                # A heartbeat updates `_full_last_activity` without entering
                # the transaction queue. Recompute its remaining budget.
                continue
        else:
            item = self._proto.full.get_nowait()
        if isinstance(item, _FullTerminal):
            item = item.error
        if item is None:
            self._ended = True
            raise StopAsyncIteration
        if isinstance(item, BaseException):
            self._terminal_error = item
            raise item
        self._proto._full_queued = max(self._proto._full_queued - 1, 0)
        return item

    async def next(self) -> Optional[FullTxV2]:
        try:
            return await self.__anext__()
        except StopAsyncIteration:
            return None

    @property
    def heartbeat(self) -> Optional[Heartbeat]:
        """The most recent heartbeat observed on this stream.

        ``highest_seq ==`` :data:`NO_SEQ_ASSIGNED`
        means the server has not assigned this subscriber a transaction yet.
        `None` means no heartbeat has arrived at all yet (a busy stream can
        go a long time without one -- the server resets its heartbeat timer
        on every real send)."""
        state = self._proto._full_state
        return state.heartbeat if state else None

    @property
    def heartbeats(self) -> int:
        state = self._proto._full_state
        return state.heartbeats if state else 0

    @property
    def dropped(self) -> int:
        """Frames refused at the queue boundary before a loud overflow."""
        return self._proto.full_dropped

    @property
    def queued(self) -> int:
        return self._proto._full_queued

    @property
    def queue_capacity(self) -> int:
        return self._proto.full_queue_len

    @property
    def close_info(self) -> Optional[CloseInfo]:
        return self._proto.close_info

    @property
    def metrics(self) -> SubscriptionMetrics:
        return SubscriptionMetrics(
            dropped=self.dropped,
            queued=self.queued,
            queue_capacity=self.queue_capacity,
            heartbeats=self.heartbeats,
            last_heartbeat=self.heartbeat,
        )

    async def update_filter(
        self, flt: Optional[Filter] = None, fields: Sequence[str] = ()
    ) -> Ack:
        """Updates the active filter/enrichment fields live (opens a fresh
        control stream) and returns the server's parsed ack. Raises
        :class:`Rejected` if the server refused it. The tier cannot change
        after the first control message -- this never re-sends a token."""
        control = (flt or Filter())._to_control(True, fields=fields)
        return await _control_round_trip(self._proto, control)


class PulseClient:
    def __init__(self, proto: _PulseProtocol, token: Optional[str] = None):
        self._proto = proto
        self._token = token
        self._subscription_kind: Optional[str] = None
        self._subscribe_lock = asyncio.Lock()

    @property
    def subscription_kind(self) -> Optional[str]:
        """The selected or attempted feed, or ``None`` before first use.

        Once an initial control message may have reached the peer, the
        connection is consumed even if its ack is missing, malformed, or
        times out. Open a new connection after any subscribe failure.
        """
        return self._subscription_kind

    @property
    def close_info(self) -> Optional[CloseInfo]:
        return self._proto.close_info

    async def subscribe_sig_first(self, flt: Optional[Filter] = None) -> SigFirstSub:
        """Select the sig-first DATAGRAM feed.

        Raises :class:`Rejected`
        if the server refused the subscription, or :class:`VersionMismatch`
        if it negotiated a wire version this SDK does not speak."""
        async with self._subscribe_lock:
            self._ensure_unsubscribed()
            control = (flt or Filter())._to_control(False, self._token)
            # The server irrevocably selects a feed from the first control
            # message. Mark the connection consumed before network I/O: an
            # ack timeout or malformed ack leaves delivery outcome unknown,
            # so trying another "initial" control on this connection is not
            # safe.
            self._subscription_kind = "sig-first"
            self._proto._feed_kind = "sig-first"
            await _control_round_trip(self._proto, control, initial=True)
            return SigFirstSub(self._proto)

    async def subscribe_full(
        self, flt: Optional[Filter] = None, fields: Sequence[str] = ()
    ) -> FullSub:
        """Select the ordered full-tx feed. `fields` requests enrichment
        groups (currently just `["alt"]`, which adds each frame's
        ALT-loaded addresses). Raises :class:`Rejected` if the server
        refused the subscription, or :class:`VersionMismatch` if it
        negotiated a wire version this SDK does not speak.

        The stream's 6-byte preamble is read and verified here, before the
        subscription is ever returned to the caller -- a mismatch (or a
        connection that closes before the preamble completes) is a loud
        :class:`thornode_pulse.frame.BadPreamble`, never a silent skip."""
        async with self._subscribe_lock:
            self._ensure_unsubscribed()
            control = (flt or Filter())._to_control(True, self._token, fields)
            self._subscription_kind = "full"
            self._proto._feed_kind = "full"
            await _control_round_trip(self._proto, control, initial=True)
            # The initial control attempt permanently consumes this
            # connection; a subsequent preamble failure does not undo that.
            try:
                await asyncio.wait_for(
                    self._proto._preamble_gate.wait(),
                    self._proto.timeouts.preamble,
                )
            except asyncio.TimeoutError:
                self._proto.close(
                    error_code=0,
                    reason_phrase="full-tx preamble timeout",
                )
                raise PreambleTimeout(
                    "pulse: no full-tx preamble within "
                    f"{self._proto.timeouts.preamble}s"
                ) from None
            return FullSub(self._proto)

    def _ensure_unsubscribed(self) -> None:
        if self._proto._terminal_error is not None:
            raise self._proto._terminal_error
        if self._subscription_kind is not None:
            raise AlreadySubscribedError(
                "a Pulse connection carries exactly one feed; "
                f"this connection already selected {self._subscription_kind!r}"
            )


def _is_loopback_host(host: str) -> bool:
    candidate = host.strip().strip("[]").rstrip(".").lower()
    if candidate == "localhost" or candidate.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _parse_target(target: str) -> Tuple[str, int]:
    """Parse ``host:port`` or bracketed ``[IPv6]:port`` without DNS I/O."""
    if not isinstance(target, str):
        raise TypeError("Pulse target must be a host:port string")
    if not target or target != target.strip():
        raise ValueError("Pulse target must be a non-empty host:port string")
    if "://" in target:
        raise ValueError("Pulse target must be host:port, not a URL")

    if target.startswith("["):
        closing = target.find("]")
        if closing < 0 or target[closing + 1 : closing + 2] != ":":
            raise ValueError("bracketed IPv6 target must use [address]:port")
        host = target[1:closing]
        port_text = target[closing + 2 :]
        if "]" in port_text or not host:
            raise ValueError("invalid bracketed IPv6 Pulse target")
    else:
        if target.count(":") != 1:
            raise ValueError(
                "Pulse target must use host:port; bracket IPv6 as [address]:port"
            )
        host, port_text = target.rsplit(":", 1)

    if not host or not port_text:
        raise ValueError("Pulse target must include both host and port")
    try:
        port = int(port_text, 10)
    except ValueError as exc:
        raise ValueError("Pulse target port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Pulse target port must be between 1 and 65535")
    return host, port


def _normalize_certificate_pin(pin: Union[str, bytes]) -> str:
    if isinstance(pin, bytes):
        if len(pin) == 32:
            return pin.hex()
        try:
            value = pin.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("certificate_sha256 must be 32 bytes or hex") from exc
    elif isinstance(pin, str):
        value = pin
    else:
        raise TypeError("certificate_sha256 must be bytes or a hex string")
    value = value.strip().lower()
    if value.startswith("sha256/"):
        value = value[7:]
    value = value.replace(":", "").replace(" ", "")
    if len(value) != 64:
        raise ValueError("certificate_sha256 must contain 64 hexadecimal digits")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("certificate_sha256 is not hexadecimal") from exc
    return value


def _build_quic_configuration(
    host: str,
    *,
    server_name: Optional[str] = None,
    ca_file: Optional[str] = None,
    ca_path: Optional[str] = None,
    ca_data: Optional[Union[str, bytes]] = None,
    insecure_local_development: bool = False,
) -> QuicConfiguration:
    """Build the TLS configuration without opening a network connection."""
    if insecure_local_development and not _is_loopback_host(host):
        raise ValueError(
            "insecure_local_development is restricted to localhost/loopback targets"
        )
    if insecure_local_development and any((ca_file, ca_path, ca_data)):
        raise ValueError(
            "custom CA options cannot be combined with insecure_local_development"
        )

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["pulse"],
        server_name=server_name or host,
    )
    config.max_datagram_frame_size = 65536  # enable QUIC DATAGRAMs
    if insecure_local_development:
        config.verify_mode = ssl.CERT_NONE
        return config

    config.verify_mode = ssl.CERT_REQUIRED
    custom_ca_chunks: List[bytes] = []
    if ca_data is None:
        pass
    elif isinstance(ca_data, str):
        custom_ca_chunks.append(ca_data.encode("ascii"))
    else:
        custom_ca_chunks.append(ca_data)
    if ca_file is not None:
        custom_ca_chunks.append(Path(ca_file).read_bytes())
    custom_ca_data = b"\n".join(custom_ca_chunks) or None
    # certifi is loaded directly by OpenSSL as the maintained default CA
    # bundle. Only caller-provided CA material goes through aioquic's cadata
    # parser, avoiding warnings from reparsing platform-specific roots.
    config.load_verify_locations(
        cafile=certifi.where(),
        capath=ca_path,
        cadata=custom_ca_data,
    )
    return config


def _verify_certificate_pin(
    proto: _PulseProtocol,
    expected_pin: Union[str, bytes],
) -> None:
    expected = _normalize_certificate_pin(expected_pin)
    certificate = getattr(getattr(proto._quic, "tls", None), "_peer_certificate", None)
    if certificate is None:
        raise ssl.SSLCertVerificationError(
            "Pulse peer certificate was unavailable for SHA-256 pinning"
        )
    actual = certificate.fingerprint(hashes.SHA256()).hex()
    if not hmac.compare_digest(expected, actual):
        raise CertificatePinMismatch(expected, actual)


@asynccontextmanager
async def connect_pulse(
    target: str,
    *,
    token: Optional[str] = None,
    server_name: Optional[str] = None,
    ca_file: Optional[str] = None,
    ca_path: Optional[str] = None,
    ca_data: Optional[Union[str, bytes]] = None,
    certificate_sha256: Optional[Union[str, bytes]] = None,
    insecure_local_development: bool = False,
    timeouts: Timeouts = _DEFAULT_TIMEOUTS,
    sig_queue_len: int = SIG_QUEUE_LEN,
    full_queue_len: int = FULL_QUEUE_LEN,
) -> AsyncIterator[PulseClient]:
    """Connect to ``host:port`` with certificate/hostname verification.

    certifi's maintained Mozilla CA roots are trusted by default. ``ca_file``,
    ``ca_path`` and ``ca_data`` add private roots; ``certificate_sha256`` adds
    an exact leaf certificate pin after normal verification. Only an explicit
    ``insecure_local_development=True`` disables verification, and it is
    rejected for non-loopback targets.
    """
    host, port = _parse_target(target)
    config = _build_quic_configuration(
        host,
        server_name=server_name,
        ca_file=ca_file,
        ca_path=ca_path,
        ca_data=ca_data,
        insecure_local_development=insecure_local_development,
    )
    protocol_factory = partial(
        _PulseProtocol,
        timeouts=timeouts,
        sig_queue_len=sig_queue_len,
        full_queue_len=full_queue_len,
    )
    async with connect(
        host,
        port,
        configuration=config,
        create_protocol=protocol_factory,
    ) as proto:
        typed_proto = cast(_PulseProtocol, proto)
        if certificate_sha256 is not None:
            _verify_certificate_pin(typed_proto, certificate_sha256)
        yield PulseClient(typed_proto, token=token)
