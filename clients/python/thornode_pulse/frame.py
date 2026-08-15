"""Wire frame and datagram codecs for Pulse wire v2.

See the public protocol specification for the complete wire format.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

# ---- errors ------------------------------------------------------------------


class BadFrame(ValueError):
    """Raised when a datagram, stream frame, or full-tx body does not match
    the documented wire layout (truncated, oversized, or malformed).

    A decode error here is fatal to the stream. A client that cannot parse a
    known frame has no reliable way to locate the next boundary, so this
    exception propagates to the caller.
    """


class BadPreamble(ValueError):
    """Raised when the full-tx stream's opening bytes are not exactly
    :data:`PREAMBLE` -- the strongest signal available that this client is
    not actually talking to a wire v2 server (or the stream was corrupted in
    transit).

    Deliberately its own exception, never folded into :class:`BadFrame`: the
    preamble is the one place a client confirms it is speaking the protocol
    it thinks it is, and a mismatch there must never be a silent skip.
    """


# ---- stream preamble -----------------------------------------------------

#: Wire protocol version carried by the stream preamble.
WIRE_VERSION = 2

#: Written once at the head of every full-tx unidirectional stream, before
#: any frame: ``b"PLS2"`` then the version then a reserved flags byte.
#:
#: This exists because a per-frame version byte cannot work: byte 0 of a v1
#: body is ``slot``'s low byte, which takes all 256 values roughly every 100
#: seconds. A v1 stream's first byte, by contrast, is always ``0x00`` -- the
#: high byte of a u32 big-endian length prefix on a frame capped at 64 KiB --
#: so a non-zero magic is unambiguous.
PREAMBLE = b"PLS2\x02\x00"


def _verify_preamble(buf: bytes) -> None:
    """Checks `buf` against :data:`PREAMBLE` exactly (length and content).
    Raises :class:`BadPreamble` on any mismatch, including a short read."""
    if buf != PREAMBLE:
        raise BadPreamble(
            "bad stream preamble: this server is not speaking pulse wire v2"
        )


# ---- frame message types ------------------------------------------------

MSG_TX = 1
MSG_HEARTBEAT = 2
#: Wire v2 assigns this message type to shed notices but does not emit them.
MSG_SHED = 3

# ---- frame flags (per-frame booleans, NOT a TLV presence bitmap) --------

#: The ALT address set on this frame may be incomplete.
FLAG_ALT_INCOMPLETE = 0x01

# ---- TLV types -------------------------------------------------------------

TLV_LOADED_WRITABLE = 1
TLV_LOADED_READONLY = 2
TLV_SERVER_TS_MS = 3
TLV_HIGHEST_SEQ = 4

#: 64 KiB cap on a full-tx body (the positional v1 payload, before any v2 TLV
#: trailer).
MAX_FULL_TX_BODY = 1 << 16


def put_tlv(buf: bytearray, t: int, value: bytes) -> None:
    """Appends one ``u8 type | u16 LE len | value`` record to `buf`.

    `len` is `u16` because a loaded-address list is 32 bytes per address and
    ALT-heavy transactions load dozens; a `u8` length would cap at 7.
    """
    buf.append(t)
    buf += struct.pack("<H", len(value))
    buf += value


def parse_tlvs(src: bytes) -> List[Tuple[int, bytes]]:
    """Parses a TLV trailer to the end of `src`.

    Unknown types are returned to the caller rather than rejected --
    skipping them is what makes new fields additive. A duplicate type IS
    rejected: silently preferring first or last is the kind of ambiguity
    that produces two implementations which disagree.
    """
    out: List[Tuple[int, bytes]] = []
    seen: set = set()
    off = 0
    n = len(src)
    while off < n:
        if off + 3 > n:
            raise BadFrame("truncated TLV header")
        t = src[off]
        length = struct.unpack_from("<H", src, off + 1)[0]
        start = off + 3
        end = start + length
        if end > n:
            raise BadFrame("TLV length overruns the buffer")
        if t in seen:
            raise BadFrame(f"duplicate TLV type {t}")
        seen.add(t)
        out.append((t, src[start:end]))
        off = end
    return out


# ---- FullTx: the v1 positional body ----------------------------------------


@dataclass
class Instruction:
    program_id_index: int
    accounts: bytes
    data: bytes


@dataclass
class AddressTableLookup:
    account_key: bytes
    writable_indexes: bytes
    readonly_indexes: bytes


@dataclass
class FullTx:
    slot: int
    versioned: bool
    num_required_signatures: int
    num_readonly_signed_accounts: int
    num_readonly_unsigned_accounts: int
    recent_blockhash: bytes
    signatures: List[bytes] = field(default_factory=list)
    account_keys: List[bytes] = field(default_factory=list)
    instructions: List[Instruction] = field(default_factory=list)
    address_table_lookups: List[AddressTableLookup] = field(default_factory=list)


class _Decoder:
    __slots__ = ("b", "off")

    def __init__(self, b: bytes):
        self.b = b
        self.off = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.off + n > len(self.b):
            raise BadFrame("unexpected end of frame")
        s = self.b[self.off : self.off + n]
        self.off += n
        return s

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def count(self, min_elem: int) -> int:
        """Reads a u16 count and rejects it before any allocation if that
        many elements of at least `min_elem` bytes cannot fit in the
        remaining frame."""
        n = self.u16()
        if min_elem == 0 or n > (len(self.b) - self.off) // min_elem:
            raise BadFrame("length prefix exceeds remaining frame")
        return n


def decode_full_tx_prefix(src: bytes) -> Tuple[FullTx, int]:
    """Decodes a FullTx body from the front of `src` and returns the cursor
    offset just past it, without requiring `src` to be fully consumed. This
    lets a v2 frame decode the v1 body and then read whatever follows as a
    TLV trailer. :func:`decode_full_tx` wraps this and enforces exact
    consumption for the plain v1 case."""
    if len(src) > MAX_FULL_TX_BODY:
        raise BadFrame("body exceeds max size")
    d = _Decoder(src)
    slot = d.u64()
    nreq = d.u8()
    nros = d.u8()
    nrou = d.u8()
    versioned = d.u8() != 0
    blockhash = d.take(32)

    signatures = [d.take(64) for _ in range(d.count(64))]
    account_keys = [d.take(32) for _ in range(d.count(32))]

    instructions: List[Instruction] = []
    for _ in range(d.count(5)):  # min ix = progIdx(1)+accLen(2)+dataLen(2)
        pid = d.u8()
        accounts = d.take(d.u16())
        data = d.take(d.u16())
        instructions.append(Instruction(pid, accounts, data))

    atls: List[AddressTableLookup] = []
    for _ in range(d.count(36)):  # min ATL = key(32)+wLen(2)+rLen(2)
        key = d.take(32)
        writable = d.take(d.u16())
        readonly = d.take(d.u16())
        atls.append(AddressTableLookup(key, writable, readonly))

    ft = FullTx(
        slot=slot,
        versioned=versioned,
        num_required_signatures=nreq,
        num_readonly_signed_accounts=nros,
        num_readonly_unsigned_accounts=nrou,
        recent_blockhash=blockhash,
        signatures=signatures,
        account_keys=account_keys,
        instructions=instructions,
        address_table_lookups=atls,
    )
    return ft, d.off


def decode_full_tx(b: bytes) -> FullTx:
    """Strictly decodes a full-tx body. Raises :class:`BadFrame` on any
    truncation, oversize, or trailing garbage; never returns partial data."""
    ft, consumed = decode_full_tx_prefix(b)
    if consumed != len(b):
        raise BadFrame("trailing bytes after full-tx body")
    return ft


def encode_full_tx(ft: FullTx) -> bytes:
    """Inverse of :func:`decode_full_tx` -- for round-trip testing."""
    out = bytearray()
    out += struct.pack("<Q", ft.slot)
    out += bytes(
        [
            ft.num_required_signatures & 0xFF,
            ft.num_readonly_signed_accounts & 0xFF,
            ft.num_readonly_unsigned_accounts & 0xFF,
            1 if ft.versioned else 0,
        ]
    )
    out += ft.recent_blockhash
    out += struct.pack("<H", len(ft.signatures))
    for s in ft.signatures:
        out += s
    out += struct.pack("<H", len(ft.account_keys))
    for k in ft.account_keys:
        out += k
    out += struct.pack("<H", len(ft.instructions))
    for ix in ft.instructions:
        out += bytes([ix.program_id_index & 0xFF])
        out += struct.pack("<H", len(ix.accounts))
        out += ix.accounts
        out += struct.pack("<H", len(ix.data))
        out += ix.data
    out += struct.pack("<H", len(ft.address_table_lookups))
    for l in ft.address_table_lookups:
        out += l.account_key
        out += struct.pack("<H", len(l.writable_indexes))
        out += l.writable_indexes
        out += struct.pack("<H", len(l.readonly_indexes))
        out += l.readonly_indexes
    return bytes(out)


# ---- v2 stream frames -------------------------------------------------------


@dataclass
class FullTxV2:
    """A decoded v2 transaction frame: the v1 body plus its v2 additions."""

    tx: FullTx
    alt_incomplete: bool = False
    loaded_writable: List[bytes] = field(default_factory=list)
    loaded_readonly: List[bytes] = field(default_factory=list)


@dataclass
class FrameHeartbeat:
    server_ts_ms: int
    highest_seq: int


@dataclass
class FrameUnknown:
    """Carries the message type of a frame this decoder does not recognize,
    so a caller can skip it deliberately rather than erroring."""

    msg_type: int


#: A decoded v2 stream frame: exactly one of these three shapes. Python has
#: no direct equivalent of Rust's closed `enum Frame`, so (mirroring the Go
#: SDK's interface + concrete-type approach) this is a plain typing.Union
#: dispatched with `isinstance`.
Frame = Union[FullTxV2, FrameHeartbeat, FrameUnknown]


def _flatten32(addrs: List[bytes]) -> bytes:
    return b"".join(addrs)


def _unflatten32(src: bytes) -> List[bytes]:
    if len(src) % 32 != 0:
        raise BadFrame("loaded-address TLV length is not a multiple of 32")
    return [bytes(src[i : i + 32]) for i in range(0, len(src), 32)]


def encode_frame_tx(
    ft: FullTx,
    alt_incomplete: bool = False,
    loaded_writable: Optional[List[bytes]] = None,
    loaded_readonly: Optional[List[bytes]] = None,
) -> bytes:
    """Encodes a v2 transaction frame: `msg_type | flags | v1 body | TLV
    trailer`. The v1 body is reused byte-for-byte; only the framing around it
    is new. Omit `loaded_writable`/`loaded_readonly` for a non-enriched
    subscriber -- the trailer is then empty and the frame costs two bytes
    more than v1."""
    loaded_writable = loaded_writable or []
    loaded_readonly = loaded_readonly or []
    out = bytearray()
    out.append(MSG_TX)
    out.append(FLAG_ALT_INCOMPLETE if alt_incomplete else 0)
    out += encode_full_tx(ft)
    if loaded_writable:
        put_tlv(out, TLV_LOADED_WRITABLE, _flatten32(loaded_writable))
    if loaded_readonly:
        put_tlv(out, TLV_LOADED_READONLY, _flatten32(loaded_readonly))
    return bytes(out)


def decode_frame(src: bytes) -> Frame:
    """Decodes one v2 frame (the caller has already stripped the u32
    big-endian length prefix). Bounds-checked; raises :class:`BadFrame` on
    malformed input.

    A `msg_type` this decoder does not recognize is returned as
    :class:`FrameUnknown` rather than an error -- that is a deliberate skip,
    not a failure; see the module-level wire notes.
    """
    if len(src) < 2:
        raise BadFrame("frame shorter than the msg_type/flags header")
    msg_type = src[0]
    flags = src[1]
    rest = src[2:]

    if msg_type == MSG_TX:
        if flags & ~FLAG_ALT_INCOMPLETE:
            raise BadFrame("reserved flag bits set on a tx frame")
        # The v1 body is self-delimiting: decode it, then treat whatever
        # follows as the TLV trailer.
        tx, consumed = decode_full_tx_prefix(rest)
        tlvs = parse_tlvs(rest[consumed:])
        loaded_writable: List[bytes] = []
        loaded_readonly: List[bytes] = []
        for t, value in tlvs:
            if t == TLV_LOADED_WRITABLE:
                loaded_writable = _unflatten32(value)
            elif t == TLV_LOADED_READONLY:
                loaded_readonly = _unflatten32(value)
            # else: unknown TLV -- skip, do not error
        return FullTxV2(
            tx=tx,
            alt_incomplete=bool(flags & FLAG_ALT_INCOMPLETE),
            loaded_writable=loaded_writable,
            loaded_readonly=loaded_readonly,
        )

    if msg_type == MSG_HEARTBEAT:
        # alt_incomplete (bit 0) is a tx-frame-only concept, so unlike
        # MSG_TX there is no bit this message type defines: all 8 bits are
        # reserved here and MUST be zero. Do not reuse the MSG_TX
        # `~FLAG_ALT_INCOMPLETE` mask -- that would silently accept bit 0 on
        # a frame kind where it has no meaning.
        if flags != 0:
            raise BadFrame("heartbeat frame flags must be all zero")
        tlvs = parse_tlvs(rest)
        server_ts_ms = 0
        highest_seq = 0
        for t, value in tlvs:
            if t == TLV_SERVER_TS_MS:
                if len(value) != 8:
                    raise BadFrame("server_ts_ms TLV must be 8 bytes")
                server_ts_ms = struct.unpack("<Q", value)[0]
            elif t == TLV_HIGHEST_SEQ:
                if len(value) != 8:
                    raise BadFrame("highest_seq TLV must be 8 bytes")
                highest_seq = struct.unpack("<Q", value)[0]
            # else: unknown TLV -- skip, do not error
        return FrameHeartbeat(server_ts_ms=server_ts_ms, highest_seq=highest_seq)

    return FrameUnknown(msg_type=msg_type)


# ---- typed datagrams --------------------------------------------------------

DG_SIG_FIRST = 1
DG_HEARTBEAT = 2

#: `u8 type | u64 slot | u64 seq | 64B signature`
DG_SIG_FIRST_MIN = 1 + 8 + 8 + 64
#: `u8 type | u64 server_ts_ms | u64 highest_seq`
DG_HEARTBEAT_MIN = 1 + 8 + 8


@dataclass
class DatagramSigFirst:
    slot: int
    seq: int
    signature: bytes


@dataclass
class DatagramHeartbeat:
    server_ts_ms: int
    highest_seq: int


@dataclass
class DatagramUnknown:
    """Carries the type tag of a datagram this decoder does not recognize,
    so a caller can skip it deliberately rather than erroring."""

    dg_type: int


Datagram = Union[DatagramSigFirst, DatagramHeartbeat, DatagramUnknown]


def encode_dg_sig_first(slot: int, seq: int, signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("signature must be exactly 64 bytes")
    out = bytearray(DG_SIG_FIRST_MIN)
    out[0] = DG_SIG_FIRST
    struct.pack_into("<Q", out, 1, slot)
    struct.pack_into("<Q", out, 9, seq)
    out[17:81] = signature
    return bytes(out)


def encode_dg_heartbeat(server_ts_ms: int, highest_seq: int) -> bytes:
    out = bytearray(DG_HEARTBEAT_MIN)
    out[0] = DG_HEARTBEAT
    struct.pack_into("<Q", out, 1, server_ts_ms)
    struct.pack_into("<Q", out, 9, highest_seq)
    return bytes(out)


def decode_datagram(src: bytes) -> Optional[Datagram]:
    """Decodes a datagram by its type tag.

    **Each type declares a MINIMUM length, not an exact one.** A known type
    that is long enough parses, and trailing bytes are ignored -- that is
    what lets a later version add a field without breaking this decoder. An
    unknown type is reported (never an error) so the caller can skip it
    deliberately.

    Returns `None` for a known type that is too short to parse, or an empty
    datagram -- there is nothing safe to report there, but it is still not
    an error: a corrupt or truncated QUIC datagram is expected, lossy
    transport behavior, not a protocol violation to raise over.
    """
    if not src:
        return None
    t = src[0]
    if t == DG_SIG_FIRST:
        if len(src) < DG_SIG_FIRST_MIN:
            return None
        slot = struct.unpack_from("<Q", src, 1)[0]
        seq = struct.unpack_from("<Q", src, 9)[0]
        signature = bytes(src[17:81])
        return DatagramSigFirst(slot=slot, seq=seq, signature=signature)
    if t == DG_HEARTBEAT:
        if len(src) < DG_HEARTBEAT_MIN:
            return None
        server_ts_ms = struct.unpack_from("<Q", src, 1)[0]
        highest_seq = struct.unpack_from("<Q", src, 9)[0]
        return DatagramHeartbeat(server_ts_ms=server_ts_ms, highest_seq=highest_seq)
    return DatagramUnknown(dg_type=t)
