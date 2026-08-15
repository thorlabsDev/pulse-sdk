# pulse wire protocol — v2

Everything a client needs to consume the pulse stream in any language. The
Rust and Python SDKs in this repository, plus the separate
[Go SDK](https://github.com/thorlabsDev/pulse-go), implement this protocol.
[`pulse-wire/src/frame.rs`](../pulse-wire/src/frame.rs) defines
the canonical payload codec, while
[`pulse-wire/src/protocol.rs`](../pulse-wire/src/protocol.rs) defines ALPN,
wire version, close codes, and retry classes. All SDKs consume the shared
[`conformance/wire-v2/vectors.json`](../conformance/wire-v2/vectors.json)
rather than maintaining independent golden bytes.

**This document describes wire v2 only. There is no v1 compatibility path.**
The server speaks v2 exclusively; a client that does not declare `"v": 2` (or
higher) on its first control message is refused (§3). Do not implement
anything from an older version of this document.

**Updating an existing v1 client?** Read
[`MIGRATION-v1-to-v2.md`](MIGRATION-v1-to-v2.md) instead — it is the change
list and the checklist, not the full specification.

## 1. Connect

- Transport: **QUIC** (TLS 1.3).
- **ALPN: `pulse`** (required).
- Clients MUST validate the server certificate and hostname for public
  endpoints. A local development endpoint may use a self-signed certificate,
  but trusting it is an explicit development-only choice; it is not appropriate
  when sending a bearer token over a network.
- Enable QUIC **DATAGRAMs** on the client (needed for the sig-first tier).

## 2. The control message

Open one **client-initiated bidirectional stream** and write a single JSON
object:

```json
{
  "token": "<optional bearer token>",
  "account_include":  ["<base58 pubkey>", "..."],
  "account_exclude":  [],
  "account_required": [],
  "vote": false,
  "full": false,
  "v": 2,
  "fields": []
}
```

| Field | Type | Default if absent | Meaning |
|---|---|---|---|
| `token` | string | `""` | Bearer token. Required on the **first** message when server auth is enabled; ignored on later update messages. |
| `account_include` | array of base58 pubkey | `[]` | Match transactions touching **any** listed key (empty = all). |
| `account_exclude` | array of base58 pubkey | `[]` | Drop transactions touching any listed key. |
| `account_required` | array of base58 pubkey | `[]` | Match only transactions touching **all** listed keys. |
| `vote` | bool or absent | absent (non-vote only) | `false` selects non-vote transactions; `true` selects vote transactions. See [§9 Vote transactions](#9-vote-transactions). |
| `full` | bool | `false` | Selects the tier. Honored **only on the first control message** — see §2.1. |
| `v` | u32 | `1` | The client's **maximum** supported wire version, not an exact match (§3). **A real client MUST send `"v": 2`** (or higher); the default of `1` exists only so an old, unmodified client fails negotiation cleanly instead of getting a type error. |
| `fields` | array of string | `[]` | Enrichment opt-in groups. Currently only `"alt"` is defined. See §10. |

**Unknown JSON fields are ignored**, not rejected — this lets a future
field ship without breaking an existing server. Conversely, the server ignores
unknown values inside `fields` for the same reason (§10).

A pubkey that fails to base58-decode, or that decodes to a length other than
32 bytes, is a **decode error** on the whole message. The server rejects the
message instead of dropping only that key.

### 2.1 The tier is fixed by the first message

`full` selects the tier and is honored **only on the connection's first
control message**:

- absent or `false` → sig-first DATAGRAM tier (§7).
- `true` → full-tx stream tier (§6).

The tier **cannot change** on a later message. A later message updates the
filter, `vote`, and `fields` (§11) but its `full` and `v` values are ignored.

### 2.2 Sending nothing

You do not need to keep the control stream open after writing your message —
close your write side (FIN) once you're done. Two distinct "nothing sent"
cases behave differently, and the difference matters:

- **You never open a control stream at all**: after the server's separate
  ~300 ms *accept* deadline the server
  closes the connection with **code 4** — with authentication disabled. (With
  authentication enabled it is code 2, unauthenticated; that check comes
  first.) There is no zero-config subscribe-all mode under wire v2: a client
  that sends nothing has declared no version, and is indistinguishable from a
  v1 client that would misparse every typed datagram it received. Since no
  control stream was ever opened, there is nowhere to write a JSON reason —
  the close code is the entire signal for this one case.
- **You open a control stream but send no bytes before FIN or the read
  deadline:** the server closes with code 2 when authentication is enabled,
  or code 1 when authentication is disabled.
- **You send incomplete or malformed JSON:** the server closes with code 1.

Once the stream has been accepted, the server gives its first control value a
separate ~300 ms read deadline.

The first control message is mandatory. There is no path on which the server
serves wire v2 bytes to a client that never asked for them.

## 3. Version negotiation and close codes

The server selects `min(client's declared "v", 2)`. If that minimum is below
`2`, negotiation fails — there is no dialect it can fall back to. This is
first-message-only: once a connection has negotiated v2, it never revisits
`v` on a later (filter-update) control message.

QUIC application close codes:

| Code | Meaning | Scope |
|---:|---|---|
| 0 | normal close | — |
| 1 | invalid control message (malformed JSON, bad pubkey, oversized, or a stream opened but never sent a complete value) | first message only |
| 2 | unauthenticated (missing/invalid/revoked token) | first message, and mid-connection on token revocation |
| 3 | quota exceeded — **transient**: the tier is entitled to pulse but is currently at its cap. Retrying later can succeed. | first message only |
| 4 | unsupported protocol version (client did not declare `v >= 2`, or never sent a control message at all with auth disabled) | first message only |
| 5 | tier not entitled — **permanent**: the tier's `pulse` cap is `0`, or the subscription requests an unfiltered feed where an account filter is required. | first message only |

> **Clients MUST NOT reconnect on code 5.** It is the one close code that says
> the same request cannot succeed unchanged. Add a permitted account filter or
> use access that includes the requested feed. Code 3 is the transient close
> and can be retried with bounded backoff.

**What actually gets written before the close, precisely:**

- **Code 4 (unsupported version)** is the *only* close that writes a JSON
  envelope on the control stream first:
  `{"type":"error","code":4,"reason":"unsupported protocol version; this server speaks wire v2"}`,
  length-prefixed per §4, followed by a close whose QUIC reason bytes are the
  plain string `"unsupported protocol version"`. The server finishes the
  envelope write before closing. A client that never opened a control stream
  (§2.2) receives only the close code and the plain-text reason
  `"no control message; cannot negotiate wire v2"`.
- **Codes 1, 2, 3 and 5** close with a **plain UTF-8 string** as the QUIC
  CONNECTION_CLOSE reason (e.g. `b"invalid control message"`,
  `b"unauthenticated"`, `b"token revoked"`, or the quota error's `Display`
  text) — **not** a JSON envelope on the control stream. If you want a
  structured reason for these, parse the close reason bytes as plain text, not
  JSON.

A **rejected filter update** (after the first message has already succeeded)
never closes the connection at all — see §11.

## 4. Control envelope framing

Every server→client message on a control bidi stream (first-message ack/error,
or a later update's ack) is one JSON object, length-prefixed:

```
[ u32 length, BIG-endian ][ JSON body (length bytes) ]
```

Reject a declared JSON length above 16,384 bytes before allocating or reading
the body.

This is the **only** other big-endian field in the protocol besides the
full-tx frame length prefix (§6) — everything else on the wire is
little-endian.

Two envelope shapes appear in practice:

```json
{"type": "ack",   "ok": true,  "v": 2}
{"type": "ack",   "ok": false, "reason": "filter limit exceeded"}
{"type": "error", "code": 4,   "reason": "unsupported protocol version; this server speaks wire v2"}
```

- **The first control message's success ack carries `"v"`** — the version the
  server actually negotiated (`min(client, 2)`). This is the **only** channel
  a sig-first subscriber has to learn which version was chosen: that tier is
  DATAGRAM-only, so there is no stream and therefore no preamble (§6) to
  confirm it another way. A later update normally omits `v`; if it is present,
  it must match the established wire version.
- The top-level `"type"` discriminator is mandatory: only `"ack"` and
  `"error"` are valid. A missing/unknown type is malformed. `"error"` is a
  rejection shape and cannot be accepted as a success. Likewise, a successful
  first `"ack"` with no `"v"` is malformed; clients MUST NOT infer v2 from
  the connection having otherwise stayed open. A successful update ack may
  omit `"v"`; a present value must equal `2`.
- A rejected first message never reaches the ack stage at all for codes 1, 2,
  3, and 5 (§3): the connection is simply closed. Code 4 gets the `error` envelope
  shown above instead of an ack.
- A rejected **update** (§11) gets `{"type":"ack","ok":false,"reason":...}`
  and the connection keeps streaming — this is the one case where `ok:false`
  does not mean the connection is about to close.
- Treat unrecognized top-level JSON fields as ignorable, matching the control
  message's own forward-compatibility rule.

### 4.1 Reading the ack: bound it, and treat a short read as a failure

A client MUST NOT wait indefinitely for an ack. **All three SDKs time the ack
read out after 10 seconds** and surface an error (`Error::AckTimeout` in Rust,
a read deadline in Go, `AckTimeout` in Python). The server acks as soon as
admission completes. The server uses separate ~300 ms deadlines to accept the
first control stream and then to read its first value; the 10-second client
ack timeout is headroom for a slow link, not a tuning knob.

Two failure modes make this mandatory rather than defensive, and neither one
produces any connection-level event to wake a blocked reader:

- **The peer accepts the control stream and then never writes and never
  closes.** Nothing at the QUIC layer is wrong; only a timeout ends the wait.
- **The control stream FINs before a complete envelope arrives** — including a
  clean 0-byte FIN, which is exactly what a pre-v2 server produces: it drops
  its send half of the control bidi, and dropping a finished send stream
  delivers a FIN. **An incomplete envelope at end-of-stream is an error, not a
  quiet "no ack".** The connection may well stay up and keep delivering
  datagrams, so a client that treats this as "still waiting" hangs forever
  with data flowing past it.

## 5. `seq`

`seq` is a per-connection, per-subscriber monotonic counter assigned to
**transactions only**. It appears on sig-first datagrams (§7), and heartbeats
report its high-water mark as `highest_seq` (§8):

- **Assigned at match time, before any droppable stage.** The distributor
  delivers with a non-blocking send and drops the delivery if a subscriber's
  channel is full. `seq` is assigned *before* that drop, not after — so a
  shed transaction still consumes a `seq` value and leaves a real,
  detectable gap. If `seq` were assigned only to transactions that actually
  made it onto the wire, the most important kind of loss (the server
  shedding load) would be the one kind a client could never see.
- **Scope: per connection.** Restarts at `0` on reconnect. The **first**
  transaction delivered on any connection is `seq == 0` — `0` is a real,
  already-assigned value, never a sentinel (contrast with `highest_seq`'s
  sentinel, §8).
- **Counts transactions only.** Heartbeats have their own frame/datagram type
  and never consume a `seq` value.
- **No delivery guarantee.** Sig-first delivery can drop, reorder, or duplicate
  transactions. A duplicate consumes its own `seq` value if it reaches the
  distributor; consumers that need uniqueness must deduplicate by signature.

**What a gap in `seq` means, and what it does not:** it is a useful delivery
signal, not an exact loss count. **There is no retransmit.** Treat it as a
metric and reconcile against an authoritative source when completeness matters.

**Gap counting over-reports under reordering, and that is expected, not a
bug.** QUIC DATAGRAMs are unordered by definition. If a subscriber tracks
loss with a scalar high-watermark (`last_seq`, monotonically advanced by
`max(last_seq, seq)` on every item), a late-arriving item that is behind the
watermark cannot be told apart from a genuinely lost one at the moment a
later item jumps ahead of it — the watermark model charges one **provisional**
gap on that jump and has no way to reverse the charge if the "lost" item
shows up afterward. A perfectly lossless but reordered stream can therefore
report a gap count greater than zero. Treat a nonzero gap count as **"loss
happened, or reordering did"** — not as an exact count of sequence numbers
that never arrived on the wire at all. (If you implement your own gap
counter, don't claim more precision than this; the three SDKs' `gaps()` /
`Gaps()` accessors document this same caveat.)

## 6. The full-tx stream

After a `{"full": true}` first control message succeeds (ack `ok:true`), the
server opens **one server-initiated unidirectional stream**.

Frames that the server has successfully enqueued into this QUIC stream are
ordered and reliable at the transport layer. That is deliberately narrower
than an end-to-end delivery promise: before enqueue, the server uses a bounded
subscriber queue and may shed transactions under load. Full-tx therefore makes
no landed, at-least-once, lossless, or completeness guarantee; consumers that
need those properties must reconcile independently.

### 6.1 Preamble

The stream opens with a fixed 6-byte preamble, written once, before any
frame:

```
offset  size  field
0       4     magic    b"PLS2"
4       1     version  u8 = 2
5       1     flags    u8, reserved, must be zero
```

i.e. the exact byte sequence `50 4C 53 32 02 00`. **A client must read and
verify this before treating anything else on the stream as a frame.** A
mismatch is a protocol error: the peer is not serving wire v2, or the stream
was corrupted in transit.

Why a stream-level preamble and not a per-frame version tag: a version byte
folded into each frame's own content cannot be sniffed reliably, because a
transaction's encoded byte content (§6.3, byte 0 is the low byte of the slot
number) takes on all 256 possible values roughly every 100 seconds — nothing
about a frame's bytes rules out any particular dialect. The preamble instead
occupies a position no frame ever writes to: the very first byte of the
*stream itself*, before any length prefix or frame exists at all. An earlier
wire format had no such header and began its stream directly with
length-prefixed frames — meaning its first stream byte was deterministically
the high byte of a `u32` big-endian length prefix on a frame capped well
under 64 KiB, i.e. always exactly `0x00`. The preamble's first byte, `0x50`
(`'P'`), can never collide with that, which is what makes a non-zero magic
at that specific position unambiguous — a discrimination a per-frame tag
could never offer.

### 6.2 Frame layout

After the preamble, the stream is a sequence of length-delimited frames:

```
[ u32 length, BIG-endian ][ frame body (length bytes) ]   …repeats…
```

Each frame body is:

```
u8  msg_type
u8  flags
    <positional transaction body, see §6.3 — MSG_TX only>
    <TLV trailer, see §6.4>
```

`msg_type`:

| Value | Meaning |
|---:|---|
| 1 | `MSG_TX` — transaction (positional body + TLV trailer) |
| 2 | `MSG_HEARTBEAT` — no positional body; TLV trailer only (§8) |
| 3 | `MSG_SHED` — reserved; wire v2 does not emit it. |

**A client MUST skip any `msg_type` it does not recognize**, using the frame's
own length prefix to find the next frame — never treat an unknown type as an
error. That is what makes new message kinds additive.

`flags` semantics depend on `msg_type`:

- **`MSG_TX`**: bit 0 = `alt_incomplete` (the ALT-loaded address set on this
  frame may be incomplete — see §10); bits 1-7 are reserved and **MUST** be
  zero. A frame with any reserved bit set is malformed and MUST be rejected.
- **`MSG_HEARTBEAT`**: **every** bit is reserved (bit 0 has no meaning on a
  heartbeat — it is not "alt_incomplete inherited from MSG_TX"). Any nonzero
  `flags` byte on a heartbeat frame is malformed.

### 6.3 The positional transaction body (`MSG_TX` only)

Exactly reproduced, byte for byte:

```
offset  size      field
0       8         slot                              (u64 LE)
8       1         num_required_signatures           (u8)
9       1         num_readonly_signed_accounts      (u8)
10      1         num_readonly_unsigned_accounts    (u8)
11      1         versioned                         (u8: 0 = legacy, 1 = v0)
12      32        recent_blockhash
44      2         signature_count        (u16 LE)   = S
…       64×S      signatures             (64 bytes each)
…       2         account_key_count      (u16 LE)   = K
…       32×K      account_keys           (32 bytes each)
…       2         instruction_count      (u16 LE)   = I
        per instruction:
          1       program_id_index       (u8)
          2       accounts_len           (u16 LE)
          …       accounts               (accounts_len bytes of u8 indexes)
          2       data_len               (u16 LE)
          …       data                   (data_len bytes)
…       2         address_table_lookup_count (u16 LE) = A
        per lookup:
          32      account_key
          2       writable_indexes_len   (u16 LE)
          …       writable_indexes
          2       readonly_indexes_len   (u16 LE)
          …       readonly_indexes
```

All multi-byte integers inside the body are **little-endian**. A decoder must
bounds-check every length before allocating and, when asked to consume the
body in isolation, reject trailing bytes — but note that inside a `MSG_TX`
frame this body is **not** the end of the frame: whatever follows it up to
the frame's length prefix is the TLV trailer (§6.4), which is why the wire
decoder treats this body as self-delimiting (decode until its fields are
exhausted, note the offset) rather than requiring it to consume everything.

`fee_payer`, `program_ids`, static writable accounts, and the ComputeBudget
fields are all derivable from this body client-side — see §12. They are
**not** separate wire fields.

### 6.4 TLV trailer

Everything in a frame body after `msg_type | flags | (positional body if
`MSG_TX`)` is a sequence of TLV records, repeated until the frame's length
prefix is exhausted:

```
u8  type
u16 len      (little-endian)
u8  value[len]
```

`len` is `u16`, not `u8`, specifically because a loaded-address list is 32
bytes per address and an ALT-heavy transaction can load dozens of them — a
`u8` length would cap at 7 addresses.

| Type | Field | Value | Frame kinds |
|---:|---|---|---|
| 1 | `loaded_writable_addresses` | `len/32` × 32-byte pubkeys, in lookup order | `MSG_TX` |
| 2 | `loaded_readonly_addresses` | same | `MSG_TX` |
| 3 | `server_ts_ms` | u64 LE | `MSG_HEARTBEAT` |
| 4 | `highest_seq` | u64 LE — sentinel `u64::MAX`, see §8 | `MSG_HEARTBEAT` |

Rules, in the order a decoder should apply them:

- **Order is not significant** — parse the whole trailer, then dispatch on
  type.
- **An unknown `type` MUST be skipped**, never rejected — this is the
  forward-compatibility mechanism for adding fields later.
- **A duplicate `type` is a protocol error.** Reject the whole frame instead
  of choosing one occurrence.
- A heartbeat emitted by wire v2 contains both TLV type 3 and type 4. The
  reference decoders use `0` when either field is absent. For
  `highest_seq`, `0` is a real assigned sequence value; only the explicit
  `u64::MAX` value means that no transaction has been assigned (§8).

### 6.5 End of stream: a truncated frame is loss, not a clean close

A close is clean **only on a frame boundary** — before a length prefix. Once
the 4-byte length prefix has been read, the sender has stated how many bytes
are coming; if the stream ends before all of them arrive (including the case
where *none* of the body arrives, and the case of a partial length prefix),
that is a **truncated frame and MUST be reported as an error**, not as a
normal end of stream. All three SDKs agree on this (`ErrBadFrame` in Go,
`Error::BadFrame` in Rust, `BadFrame` in Python). If a QUIC application close
arrives with the truncation, preserve **both** facts: the framing error records
that bytes were lost, while `{code, reason}` supplies the terminal retry
classification. Do not replace one with the other.

The distinction matters because the two look identical to a caller that only
checks for "the iterator ended": reporting a truncation as a clean close turns
a transport failure into silence. An incomplete **preamble** is a separate case
with its own error (§6.1).

### 6.5.1 Maximum frame size

`MAX_FULL_TX_BODY = 65536` (64 KiB) limits the complete remainder of a
`MSG_TX` frame after `msg_type` and `flags`: the positional body and TLV trailer
combined. Reject a transaction frame when that remainder exceeds 65,536 bytes.

`MAX_FULL_TX_FRAME` limits the outer `u32` frame length before the message type
is known:

```
MAX_FULL_TX_FRAME = MAX_FULL_TX_BODY + 2 × (65535 + 3) + 2
                   = 65536          + 2 × 65538        + 2
                   = 196614 bytes
```

Reject an outer length above 196,614 before allocating or reading the frame.
For `MSG_TX`, apply the 65,536-byte inner limit after reading the type and
flags. The outer value is an allocation ceiling, not a valid encoded
transaction size.

## 7. Datagrams (sig-first tier)

The server sends one QUIC **DATAGRAM** per matching transaction, plus
periodic heartbeat datagrams (§8). Every datagram starts with a one-byte type
tag at offset 0. All integers are little-endian.

| Type | Meaning | Layout | Minimum length |
|---:|---|---|---:|
| 1 (`DG_SIG_FIRST`) | one matched transaction | `u8 type=1 \| u64 slot \| u64 seq \| 64B signature` | 81 |
| 2 (`DG_HEARTBEAT`) | liveness / tail-loss signal | `u8 type=2 \| u64 server_ts_ms \| u64 highest_seq` | 17 |

**Each type declares a MINIMUM length, not an exact one.** A datagram of a
known type that is at least that long parses successfully and **any trailing
bytes beyond the known fields must be ignored** — this is what lets a future
wire revision append a field to a datagram without breaking this decoder. A
known type shorter than its minimum is malformed (reject it, do not attempt a
partial parse). An unrecognized type tag must be skipped, never treated as an
error.

Sig-first datagrams are fire-and-forget: no head-of-line blocking. They can be
dropped, reordered, or duplicated by the delivery path, so they are neither
lossless nor at-least-once. Enrichment (§10) never reaches this tier under any
subscription; its entire value proposition is staying small (81 bytes, fixed).

## 8. Heartbeats

Both tiers carry periodic heartbeats for idle-stream liveness. On sig-first,
they can reveal **trailing** loss that item-to-item comparison alone cannot
show. Full-tx heartbeats expose a high-water mark, but do not turn the feed into
an end-to-end completeness guarantee.

- **Sig-first tier:** a `DG_HEARTBEAT` datagram (§7).
- **Full-tx tier:** a `MSG_HEARTBEAT` frame — `msg_type=2, flags=0`, TLV types
  3 (`server_ts_ms`) and 4 (`highest_seq`) in the trailer (§6.4).

**Cadence:** every 10 seconds of stream idleness — **not** a fixed metronome.
The server resets its heartbeat timer on every real send (transaction
datagram or frame), so a busy stream may go much longer than 10 seconds
between heartbeats, and a heartbeat firing is itself a signal that the stream
has gone quiet for a full interval.

**`highest_seq` — the sentinel, precisely:** the wire value `u64::MAX` means
"no transaction has been assigned to this subscriber yet." **`0` is a real,
already-assigned sequence value** (§5) — the first delivery on any connection
is `seq == 0` — so a client must never treat `0` as "nothing sent." The
converse matters just as much: a client must never compute a gap by comparing
against the `u64::MAX` sentinel (that would report an absurd multi-quintillion
gap) and must never install the sentinel as a baseline "last known seq" —
doing so and later comparing a real `seq` against it produces the same bogus
result. The correct handling is: if `highest_seq` is the sentinel, ignore the
heartbeat for gap-tracking purposes entirely (no baseline change, no gap
charged). Otherwise, if you have no prior baseline, adopt it as your baseline
without alleging a gap (you have no evidence anything was lost before your
first observation); if you do have a prior baseline and this value is
higher, the difference is trailing loss.

When not the sentinel, `highest_seq` is the **highest `seq` value the server
has assigned to that subscriber so far** (0-indexed, per §5) — not a count of
assignments. After N deliveries to a subscriber, the assigned values are
`0..N-1`, so `highest_seq` reads `N-1`, not `N`; this is exactly the same
0-indexing `seq` itself uses (§5), and it is why `0` is a real value here
too, not "one transaction assigned." This applies on the sig-first tier,
where every datagram also carries `seq` explicitly. On the full-tx tier
there is no per-frame sequence number — `highest_seq` is still reported, but
a client cannot compute a numeric gap from it the way a sig-first subscriber
can; treat it as a raw signal to compare against your own received-frame
count if useful, keeping the 0-indexing in mind.

## 9. Vote transactions

The server excludes Solana vote transactions by default. The `vote` control
field mirrors Yellowstone's `vote` semantics:

- **absent / omitted** → select non-vote transactions;
- `false` → select non-vote transactions;
- `true` → select vote transactions only.

A transaction is classified as a vote when it is a single instruction
invoking the Vote program (`Vote111111111111111111111111111111111111111`) —
the same `is_simple_vote_transaction` rule Geyser/Yellowstone uses. A tx that
merely lists the vote key without invoking it, or carries additional
instructions, is **not** a vote.

The `vote` predicate ANDs with the account predicates:

- `vote: true` **with no account filter** narrows to **vote txs only** — it
  does **not** mean "votes in addition to non-votes."
- `account_include=[Vote111…]` **with `vote: false`** yields the **empty
  set** (the account predicate matches vote txs; the vote predicate then
  excludes them).
- **There is no single subscription that returns votes and non-votes
  together.** `absent` and `false` both give non-votes only; `true` gives
  votes only. To receive both, open **two** subscriptions and merge
  client-side.

**Account filtering and ALT resolution.** `account_include` / `account_exclude`
/ `account_required` are matched against a transaction's *static* account
keys plus, when the server's ALT resolution for that transaction succeeded,
its resolved `loaded_writable` and `loaded_readonly` addresses — not just the
static keys. When a transaction's ALT resolution is **incomplete**
(`alt_incomplete`, a `MSG_TX` flags bit, §6.2/§10) and the subscription has any `account_exclude`
entries, the server conservatively **drops** that transaction rather than
risk delivering it to a filter it might actually match; this conservative
drop applies only to `account_exclude` (an incomplete resolution can never
cause an under-broad `account_include`/`account_required` to over-match, so
those are unaffected).

> A `failed` (execution-status) filter is **not supported**: shreds carry no
> execution status, so the server cannot know whether a tx succeeded.

## 10. Enrichment (`fields`)

Everything a client can already compute from bytes the frame carries — fee
payer, program ids, the static writable set, compute-budget price/limit — is
**not** shipped as enrichment; see §12. Enrichment covers only what a client
genuinely cannot compute itself, because it does not have the address-lookup
tables the server resolved ALT references against:

- `loaded_writable_addresses` (TLV type 1)
- `loaded_readonly_addresses` (TLV type 2)
- `alt_incomplete` (flags bit 0 on a `MSG_TX` frame)

**Opt-in shape:** the control message's `fields` array names enrichment
groups. Today only `"alt"` is defined. It controls the two resolved-address
TLVs (types 1 and 2); it does **not** gate `alt_incomplete`. That flag is an
independent property of every full-tx transaction frame and is present for bare
and enriched subscriptions alike. `fields` is a list, not a boolean,
specifically so a future group can be added without changing what an old client
that only asked for `"alt"` receives. Unrecognized group names inside `fields`
are ignored, not rejected.

**`fields` applies to filter UPDATEs, not only to the first control
message.** `full` (§2.1) is immutable after the first message because it
selects the delivery tier. `fields` only changes the contents of frames on an
already-open full-tx stream, so an update takes effect on subsequent frames.
An update that
**omits** `fields` sets enrichment to **off** (the empty-list default), not
"leave it as it was" — see §11 for why control messages are not partial
patches.

**Enrichment never reaches the sig-first tier**, under any subscription.
Wire v2 currently emits 81-byte transaction datagrams and 17-byte heartbeat
datagrams; decoders still accept longer datagrams as described in §7.

## 11. Filter updates

To change your filter, `vote`, or `fields` after the first control message,
open another client-initiated bidi stream and send another control JSON
object. The response is the same length-prefixed ack envelope as the first
message (§4), minus the `v` key.

**A control message — first or update — is a complete subscription selection,
not a partial patch.** An update message replaces
`account_include`/`account_exclude`/`account_required`, `vote`, and `fields`
wholesale; any field you omit resets to that field's default, it does not
carry over from your previous message. Concretely: if your first message set
`fields: ["alt"]` and your update message omits `fields` entirely, enrichment
turns **off** — it does not stay on. `token` and `full` are read but ignored
on an update (auth is validated once at connection admission; the tier is
fixed at first message).

**A rejected update does not close the connection.** It is acked
`{"type":"ack","ok":false,"reason":"..."}` and the connection **keeps
streaming under the previous filter** — contrast this with a rejected first
message, which always closes the connection because there is no prior
subscription to fall back to (§3).

**Filter updates are not atomic.** Frames already sitting in a subscriber's
bounded delivery channel were matched under the previous filter and
will still be delivered after you receive the update's `ok:true` ack. The ack
means "applied going forward from here," not "the exact boundary between old
and new is this frame." Do not assume otherwise when reconciling a filter
change against what you actually received.

## 12. Derived fields (client-side, not on the wire)

These values are **not** separate wire fields. Compute them from the decoded
transaction body (§6.3), or use the helpers in
`thornode_pulse_wire::derive`, `derive.go`, and `derive.py`:

| Field | How to compute |
|---|---|
| `fee_payer` | `account_keys[0]` (`None`/absent if the transaction has no account keys). |
| `program_ids` | Resolve each instruction's `program_id_index` against `account_keys`, in first-use order, deduplicated. Solana forbids an ALT-sourced program id, so this is complete without any lookup-table resolution — no dependency on enrichment (§10). |
| `writable_accounts` (static) | Fall out of the three header counts: signed-writable = `account_keys[0 .. num_required_signatures - num_readonly_signed_accounts]`; unsigned-writable = `account_keys[num_required_signatures .. len - num_readonly_unsigned_accounts]`. This is the **static** writable set only — ALT-loaded writables are the separate `loaded_writable_addresses` enrichment field (§10), not part of this helper. |
| `compute_unit_price` | Find the ComputeBudget-program (`ComputeBudget111111111111111111111111111111`) instruction whose first data byte is discriminator `3` (`SetComputeUnitPrice`); the following 8 bytes, little-endian, are micro-lamports per compute unit. |
| `compute_limit` | Same search with discriminator `2` (`SetComputeUnitLimit`); the following 4 bytes, little-endian, are the unit limit. |

**`None`/absent is not zero.** If a transaction sets no explicit compute-unit
price or limit, both helpers return "not present," never `0`. Do not replace
an absent field with a runtime default; that value is not encoded in the
transaction bytes.

To calculate transaction size, use the byte length of the positional body
(§6.3), or `frame_length - 2 - TLV_trailer_length` for a `MSG_TX` frame.

## 13. Authentication & quotas

The control message's optional `"token"` field carries a bearer token. When
server auth is enabled, it is required on the **first** control message;
missing or invalid credentials close the connection with code 2 (§3).

Per-tier quotas cap each token's concurrent live subscriptions and total
account-filter entries. Account quota counts `account_include` plus
`account_required`; `account_exclude` does not count. An unfiltered
subscription (no `account_include` and no `account_required`) is rejected on
tiers with an account cap. A temporary capacity breach on the **first** message
closes the connection with code 3; a permanently disallowed entitlement or
subscription shape closes with code 5. An update rejection is handled per §11
(`ack ok:false`, connection keeps streaming under the previous filter).

## Reference implementations

| Language | SDK | Frame decoders |
|---|---|---|
| Rust   | [`clients/rust`](../clients/rust) | `thornode_pulse_wire::frame`, re-exported from `thornode_pulse` |
| Go     | [`thorlabsDev/pulse-go`](https://github.com/thorlabsDev/pulse-go) | `frame.go` |
| Python | [`clients/python`](../clients/python) | `thornode_pulse/frame.py` |

Use `pulse-wire/src/frame.rs`, `pulse-wire/src/protocol.rs`, and the shared
`conformance/wire-v2/vectors.json` fixture when testing another implementation.
