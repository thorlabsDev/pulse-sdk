# Migrating a pulse client from wire v1 to v2

> Normative reference: [`PROTOCOL.md`](PROTOCOL.md). This page is the change
> list and the minimum you must do. Where the two disagree, `PROTOCOL.md`
> wins.

The pulse QUIC wire changed in a single breaking step. **There is no
compatibility mode and no negotiation down to v1** — the server speaks v2
only. This was deliberate: the format now carries its own version, so a
future addition can ship without another break.

Your client must be updated. This page tells you exactly what to change.

---

## The symptom

If you connect with an unmodified v1 client, you will see one of these, and
**no transactions at all**:

| What you see | Why |
|---|---|
| Connection closed, application error code **4**, reason `unsupported protocol version` | Your control message did not declare `"v": 2`. This is the normal v1 client outcome. |
| Connection closed, code **4**, reason `no control message; cannot negotiate wire v2` | You connected and sent nothing. Under v1 that defaulted to the signature firehose; under v2 it is refused, because silence is indistinguishable from a v1 client. |
| A custom v2 connection receives datagrams, but slots and signatures decode incorrectly | Its control message requests v2 while its datagram parser still uses the v1 layout. See §2 — the length changed from 72 to 81 bytes and the first byte is now a type tag, not the slot. |

The failure is loud by design. Nothing silently misparses if you follow this
page.

---

## 1. The control message: add `"v": 2`

This is the one change every client needs, regardless of tier.

```diff
 {
   "token": "...",
   "account_include": ["..."],
-  "full": false
+  "full": false,
+  "v": 2
 }
```

`v` is your client's **maximum** supported version, not an exact match. The
server negotiates `min(yours, 2)`. Omitting it means `1`, which is refused.

Open the first control stream within the server's ~300 ms accept deadline, then
send its complete first JSON value within a separate ~300 ms read deadline.

**New: the server now acks your control message.** Read it — it is
length-prefixed JSON on the same bidirectional stream you wrote to:

```
[ u32 length, BIG-endian ][ JSON body ]
```

```json
{"type": "ack", "ok": true, "v": 2}
```

Require the `"type":"ack"` discriminator and require `"v":2` on this first
success. Missing/unknown `type`, or an initial success with no `v`, is a
protocol error. A later filter-update ack may omit `v`; if present, it must
match the established wire version.

**Bound this read.** All three official SDKs time it out after 10 seconds. An
incomplete envelope at end-of-stream is an **error**, not a quiet "no ack" —
a pre-v2 server produces exactly that (a clean 0-byte FIN) while the
connection stays up and keeps delivering datagrams, so a client that treats it
as "still waiting" hangs forever with data flowing past it. See
[`PROTOCOL.md` §4.1](PROTOCOL.md).

---

## 2. Sig-first tier: the datagram grew from 72 to 81 bytes

**v1** — 72 bytes, no type tag:

```
[ u64 slot, LE ][ 64-byte signature ]
```

**v2** — 81 bytes minimum:

```
[ u8 type = 1 ][ u64 slot, LE ][ u64 seq, LE ][ 64-byte signature ]
   offset 0        offset 1        offset 9        offset 17
```

Three rules that were not in v1:

1. **Read the first byte as a type tag.** `1` = signature notification,
   `2` = heartbeat. **Any other value: skip the datagram**, do not error. That
   is how a future datagram type ships without breaking you.
2. **The lengths above are minimums, not exact.** A datagram of the right type
   that is *longer* than the minimum is valid — parse the fields you know and
   **ignore the trailing bytes**. A v1 client's `if len != 72` check is the
   single most common way to break on the next additive change; do not
   reproduce it as `if len != 81`. Reject only when the datagram is *shorter*
   than the minimum for its type.
3. **`seq` is new** — a per-connection counter, starting at 0, assigned to
   transactions before the server's droppable handoff. Use gaps as a delivery
   signal, not as an exact loss tally: sig-first can drop, reorder, or
   duplicate transactions and has no retransmit/at-least-once guarantee.

A gap count **over-reports under reordering**: QUIC datagrams are unordered by
definition, so the first out-of-order arrival charges one gap that is never
reversed. Read a non-zero count as "loss happened, or reordering did", not as
an exact loss tally.

---

## 3. Full-tx tier: a preamble, then typed frames

Frames that the server successfully enqueues into the QUIC stream are ordered
and reliable. The bounded subscriber queue can shed transactions before
enqueue, so full-tx is not an end-to-end lossless, at-least-once, landed, or
completeness guarantee.

### 3.1 The stream now opens with a 6-byte preamble

Before any frame, read and verify exactly six bytes:

```
50 4C 53 32 02 00        ("PLS2", version 2, reserved 0)
```

Anything else: fail the subscription. Do not try to parse what follows.

This exists because a per-frame version byte was impossible — byte 0 of a v1
frame body is the low byte of the slot, which cycles through all 256 values
about every 100 seconds, so version sniffing would have failed on a schedule.

Once a frame length prefix begins, a close before its complete body is a
truncation, not a clean end. If an application close `{code, reason}` arrives
at the same time, preserve both the bad-frame signal and the close context.

### 3.2 Each frame gained a 2-byte header and a trailer

**v1:**

```
[ u32 length, BE ][ body ]
```

**v2:**

```
[ u32 length, BE ][ u8 msg_type ][ u8 flags ][ body ][ TLV trailer ]
```

- `msg_type`: `1` = transaction, `2` = heartbeat. **Any other value: skip the
  frame** using its length prefix. Do not error.
- `flags`: on a transaction frame, bit 0 = `alt_incomplete`. **All other bits
  are reserved** — if any is set, treat the frame as malformed. On a heartbeat
  frame every bit is reserved.
- **The body is byte-for-byte identical to v1's.** Your existing body decoder
  does not change. You are adding two bytes in front and a trailer behind.

### 3.3 The TLV trailer

Zero or more entries, each:

```
[ u8 type ][ u16 length, LE ][ value ]
```

| Type | Meaning |
|---|---|
| 1 | ALT-loaded **writable** addresses (multiple of 32 bytes) |
| 2 | ALT-loaded **read-only** addresses (multiple of 32 bytes) |
| 3 | server timestamp, ms (u64 LE, heartbeat) |
| 4 | `highest_seq` (u64 LE, heartbeat) |

**Skip unknown TLV types** using their length — this is the main extension
point. A **duplicate** type in one trailer is malformed.

Types 1 and 2 appear only with `"fields": ["alt"]`. `alt_incomplete`, by
contrast, is the `MSG_TX` flags bit: it is not a TLV and is not gated by
`fields`, so it can be set on a bare full-tx frame.

Types 1 and 2 only appear if you opt in with `"fields": ["alt"]` in the
control message. They give you the accounts a versioned (v0) transaction
actually touches, resolved from its address lookup tables, without you having
to resolve them yourself.

### 3.4 Heartbeats are new

Every 10 seconds **on an idle stream** (the timer resets on every send, so a
busy subscription never sees one). A heartbeat carries the server timestamp
and `highest_seq` — the highest `seq` the server has assigned you.

`highest_seq == u64::MAX` is a **sentinel** meaning "nothing assigned yet". It
is not a count and not a real sequence number. Never install it as a baseline
and never compute a gap from it. `0`, by contrast, is a real assigned value.

---

## 4. Filter updates

Sending a second control message updates your filter and returns an ack. Filter
updates follow these rules:

- **The tier is fixed by your first message.** `full` and `v` are ignored on
  updates.
- On full-tx, **`fields` is not fixed** — you can turn ALT enrichment on or off
  later. Sig-first APIs do not accept enrichment fields and send an empty list.
- **The update is not atomic.** Frames already queued under the old filter
  still arrive after the ack. Do not assume the first frame after an ack
  matches the new filter.
- A **rejected update does not close the connection** — you get
  `{"type":"ack","ok":false,"reason":"..."}` and your existing subscription
  keeps streaming. Only a failed *first* message closes.

---

## 5. Checklist

- [ ] Send `"v": 2` on the first control message.
- [ ] Read the length-prefixed ack, with a timeout; treat a short/absent
      envelope as an error; require `type:"ack"` plus `v:2` on initial success.
- [ ] Sig-first: switch to the 81-byte layout, dispatch on the type tag, and
      use a **minimum**-length check, not an equality check.
- [ ] Sig-first: skip unknown datagram types instead of erroring.
- [ ] Full-tx: read and verify the 6-byte preamble before the first frame.
- [ ] Full-tx: parse `msg_type` + `flags`, skip unknown message types by
      length, reject reserved flag bits.
- [ ] Full-tx: parse the TLV trailer, skipping unknown types.
- [ ] Optional but recommended: track `seq` gaps as your loss signal, and opt
      into `"fields": ["alt"]` if you consume versioned transactions.

---

## 6. The easy path

The official SDKs already implement these changes:

- Rust: [`thornode-pulse`](https://github.com/thorlabsDev/pulse-sdk/tree/main/clients/rust)
- Go: [`github.com/thorlabsDev/pulse-go`](https://github.com/thorlabsDev/pulse-go)
- Python: [`thornode-pulse`](https://github.com/thorlabsDev/pulse-sdk/tree/main/clients/python)

Use an SDK unless you need a client for another language. Custom clients can
verify their framing and close-code handling with the shared
[`conformance/wire-v2/vectors.json`](../conformance/wire-v2/vectors.json)
fixture.
