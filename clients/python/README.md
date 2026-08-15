# thornode-pulse

Async Python SDK for the ThorNode Pulse QUIC transaction stream (wire v2),
built on [aioquic](https://github.com/aiortc/aioquic).

```sh
pip install 'thornode-pulse[examples]'
```

The `examples` extra installs `base58` for canonical Solana signature text.
Applications that consume signature bytes directly can install just
`thornode-pulse`.

The SDK requires Python 3.9 or newer. Distribution and import names differ in
the usual Python style:

```python
import thornode_pulse
```

## Quick start

Set the target and token supplied by ThorNode, plus an account or program to
match. Use an explicit filter unless the selected access includes an unfiltered feed.

```sh
export PULSE_TARGET='<HOST:PORT_FROM_DASHBOARD>'
export PULSE_TOKEN='<TOKEN_FROM_SAME_LOCATION>'
export PULSE_ACCOUNT='<ACCOUNT_OR_PROGRAM_PUBKEY>'
```

Equivalent application code:

```python
import asyncio
import os

import base58

from thornode_pulse import Filter, PulseConnectionClosed, connect_pulse


async def main() -> None:
    target = os.environ["PULSE_TARGET"]
    flt = Filter.accounts(os.environ["PULSE_ACCOUNT"])

    try:
        async with connect_pulse(
            target,
            token=os.environ["PULSE_TOKEN"],
        ) as client:
            sub = await client.subscribe_sig_first(flt)
            async for item in sub:
                signature = base58.b58encode(item.signature).decode("ascii")
                print(item.slot, item.seq, signature)
    except PulseConnectionClosed as exc:
        print(exc.close.code, exc.close.reason, exc.close.retry_disposition.value)
        raise


asyncio.run(main())
```

Exactly one feed may be selected on a connection. Open a second
`connect_pulse(...)` context when an application needs both feeds.
The first subscription attempt consumes its connection as soon as its control
message may be sent. If subscribing fails or its acknowledgement times out,
open a new connection instead of trying another feed on the old one.

## Full transaction feed

```python
async with connect_pulse(target, token=token) as client:
    sub = await client.subscribe_full(
        Filter.accounts(program_id),
        fields=("alt",),
    )
    async for frame in sub:
        print(frame.tx.slot, len(frame.tx.signatures))
        print(sub.metrics)
```

The full feed uses one ordered QUIC stream. It is a live feed, not replay or
backfill, and the SDK does not claim end-to-end losslessness. Its local queue
is bounded; if a consumer falls behind, iteration raises `FullQueueOverflow`
when the queue reaches capacity. If neither a transaction frame nor a
heartbeat arrives within the idle budget, iteration raises `FullStreamTimeout`.

## TLS

Certificate-chain and hostname verification are enabled by default using
certifi's maintained Mozilla CA bundle. Tokens are never sent over an
unverified remote connection.

Private deployments can add a CA without replacing the default CA bundle:

```python
async with connect_pulse(target, token=token, ca_file="pulse-ca.pem") as client:
    ...
```

`server_name="<CERTIFICATE_HOSTNAME>"` sets the SNI/hostname when dialing an IP.
`certificate_sha256="..."` adds an exact SHA-256 leaf-certificate pin after
normal chain and hostname verification.

For a self-signed server running on the same machine only, the deliberately
long option `insecure_local_development=True` disables verification. The SDK
rejects this option for non-loopback targets.

## Filters and updates

`Filter` is immutable. Builder methods return copies:

```python
flt = (
    Filter.accounts(program_id)
    .excluding(blocked_account)
    .requiring(required_account)
    .with_vote(False)
)
await sub.update_filter(flt)
```

Only full-tx subscriptions accept `fields`; sig-first APIs intentionally do
not expose a meaningless enrichment argument.

## Errors, metrics, and retry decisions

QUIC closes raise `PulseConnectionClosed`, preserving typed
`CloseInfo(code, reason, frame_type)`. For Pulse application closes,
`frame_type` is `None` and `close.retry_disposition` follows the protocol:

- code 0: `normal`
- code 2: `credentials_required`
- code 3: `transient` (retry with backoff)
- codes 1, 4, and 5: `non_retryable`

Transport closes carry a non-`None` QUIC `frame_type`; their numeric codes are
not Pulse application codes and their retry disposition is `unknown`.

If a connection close interrupts a partial full-tx preamble or frame,
iteration raises `PulseStreamTruncated`, a `PulseConnectionClosed` subclass.
It preserves both `.close` and the `BadPreamble` or `BadFrame` in
`.truncation` (and as the chained cause), so retry policy never hides data
truncation.

Both subscription types expose a `metrics` snapshot with `dropped`, `queued`,
`queue_capacity`, `heartbeats`, and `last_heartbeat`. Sig-first also exposes
`gaps`, a provisional loss-or-reordering indicator.

Control acknowledgements, the full-stream preamble, and full-stream liveness
all have finite defaults. Override them together with `Timeouts(...)`.

## Development

```sh
python -m pip install -e '.[test,release]'
pytest
python -m build
twine check dist/*
```

See [CHANGELOG.md](https://github.com/thorlabsDev/pulse-sdk/blob/main/clients/python/CHANGELOG.md)
for the package/import rename and compatibility notes. The wire layout is
documented in the public
[Pulse protocol reference](https://github.com/thorlabsDev/pulse-sdk/blob/main/docs/PROTOCOL.md).

Licensed under either MIT or Apache-2.0, at your option.
