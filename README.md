# ThorNode Pulse SDKs

Official client SDKs and the public wire specification for ThorNode Pulse Decoded Shreds.

Pulse streams matching Solana transaction signatures or decoded transaction bodies over QUIC. A connection carries one of two feeds:

- **Sig-first:** compact, unordered datagrams containing slot, sequence number, and signature.
- **Full-tx:** ordered transaction frames after server enqueue.

Neither feed is a landing, confirmation, replay, or end-to-end completeness guarantee. See the [wire v2 specification](docs/PROTOCOL.md) for the exact delivery boundary.

## SDKs

| Language | Package | Guide |
| --- | --- | --- |
| Rust | `thornode-pulse` | [Rust SDK](clients/rust/README.md) |
| Python | `thornode-pulse` / `thornode_pulse` | [Python SDK](clients/python/README.md) |
| Go | `github.com/thorlabsDev/pulse-go` | [Separate Go repository](https://github.com/thorlabsDev/pulse-go) |

Use the target and token shown for the same location in the ThorNode dashboard. The SDKs validate the server certificate and hostname by default.

## Protocol resources

- [Pulse wire v2 specification](docs/PROTOCOL.md)
- [Migrating a wire v1 client](docs/MIGRATION-v1-to-v2.md)
- [Shared conformance vectors](conformance/wire-v2/README.md)
- [ThorNode Pulse documentation](https://docs.thornode.io/products/pulse)

## Development

```bash
cargo test --workspace --all-targets

cd clients/python
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
```

## Security

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md) to report it privately.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at your option.
