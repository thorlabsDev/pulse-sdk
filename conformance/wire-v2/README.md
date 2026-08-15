# Pulse wire-v2 conformance vectors

`vectors.json` is the shared cross-language golden fixture for the canonical
codec in `pulse-wire/src/frame.rs` and protocol constants in
`pulse-wire/src/protocol.rs`.

Regenerate it from code with:

```sh
cargo run -q -p thornode-pulse-wire --example generate_conformance
```

Rust, Go, and Python tests decode this same fixture. Multi-byte payload fields
are little-endian. The full-stream record length and control-envelope length
are the two big-endian prefixes.
