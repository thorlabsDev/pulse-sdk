# thornode-pulse-wire

Canonical, dependency-free Rust codec and protocol constants for Thornode
Pulse wire v2.

This crate intentionally contains no server, transport, authentication, or
retry implementation. Use `thornode-pulse` for the reference QUIC client.
Cross-language golden vectors live in `conformance/wire-v2` in the source
repository.

Licensed under either MIT or Apache-2.0, at your option.
