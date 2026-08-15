# Changelog

## 0.1.0

Initial public preview of `thornode-pulse` for Pulse wire v2.

### Compatibility

- The distribution is `thornode-pulse`; import it as `thornode_pulse`.
- Install the `examples` extra for canonical base58 signature rendering in
  the bundled examples; `base58` is not a core runtime dependency.
- The earlier unpublished `pulse-client` / `pulse_client` names are not kept as
  aliases. Update imports before installing this release.
- Certificate and hostname verification are enabled by default. Development
  deployments using a private CA must pass `ca_file`, `ca_path`, or `ca_data`.
- One connection carries exactly one sig-first or full-tx feed.
- A first subscription attempt consumes the connection even when its ack is
  missing, malformed, or times out; retry by opening a new connection.
- `connect_pulse` accepts the dashboard's `host:port` target directly,
  including bracketed `[IPv6]:port` targets.
- Sig-first subscribe/update APIs no longer accept `fields`; enrichment fields
  apply only to full-tx.
- `Filter` values are immutable; fluent methods return a new value.
- Connection closes surface as `PulseConnectionClosed` with `CloseInfo.code`,
  `CloseInfo.reason`, `CloseInfo.frame_type`, and protocol-defined retry
  classification. QUIC transport codes are not misclassified as Pulse
  application-close codes.
- Initial subscription success requires an explicit wire-v2 ack; update acks
  may omit their already-negotiated version.
- A close that interrupts a partial full-tx preamble or frame surfaces as
  `PulseStreamTruncated`, preserving both the typed close and truncation error.
- The full-tx queue and all protocol waits are bounded. Queue overflow and idle
  timeout are explicit terminal errors rather than silent loss or an endless
  wait.
