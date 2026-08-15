//! Stable, non-payload parts of the Pulse wire-v2 contract.
//!
//! Keeping these values beside the frame codec prevents the server, SDKs and
//! documentation from independently redefining protocol behavior.

/// TLS ALPN negotiated by every Pulse QUIC connection.
pub const ALPN: &[u8] = b"pulse";

/// The only wire version implemented by this release.
pub const WIRE_VERSION: u32 = 2;

/// The first control message was malformed or otherwise invalid.
pub const CLOSE_INVALID_CONTROL: u32 = 1;
/// Authentication failed, credentials were revoked, or required credentials
/// were not supplied.
pub const CLOSE_UNAUTHENTICATED: u32 = 2;
/// Admission is temporarily unavailable (for example, all subscription slots
/// are currently in use). Retry with bounded, jittered backoff.
pub const CLOSE_QUOTA_EXCEEDED: u32 = 3;
/// The first control message did not negotiate a supported wire version.
pub const CLOSE_UNSUPPORTED_VERSION: u32 = 4;
/// The authenticated tier can never use the requested Pulse entitlement or
/// subscription shape. Retrying the same request cannot succeed.
pub const CLOSE_TIER_NOT_ENTITLED: u32 = 5;

/// What a client should do after a terminal application close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// The peer closed normally. Reconnect only when the application intends
    /// to continue consuming the feed.
    Normal,
    /// The same request is invalid or permanently unsupported.
    NonRetryable,
    /// Obtain or refresh credentials before opening another connection.
    CredentialsRequired,
    /// Retry with bounded, jittered backoff.
    Transient,
    /// A future or private close code not known to this SDK version.
    Unknown,
}

/// Classifies a Pulse application close code without guessing about unknown
/// codes. In particular, unknown codes are not automatically retryable.
pub const fn classify_close_code(code: u64) -> RetryClass {
    match code {
        0 => RetryClass::Normal,
        1 | 4 | 5 => RetryClass::NonRetryable,
        2 => RetryClass::CredentialsRequired,
        3 => RetryClass::Transient,
        _ => RetryClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_close_codes_have_stable_retry_semantics() {
        assert_eq!(classify_close_code(0), RetryClass::Normal);
        assert_eq!(classify_close_code(1), RetryClass::NonRetryable);
        assert_eq!(classify_close_code(2), RetryClass::CredentialsRequired);
        assert_eq!(classify_close_code(3), RetryClass::Transient);
        assert_eq!(classify_close_code(4), RetryClass::NonRetryable);
        assert_eq!(classify_close_code(5), RetryClass::NonRetryable);
        assert_eq!(classify_close_code(99), RetryClass::Unknown);
    }
}
