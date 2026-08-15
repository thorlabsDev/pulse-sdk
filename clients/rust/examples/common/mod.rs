use std::net::SocketAddr;

use thornode_pulse::{Error, PulseClient, Result};

pub async fn connect(endpoint: &str, token: Option<String>) -> Result<PulseClient> {
    let insecure_local_dev = std::env::var("PULSE_INSECURE_LOCAL_DEV")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"));
    if insecure_local_dev {
        let addr: SocketAddr = endpoint.parse().map_err(|error| {
            Error::InvalidEndpoint(format!(
                "PULSE_INSECURE_LOCAL_DEV requires a loopback SocketAddr: {error}"
            ))
        })?;
        return match token {
            Some(token) => {
                PulseClient::dangerous_connect_insecure_local_dev_with_token(addr, token).await
            }
            None => PulseClient::dangerous_connect_insecure_local_dev(addr).await,
        };
    }

    match token {
        Some(token) => PulseClient::connect_with_token(endpoint.to_owned(), token).await,
        None => PulseClient::connect(endpoint.to_owned()).await,
    }
}
