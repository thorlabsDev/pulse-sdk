use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use thornode_pulse::{Error, Filter, PulseClient, RetryClass};

struct TestServer {
    addr: SocketAddr,
    certificate_der: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum ServerBehavior {
    WaitForClose,
    CloseAfterControl(u32, &'static [u8]),
    AckWithoutVersion,
    TruncateFullThenClose(Truncation, u32, &'static [u8]),
}

#[derive(Clone, Copy)]
enum Truncation {
    Preamble,
    Prefix,
    Body,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn test_server(dns_name: &str, behavior: ServerBehavior) -> TestServer {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let identity = rcgen::generate_simple_self_signed(vec![dns_name.to_owned()]).unwrap();
    let certificate_der = identity.cert.der().to_vec();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key_pair.serialize_der(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.der().clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"pulse".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(connection) = incoming.await else {
            return;
        };
        match behavior {
            ServerBehavior::WaitForClose => {
                let _ = connection.closed().await;
            }
            ServerBehavior::CloseAfterControl(code, reason) => {
                // Wait until the SDK has completed TLS and sent its first
                // control stream, proving the close is a terminal protocol
                // event rather than a handshake error.
                if let Ok((_send, mut recv)) = connection.accept_bi().await {
                    let _ = recv.read_to_end(64 * 1024).await;
                    connection.close(quinn::VarInt::from_u32(code), reason);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            ServerBehavior::AckWithoutVersion => {
                if let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let _ = recv.read_to_end(64 * 1024).await;
                    let body = br#"{"type":"ack","ok":true}"#;
                    let _ = send.write_all(&(body.len() as u32).to_be_bytes()).await;
                    let _ = send.write_all(body).await;
                    let _ = send.finish();
                    connection.closed().await;
                }
            }
            ServerBehavior::TruncateFullThenClose(truncation, code, reason) => {
                if let Ok((mut control_send, mut control_recv)) = connection.accept_bi().await {
                    let _ = control_recv.read_to_end(64 * 1024).await;
                    let body = br#"{"type":"ack","ok":true,"v":2}"#;
                    let _ = control_send
                        .write_all(&(body.len() as u32).to_be_bytes())
                        .await;
                    let _ = control_send.write_all(body).await;
                    let _ = control_send.finish();

                    if let Ok(mut stream) = connection.open_uni().await {
                        match truncation {
                            Truncation::Preamble => {
                                let _ = stream
                                    .write_all(&thornode_pulse_wire::frame::PREAMBLE[..3])
                                    .await;
                            }
                            Truncation::Prefix => {
                                let _ =
                                    stream.write_all(thornode_pulse_wire::frame::PREAMBLE).await;
                                let _ = stream.write_all(&[0, 0, 1]).await;
                            }
                            Truncation::Body => {
                                let _ =
                                    stream.write_all(thornode_pulse_wire::frame::PREAMBLE).await;
                                let _ = stream.write_all(&64u32.to_be_bytes()).await;
                                let _ = stream.write_all(&[1, 0, 0]).await;
                            }
                        }
                        // Give the client time to verify the preamble and enter
                        // its frame read before terminating the whole connection.
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        connection.close(quinn::VarInt::from_u32(code), reason);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    });
    TestServer {
        addr,
        certificate_der,
        task,
    }
}

#[tokio::test]
async fn custom_ca_keeps_hostname_verification_and_connects() {
    let server = test_server("localhost", ServerBehavior::WaitForClose).await;
    let client = PulseClient::builder(format!("localhost:{}", server.addr.port()))
        .add_custom_ca_der(server.certificate_der.clone())
        .connect()
        .await
        .expect("custom trust anchor with matching DNS SAN must connect");
    drop(client);
}

#[tokio::test]
async fn untrusted_or_wrong_hostname_certificate_is_rejected() {
    let untrusted = test_server("localhost", ServerBehavior::WaitForClose).await;
    assert!(
        PulseClient::connect(format!("localhost:{}", untrusted.addr.port()))
            .await
            .is_err()
    );

    let wrong_name = test_server("not-localhost.invalid", ServerBehavior::WaitForClose).await;
    assert!(
        PulseClient::builder(format!("localhost:{}", wrong_name.addr.port()))
            .add_custom_ca_der(wrong_name.certificate_der.clone())
            .connect()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn insecure_constructor_rejects_non_loopback_before_connecting() {
    let addr = "192.0.2.1:443".parse().unwrap();
    let error =
        match PulseClient::dangerous_connect_insecure_local_dev_with_token(addr, "secret").await {
            Ok(_) => panic!("public addresses must never use unverified TLS"),
            Err(error) => error,
        };
    assert_eq!(error, Error::InsecureEndpointNotLoopback(addr));
}

#[tokio::test]
async fn terminal_application_close_preserves_code_reason_and_retry_class() {
    let server = test_server(
        "localhost",
        ServerBehavior::CloseAfterControl(3, b"capacity temporarily unavailable"),
    )
    .await;
    let client = PulseClient::builder(format!("localhost:{}", server.addr.port()))
        .add_custom_ca_der(server.certificate_der.clone())
        .connect()
        .await
        .unwrap();
    let error = match client.subscribe_sig_first(&Filter::all()).await {
        Ok(_) => panic!("server closes instead of acknowledging"),
        Err(error) => error,
    };
    let Error::ApplicationClosed(close) = error else {
        panic!("expected typed application close, got {error:?}");
    };
    assert_eq!(close.code, 3);
    assert_eq!(close.reason, "capacity temporarily unavailable");
    assert_eq!(close.retry_class(), RetryClass::Transient);
    assert!(close.retryable());
}

#[tokio::test]
async fn successful_initial_ack_without_version_is_rejected() {
    let server = test_server("localhost", ServerBehavior::AckWithoutVersion).await;
    let client = PulseClient::builder(format!("localhost:{}", server.addr.port()))
        .add_custom_ca_der(server.certificate_der.clone())
        .connect()
        .await
        .unwrap();
    let error = match client.subscribe_sig_first(&Filter::all()).await {
        Ok(_) => panic!("the initial ack must prove the negotiated wire version"),
        Err(error) => error,
    };
    assert_eq!(error, Error::MissingVersion);
}

#[tokio::test]
async fn truncated_full_frame_preserves_application_close_context() {
    for truncation in [Truncation::Prefix, Truncation::Body] {
        let server = test_server(
            "localhost",
            ServerBehavior::TruncateFullThenClose(
                truncation,
                3,
                b"capacity temporarily unavailable",
            ),
        )
        .await;
        let client = PulseClient::builder(format!("localhost:{}", server.addr.port()))
            .add_custom_ca_der(server.certificate_der.clone())
            .connect()
            .await
            .unwrap();
        let mut sub = client.subscribe_full(&Filter::all(), &[]).await.unwrap();
        let error = sub.next().await.unwrap_err();
        assert!(error.is_bad_frame(), "truncation was lost: {error:?}");
        let close = error
            .close_info()
            .expect("application close context was lost");
        assert_eq!(close.code, 3);
        assert_eq!(close.reason, "capacity temporarily unavailable");
    }
}

#[tokio::test]
async fn truncated_preamble_preserves_application_close_context() {
    let server = test_server(
        "localhost",
        ServerBehavior::TruncateFullThenClose(
            Truncation::Preamble,
            3,
            b"capacity temporarily unavailable",
        ),
    )
    .await;
    let client = PulseClient::builder(format!("localhost:{}", server.addr.port()))
        .add_custom_ca_der(server.certificate_der.clone())
        .connect()
        .await
        .unwrap();
    let error = match client.subscribe_full(&Filter::all(), &[]).await {
        Ok(_) => panic!("the preamble is intentionally truncated"),
        Err(error) => error,
    };
    assert!(
        error.is_bad_preamble(),
        "preamble error was lost: {error:?}"
    );
    let close = error
        .close_info()
        .expect("application close context was lost");
    assert_eq!(close.code, 3);
    assert_eq!(close.reason, "capacity temporarily unavailable");
}
