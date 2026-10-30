//! TCP connection management: the listening side (`server`) and the
//! connecting side (`client`). Every device runs both.

pub mod client;
pub mod server;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long we wait for a peer to connect or send its next message before
/// giving up, so a stalled peer can't hold a connection open forever.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Who this device is, as announced to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String,
    pub name: String,
}

impl DeviceIdentity {
    /// Build an identity with the given display name and a fresh device id.
    ///
    /// The id is not persisted yet; Phase 4 replaces it with a stable,
    /// key-backed identity used for pairing.
    pub fn new(name: impl Into<String>) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let mixed = nanos ^ ((std::process::id() as u128) << 64);
        Self {
            id: format!("device-{:08x}", (mixed % 0xffff_ffff) as u32),
            name: name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorCode, Message, read_message, write_message};
    use tokio::net::{TcpListener, TcpStream};

    async fn start_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::run(listener, DeviceIdentity::new("Receiver")));
        addr
    }

    #[tokio::test]
    async fn client_sends_text_and_gets_ack() {
        let addr = start_server().await;
        let outcome = client::send_text(
            &addr.to_string(),
            &DeviceIdentity::new("Sender"),
            "hello there",
        )
        .await
        .unwrap();
        assert_eq!(outcome.peer.name, "Receiver");
        assert_eq!(outcome.received_bytes, "hello there".len());
    }

    #[tokio::test]
    async fn server_handles_several_clients_at_once() {
        let addr = start_server().await;
        let sends = (0..8).map(|i| {
            let addr = addr.to_string();
            tokio::spawn(async move {
                client::send_text(&addr, &DeviceIdentity::new(format!("S{i}")), &"x".repeat(i))
                    .await
                    .unwrap()
                    .received_bytes
            })
        });
        for (i, handle) in sends.enumerate() {
            assert_eq!(handle.await.unwrap(), i);
        }
    }

    #[tokio::test]
    async fn server_rejects_text_before_hello() {
        let addr = start_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_message(
            &mut stream,
            &Message::Text {
                body: "skip hello".into(),
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            Message::Error { code, .. } => assert_eq!(code, ErrorCode::UnexpectedMessage),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_reports_unreachable_peer() {
        // Bind then drop to get a port nothing is listening on.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let err = client::send_text(&addr.to_string(), &DeviceIdentity::new("S"), "hi").await;
        assert!(err.is_err());
    }
}
