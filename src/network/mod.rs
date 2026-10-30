//! TCP connection management: the listening side (`server`) and the
//! connecting side (`client`). Every device runs both.

pub mod client;
pub mod handshake;
pub mod server;

use std::time::Duration;

/// How long we wait for a peer to connect or send its next message before
/// giving up, so a stalled peer can't hold a connection open forever.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the receiver's user has to accept or decline an offered file.
/// An offer nobody answers in time is declined.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub use crate::identity::DeviceIdentity;

/// The device on the other end of a connection, as it introduced itself.
/// Its id is always the fingerprint of `public_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub id: String,
    pub name: String,
    /// Proven during the handshake: the peer holds the matching private key.
    pub public_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ErrorCode, Message, read_message, write_message};
    use tokio::net::{TcpListener, TcpStream};

    async fn start_server() -> std::net::SocketAddr {
        start_server_in(std::env::temp_dir().join("opendrop-tests-unused")).await
    }

    async fn start_server_in(download_dir: std::path::PathBuf) -> std::net::SocketAddr {
        start_server_with(download_dir, server::Approval::AcceptAll).await
    }

    async fn start_server_with(
        download_dir: std::path::PathBuf,
        approval: server::Approval,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::run(
            listener,
            DeviceIdentity::new("Receiver"),
            download_dir,
            approval,
        ));
        addr
    }

    #[tokio::test]
    async fn receiver_decides_on_each_file() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("wanted.txt"), b"yes please").unwrap();
        std::fs::write(src.path().join("unwanted.txt"), b"no thanks").unwrap();
        let (requests, mut pending) = tokio::sync::mpsc::channel(4);
        let addr = start_server_with(dest.path().to_owned(), server::Approval::Ask(requests)).await;
        // Stand-in for the user: accept only "wanted.txt".
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&asked);
        tokio::spawn(async move {
            while let Some(request) = pending.recv().await {
                let server::FileRequest {
                    name,
                    size,
                    respond,
                    ..
                } = request;
                let accept = name == "wanted.txt";
                log.lock().unwrap().push((name, size));
                let _ = respond.send(accept);
            }
        });

        let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("S"))
            .await
            .unwrap();
        let declined = conn
            .send_file(&src.path().join("unwanted.txt"), &mut |_| {})
            .await
            .unwrap();
        assert!(matches!(declined, client::FileResult::Declined));
        // A decline leaves the connection usable for the next file.
        let accepted = conn
            .send_file(&src.path().join("wanted.txt"), &mut |_| {})
            .await
            .unwrap();
        assert!(matches!(accepted, client::FileResult::Delivered(_)));

        assert_eq!(files_in(dest.path()), ["wanted.txt"]);
        assert_eq!(
            *asked.lock().unwrap(),
            [
                ("unwanted.txt".to_owned(), 9),
                ("wanted.txt".to_owned(), 10)
            ]
        );
    }

    #[tokio::test]
    async fn receiver_reports_progress_and_where_it_saved() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        // Several chunks, so there's more than one progress event.
        let content = vec![7u8; crate::transfer::CHUNK_SIZE * 3 + 5];
        std::fs::write(src.path().join("big.bin"), &content).unwrap();
        let (requests, mut pending) = tokio::sync::mpsc::channel(4);
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::run_with_events(
            listener,
            DeviceIdentity::new("Receiver"),
            dest.path().to_owned(),
            server::Approval::Ask(requests),
            Some(events),
        ));
        let asked_id = tokio::spawn(async move {
            let request = pending.recv().await.unwrap();
            let _ = request.respond.send(true);
            request.transfer_id
        });

        let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("S"))
            .await
            .unwrap();
        let result = conn
            .send_file(&src.path().join("big.bin"), &mut |_| {})
            .await
            .unwrap();
        let client::FileResult::Delivered(outcome) = result else {
            panic!("expected delivery, got {result:?}");
        };
        let id = asked_id.await.unwrap();

        let mut log = Vec::new();
        while let Some(event) = received.recv().await {
            let done = matches!(event, server::ReceiveEvent::Saved { .. });
            log.push(event);
            if done {
                break;
            }
        }
        let size = content.len() as u64;
        assert_eq!(
            log.first(),
            Some(&server::ReceiveEvent::Started {
                transfer_id: id.clone(),
                peer_name: "S".into(),
                name: "big.bin".into(),
                size,
            })
        );
        let progress: Vec<u64> = log
            .iter()
            .filter_map(|e| match e {
                server::ReceiveEvent::Progress {
                    transfer_id,
                    received,
                } if *transfer_id == id => Some(*received),
                _ => None,
            })
            .collect();
        assert!(progress.len() >= 4, "{progress:?}");
        assert!(progress.windows(2).all(|w| w[0] < w[1]), "{progress:?}");
        assert_eq!(progress.last(), Some(&size));
        assert_eq!(
            log.last(),
            Some(&server::ReceiveEvent::Saved {
                transfer_id: id,
                path: dest.path().join("big.bin"),
                sha256: outcome.sha256,
            })
        );
    }

    #[tokio::test]
    async fn offer_is_declined_when_nobody_is_asking() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"hi").unwrap();
        let (requests, pending) = tokio::sync::mpsc::channel(1);
        drop(pending); // The prompt has gone away.
        let addr = start_server_with(dest.path().to_owned(), server::Approval::Ask(requests)).await;
        let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("S"))
            .await
            .unwrap();
        let result = conn
            .send_file(&src.path().join("a.txt"), &mut |_| {})
            .await
            .unwrap();
        assert!(matches!(result, client::FileResult::Declined));
        assert!(files_in(dest.path()).is_empty());
    }

    /// Connect and complete the handshake, for protocol-level tests.
    async fn handshake(addr: std::net::SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        handshake::connect(
            &mut stream,
            &DeviceIdentity::new("Test"),
            &crate::pairing::store::PairedDevices::in_memory(),
        )
        .await
        .unwrap();
        stream
    }

    fn files_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[tokio::test]
    async fn files_arrive_intact_over_one_connection() {
        let src = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let addr = start_server_in(dest.path().join("inbox")).await;

        let big: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7) as u8).collect();
        std::fs::write(src.path().join("big.bin"), &big).unwrap();
        std::fs::write(src.path().join("empty.txt"), b"").unwrap();

        let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("S"))
            .await
            .unwrap();
        let mut last = 0;
        let client::FileResult::Delivered(out) = conn
            .send_file(&src.path().join("big.bin"), &mut |n| last = n)
            .await
            .unwrap()
        else {
            panic!("file was declined");
        };
        assert_eq!(out.size, big.len() as u64);
        assert_eq!(last, big.len() as u64);
        assert_eq!(out.sha256, crate::transfer::sha256_hex(&big));
        conn.send_file(&src.path().join("empty.txt"), &mut |_| {})
            .await
            .unwrap();
        // Same name again: saved alongside, never overwritten.
        conn.send_file(&src.path().join("big.bin"), &mut |_| {})
            .await
            .unwrap();
        assert_eq!(conn.send_text("still here").await.unwrap(), 10);

        let inbox = dest.path().join("inbox");
        assert_eq!(files_in(&inbox), ["big (1).bin", "big.bin", "empty.txt"]);
        assert_eq!(std::fs::read(inbox.join("big.bin")).unwrap(), big);
        assert_eq!(std::fs::read(inbox.join("big (1).bin")).unwrap(), big);
    }

    #[tokio::test]
    async fn corrupted_file_is_rejected_and_discarded() {
        let dest = tempfile::tempdir().unwrap();
        let addr = start_server_in(dest.path().to_owned()).await;
        let mut stream = handshake(addr).await;
        let offer = |name: &str| Message::FileOffer {
            transfer_id: "t1".into(),
            name: name.into(),
            size: 5,
        };
        write_message(&mut stream, &offer("data.bin"))
            .await
            .unwrap();
        assert!(matches!(
            read_message(&mut stream).await.unwrap(),
            Message::FileAccept { .. }
        ));
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        write_message(
            &mut stream,
            &Message::FileDone {
                transfer_id: "t1".into(),
                sha256: crate::transfer::sha256_hex(b"HELLO"),
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            Message::Error { code, .. } => assert_eq!(code, ErrorCode::ChecksumMismatch),
            other => panic!("expected error, got {other:?}"),
        }
        // Give the server task a moment to drop the temp file.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(files_in(dest.path()).is_empty());
    }

    #[tokio::test]
    async fn path_names_cannot_escape_the_download_folder() {
        let dest = tempfile::tempdir().unwrap();
        let inbox = dest.path().join("inbox");
        let addr = start_server_in(inbox.clone()).await;
        let mut stream = handshake(addr).await;

        write_message(
            &mut stream,
            &Message::FileOffer {
                transfer_id: "t1".into(),
                name: "../escaped.txt".into(),
                size: 2,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_message(&mut stream).await.unwrap(),
            Message::FileAccept { .. }
        ));
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"hi")
            .await
            .unwrap();
        write_message(
            &mut stream,
            &Message::FileDone {
                transfer_id: "t1".into(),
                sha256: crate::transfer::sha256_hex(b"hi"),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            read_message(&mut stream).await.unwrap(),
            Message::FileReceived {
                received_bytes: 2,
                ..
            }
        ));
        assert_eq!(files_in(&inbox), ["escaped.txt"]);
        assert_eq!(files_in(dest.path()), ["inbox"]);

        write_message(
            &mut stream,
            &Message::FileOffer {
                transfer_id: "t2".into(),
                name: "..".into(),
                size: 2,
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            Message::Error { code, .. } => assert_eq!(code, ErrorCode::FileRejected),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn interrupted_transfer_leaves_nothing_behind() {
        let dest = tempfile::tempdir().unwrap();
        let addr = start_server_in(dest.path().to_owned()).await;
        let mut stream = handshake(addr).await;
        write_message(
            &mut stream,
            &Message::FileOffer {
                transfer_id: "t1".into(),
                name: "movie.mp4".into(),
                size: 1_000_000,
            },
        )
        .await
        .unwrap();
        read_message(&mut stream).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &[0u8; 1000])
            .await
            .unwrap();
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(files_in(dest.path()).is_empty());
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

    /// Stop and restart a device three times: a peer connecting over
    /// loopback sees the same device id every time.
    #[tokio::test]
    async fn device_id_is_stable_across_restarts() {
        let config = tempfile::tempdir().unwrap();
        let downloads = tempfile::tempdir().unwrap();
        let visitor = DeviceIdentity::new("Visitor");
        let mut seen = Vec::new();
        for _ in 0..4 {
            let me = DeviceIdentity::load_or_create(config.path(), "Receiver").unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let node = tokio::spawn(server::run(
                listener,
                me.clone(),
                downloads.path().to_owned(),
                server::Approval::AcceptAll,
            ));
            let conn = client::Connection::open(&addr.to_string(), &visitor)
                .await
                .unwrap();
            assert_eq!(conn.peer.id, me.id);
            seen.push(conn.peer.id);
            node.abort();
            let _ = node.await;
        }
        assert!(seen.windows(2).all(|w| w[0] == w[1]), "{seen:?}");
    }

    /// An impostor using a real device's id with its own key is cut off at
    /// the handshake; its file offer never reaches the user.
    #[tokio::test]
    async fn impostor_is_refused_before_any_offer_is_shown() {
        let dest = tempfile::tempdir().unwrap();
        let (requests, mut pending) = tokio::sync::mpsc::channel(4);
        let paired = std::sync::Arc::new(crate::pairing::store::PairedDevices::in_memory());
        let mac = DeviceIdentity::new("Mac");
        paired
            .insert(crate::pairing::store::PairedDevice::new(
                mac.id.clone(),
                "Mac".into(),
                mac.public_key(),
            ))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::serve(
            listener,
            server::Options {
                paired,
                ..server::Options::new(
                    DeviceIdentity::new("PC"),
                    dest.path().to_owned(),
                    server::Approval::Ask(requests),
                )
            },
        ));

        let impostor = DeviceIdentity::new("Mac");
        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_message(
            &mut stream,
            &Message::Hello {
                device_id: mac.id.clone(),
                device_name: "Mac".into(),
                public_key: impostor.public_key(),
                nonce: [3; 32],
            },
        )
        .await
        .unwrap();
        // Offer a file straight away, without waiting for a reply.
        let _ = write_message(
            &mut stream,
            &Message::FileOffer {
                transfer_id: "t1".into(),
                name: "evil.exe".into(),
                size: 4,
            },
        )
        .await;
        match read_message(&mut stream).await.unwrap() {
            Message::Error { code, .. } => assert_eq!(code, ErrorCode::IdentityMismatch),
            other => panic!("expected identity_mismatch, got {other:?}"),
        }
        assert!(matches!(
            read_message(&mut stream).await,
            Err(crate::protocol::ProtocolError::ConnectionClosed)
                | Err(crate::protocol::ProtocolError::Io(_))
        ));
        assert!(pending.try_recv().is_err(), "the offer reached the prompt");
        assert!(files_in(dest.path()).is_empty());
    }

    #[tokio::test]
    async fn loopback_handshake_takes_under_50ms() {
        let addr = start_server().await;
        let me = DeviceIdentity::new("Sender");
        // Warm up (first connect pays for lazy initialisation).
        client::Connection::open(&addr.to_string(), &me)
            .await
            .unwrap();
        let mut slowest = std::time::Duration::ZERO;
        for _ in 0..10 {
            let started = std::time::Instant::now();
            client::Connection::open(&addr.to_string(), &me)
                .await
                .unwrap();
            slowest = slowest.max(started.elapsed());
        }
        println!("slowest of 10 loopback handshakes: {slowest:?}");
        assert!(
            slowest < std::time::Duration::from_millis(50),
            "{slowest:?}"
        );
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
