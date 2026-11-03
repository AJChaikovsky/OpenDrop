//! Issue #27: connections are encrypted and tied to the device keys.

use super::*;
use crate::pairing::store::{PairedDevice, PairedDevices};
use crate::protocol::{Message, read_message, write_message};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MARKER: &[u8] = b"OPENDROP-PLAINTEXT-MARKER-7f3a";

/// A TCP relay between a client and `target` that records every byte it
/// passes, in both directions: what a packet capture would see.
async fn tap(target: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(target).await.unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            let up = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = cr.read(&mut buf).await {
                    if n == 0 || sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    up.lock().unwrap().extend_from_slice(&buf[..n]);
                }
                let _ = sw.shutdown().await;
            });
            let down = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = sr.read(&mut buf).await {
                    if n == 0 || cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    down.lock().unwrap().extend_from_slice(&buf[..n]);
                }
                let _ = cw.shutdown().await;
            });
        }
    });
    (addr, seen)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

async fn receiver(
    download_dir: &std::path::Path,
    paired: PairedDevices,
) -> (std::net::SocketAddr, DeviceIdentity) {
    let identity = DeviceIdentity::new("Receiver");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let options = server::Options {
        paired: Arc::new(paired),
        ..server::Options::new(
            identity.clone(),
            download_dir.to_owned(),
            server::Approval::AcceptAll,
        )
    };
    tokio::spawn(server::serve(listener, options));
    (addr, identity)
}

/// Acceptance: a capture of a transfer shows none of the file's contents,
/// its name, or a text message, while the file arrives intact.
#[tokio::test]
async fn a_captured_transfer_contains_no_plaintext() {
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let mut content = Vec::new();
    while content.len() < 3 * 1024 * 1024 {
        content.extend_from_slice(MARKER);
        content.extend_from_slice(b" some ordinary file text\n");
    }
    let name = "secret-OPENDROP-NAME-MARKER.txt";
    std::fs::write(src.path().join(name), &content).unwrap();
    let (server, _) = receiver(dest.path(), PairedDevices::in_memory()).await;
    let (addr, seen) = tap(server).await;

    let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("Sender"))
        .await
        .unwrap();
    let text = String::from_utf8(MARKER.to_vec()).unwrap();
    conn.send_text(&text).await.unwrap();
    let result = conn
        .send_file(&src.path().join(name), &mut |_| {})
        .await
        .unwrap();
    assert!(matches!(result, client::FileResult::Delivered(_)));
    drop(conn);
    assert_eq!(std::fs::read(dest.path().join(name)).unwrap(), content);

    let seen = seen.lock().unwrap().clone();
    assert!(seen.len() > content.len(), "capture missed the transfer");
    // The handshake itself is plaintext, which shows the capture works.
    assert!(contains(&seen, br#""type":"hello""#));
    assert!(!contains(&seen, MARKER), "file contents or text leaked");
    assert!(!contains(&seen, b"NAME-MARKER"), "file name leaked");
    assert!(!contains(&seen, br#""type":"file_offer""#));
}

/// Acceptance: a device in the middle that swaps in its own encryption key
/// is caught, because the signatures cover both keys.
#[tokio::test]
async fn a_swapped_encryption_key_fails_the_handshake() {
    let dest = tempfile::tempdir().unwrap();
    let (server, _) = receiver(dest.path(), PairedDevices::in_memory()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut upstream = TcpStream::connect(server).await.unwrap();
        let mut hello = read_message(&mut client).await.unwrap();
        if let Message::Hello { ephemeral, .. } = &mut hello {
            *ephemeral = secure::Ephemeral::new().public;
        }
        write_message(&mut upstream, &hello).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    let err = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("Sender"))
        .await
        .err()
        .expect("handshake should fail");
    assert!(err.to_string().contains("IdentityMismatch"), "{err}");
    relay.abort();
}

/// Acceptance: a device claiming a paired device's id with another key is
/// refused, on either side of the connection.
#[tokio::test]
async fn a_different_key_than_the_paired_one_fails_the_handshake() {
    let dest = tempfile::tempdir().unwrap();
    let real = DeviceIdentity::new("Mac");
    let paired = PairedDevices::in_memory();
    paired
        .insert(PairedDevice::new(
            real.id.clone(),
            "Mac".into(),
            real.public_key(),
        ))
        .unwrap();
    let (server, _) = receiver(dest.path(), paired).await;
    // Same name and id, different key.
    let mut impostor = DeviceIdentity::new("Mac");
    impostor.id = real.id.clone();
    let err = client::Connection::open(&server.to_string(), &impostor)
        .await
        .err()
        .expect("handshake should fail");
    assert!(err.to_string().contains("IdentityMismatch"), "{err}");

    // And the client refuses a server that isn't the device it paired with.
    let (other, other_identity) = receiver(dest.path(), PairedDevices::in_memory()).await;
    let ours = PairedDevices::in_memory();
    ours.insert(PairedDevice::new(
        other_identity.id.clone(),
        "Receiver".into(),
        DeviceIdentity::new("Receiver").public_key(),
    ))
    .unwrap();
    let err = client::Connection::open_with(&other.to_string(), &real, &ours)
        .await
        .err()
        .expect("handshake should fail");
    assert!(err.to_string().contains("IdentityMismatch"), "{err}");
}

/// Unpaired devices can still send with approval, but the request says
/// they're unverified; paired ones are verified.
#[tokio::test]
async fn requests_say_whether_the_sender_is_verified() {
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"hi").unwrap();
    let sender = DeviceIdentity::new("Sender");
    let receiver_id = DeviceIdentity::new("Receiver");
    let theirs = PairedDevices::in_memory();
    theirs
        .insert(PairedDevice::new(
            sender.id.clone(),
            "Sender".into(),
            sender.public_key(),
        ))
        .unwrap();
    let ours = PairedDevices::in_memory();
    ours.insert(PairedDevice::new(
        receiver_id.id.clone(),
        "Receiver".into(),
        receiver_id.public_key(),
    ))
    .unwrap();
    let (requests, mut pending) = tokio::sync::mpsc::channel(4);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(
        listener,
        server::Options {
            paired: Arc::new(theirs),
            ..server::Options::new(
                receiver_id,
                dest.path().to_owned(),
                server::Approval::Ask(requests),
            )
        },
    ));
    let verified = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let request: server::FileRequest = pending.recv().await.unwrap();
            seen.push(request.verified);
            let _ = request.respond.send(false);
        }
        seen
    });
    let file = src.path().join("a.txt");
    let mut paired_conn = client::Connection::open_with(&addr, &sender, &ours)
        .await
        .unwrap();
    assert!(paired_conn.paired);
    paired_conn.send_file(&file, &mut |_| {}).await.unwrap();
    let mut stranger = client::Connection::open(&addr, &DeviceIdentity::new("Stranger"))
        .await
        .unwrap();
    stranger.send_file(&file, &mut |_| {}).await.unwrap();
    assert_eq!(verified.await.unwrap(), [true, false]);
}

/// A peer that answers the handshake but then sends plaintext is cut off.
#[tokio::test]
async fn plaintext_after_the_handshake_is_refused() {
    let dest = tempfile::tempdir().unwrap();
    let (server, _) = receiver(dest.path(), PairedDevices::in_memory()).await;
    let mut stream = TcpStream::connect(server).await.unwrap();
    handshake::connect(
        &mut stream,
        &DeviceIdentity::new("Sender"),
        &PairedDevices::in_memory(),
    )
    .await
    .unwrap();
    write_message(&mut stream, &Message::Text { body: "hi".into() })
        .await
        .unwrap();
    // The server can't open it, so it hangs up without answering.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("server should hang up");
    assert!(read_message(&mut &buf[..]).await.is_err());
}
