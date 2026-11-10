//! Issue #38: clipboard text, approved by the receiver.

use super::tests::start_server_with;
use super::*;

/// The receiver sees the exact text and decides; a yes and a no reach the
/// sender.
#[tokio::test]
async fn clipboard_text_is_offered_and_answered() {
    let dest = tempfile::tempdir().unwrap();
    let (requests, mut pending) = tokio::sync::mpsc::channel(4);
    let addr = start_server_with(dest.path().to_owned(), server::Approval::Ask(requests)).await;
    let answers = tokio::spawn(async move {
        let mut seen = Vec::new();
        for accept in [true, false] {
            let request = pending.recv().await.unwrap();
            seen.push((request.name.clone(), request.size, request.text.clone()));
            request.respond.send(accept).unwrap();
        }
        seen
    });
    let text = "Wi-Fi password: \"correct horse\" 🐎\nline two";
    let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("Mac"))
        .await
        .unwrap();
    assert!(conn.send_clipboard("clip-1", text).await.unwrap());
    assert!(!conn.send_clipboard("clip-2", "not wanted").await.unwrap());
    let seen = answers.await.unwrap();
    assert_eq!(
        seen,
        [
            (
                server::CLIPBOARD_NAME.to_owned(),
                text.len() as u64,
                Some(text.to_owned())
            ),
            (
                server::CLIPBOARD_NAME.to_owned(),
                10,
                Some("not wanted".to_owned())
            ),
        ]
    );
    // Nothing is written to the download folder.
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}

/// Acceptance: text over the frame limit is refused with a clear error,
/// before the receiver is asked anything; the connection stays usable.
#[tokio::test]
async fn text_over_the_frame_limit_is_refused_clearly() {
    let dest = tempfile::tempdir().unwrap();
    let (requests, mut pending) = tokio::sync::mpsc::channel(4);
    let addr = start_server_with(dest.path().to_owned(), server::Approval::Ask(requests)).await;
    let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("Mac"))
        .await
        .unwrap();
    let huge = "x".repeat(70_000);
    let err = conn.send_clipboard("clip-big", &huge).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "the text is too long to send (70 KB); clipboard text can be at most about 64 KB, \
         so send it as a file instead"
    );
    // Escaping counts: 40,000 quotes become 80,000 bytes on the wire.
    let quotes = "\"".repeat(40_000);
    assert!(conn.send_clipboard("clip-quotes", &quotes).await.is_err());
    assert!(pending.try_recv().is_err(), "the receiver was asked");
    // Just under the limit still goes.
    let answer = tokio::spawn(async move {
        let request = pending.recv().await.unwrap();
        let size = request.size;
        request.respond.send(true).unwrap();
        size
    });
    let fits = "y".repeat(60_000);
    assert!(conn.send_clipboard("clip-ok", &fits).await.unwrap());
    assert_eq!(answer.await.unwrap(), 60_000);
}
