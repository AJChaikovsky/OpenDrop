use super::*;
use std::time::Duration;

/// A daemon on loopback without mDNS.
async fn daemon(name: &str, downloads: &Path, approval: Approval) -> Arc<Daemon> {
    Daemon::start(Options {
        port: 0,
        discover: false,
        ..Options::new(DeviceIdentity::new(name), downloads.to_owned(), approval)
    })
    .await
    .unwrap()
}

fn loopback(daemon: &Daemon) -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], daemon.port))]
}

/// Wait up to 10 s for transfer `id` in `table` to reach a final state.
async fn finished(table: &TransferTable, id: &str) -> Transfer {
    for _ in 0..1000 {
        if let Some(t) = table.get(id).filter(|t| t.status.is_final()) {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("transfer {id} never finished: {:?}", table.get(id));
}

/// Issue #17 acceptance: a send and a receive over loopback each appear in
/// their daemon's table with correct byte counts and end in `done`; a
/// declined offer ends in `declined` on both sides.
#[tokio::test]
async fn sends_and_receives_are_tracked_to_the_end() {
    let src = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let content = vec![9u8; crate::transfer::CHUNK_SIZE * 5 + 123];
    std::fs::write(src.path().join("wanted.bin"), &content).unwrap();
    std::fs::write(src.path().join("unwanted.txt"), b"no thanks").unwrap();

    // B asks "the user", who accepts only wanted.bin.
    let (ask, mut asked) = mpsc::channel::<FileRequest>(4);
    tokio::spawn(async move {
        while let Some(request) = asked.recv().await {
            let accept = request.name == "wanted.bin";
            let _ = request.respond.send(accept);
        }
    });
    let a = daemon("A", a_dir.path(), Approval::AcceptAll).await;
    let b = daemon("B", b_dir.path(), Approval::Ask(ask)).await;

    let sent = a
        .send_file(&loopback(&b), &src.path().join("wanted.bin"))
        .await
        .unwrap();
    let out = finished(&a.transfers, &sent).await;
    assert_eq!(out.status, Status::Done, "{out:?}");
    assert_eq!(out.direction, Direction::Send);
    assert_eq!(
        (out.bytes, out.size),
        (content.len() as u64, content.len() as u64)
    );
    assert_eq!(out.peer_name, "B");
    assert_eq!(out.peer_id.as_deref(), Some(b.identity.id.as_str()));

    let incoming = b.transfers.list();
    assert_eq!(incoming.len(), 1, "{incoming:?}");
    let got = finished(&b.transfers, &incoming[0].transfer_id).await;
    assert_eq!(got.status, Status::Done, "{got:?}");
    assert_eq!(got.direction, Direction::Receive);
    assert_eq!(
        (got.bytes, got.size),
        (content.len() as u64, content.len() as u64)
    );
    assert_eq!(got.peer_name, "A");
    assert_eq!(got.name, "wanted.bin");
    let saved = got.path.clone().unwrap();
    assert_eq!(std::fs::read(&saved).unwrap(), content);
    assert_eq!(got.sha256, out.sha256);

    let refused = a
        .send_file(&loopback(&b), &src.path().join("unwanted.txt"))
        .await
        .unwrap();
    let out = finished(&a.transfers, &refused).await;
    assert_eq!(out.status, Status::Declined, "{out:?}");
    assert_eq!(out.bytes, 0);
    let row = b
        .transfers
        .list()
        .into_iter()
        .find(|t| t.name == "unwanted.txt")
        .unwrap();
    let row = finished(&b.transfers, &row.transfer_id).await;
    assert_eq!(row.status, Status::Declined, "{row:?}");
    assert_eq!(row.bytes, 0);
}

/// An offer waiting for the user is cancelled from the table: the sender
/// sees a decline, and nothing is saved.
#[tokio::test]
async fn cancelling_a_pending_offer_declines_it() {
    let src = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"hello").unwrap();
    let (ask, mut asked) = mpsc::channel::<FileRequest>(4);
    let a = daemon("A", a_dir.path(), Approval::AcceptAll).await;
    let b = daemon("B", b_dir.path(), Approval::Ask(ask)).await;

    let sent = a
        .send_file(&loopback(&b), &src.path().join("a.txt"))
        .await
        .unwrap();
    // The user is being asked; cancel from the table instead.
    let request = asked.recv().await.unwrap();
    let row = b.transfers.get(&request.transfer_id).unwrap();
    assert_eq!(row.status, Status::AwaitingApproval);
    b.transfers.cancel(&row.transfer_id).unwrap();
    assert_eq!(
        finished(&b.transfers, &row.transfer_id).await.status,
        Status::Cancelled
    );
    assert_eq!(finished(&a.transfers, &sent).await.status, Status::Declined);
    assert_eq!(
        std::fs::read_dir(b_dir.path())
            .map(|d| d.count())
            .unwrap_or(0),
        0
    );
}

/// Cancelling a send that is waiting for the receiver stops it at once.
#[tokio::test]
async fn cancelling_an_outgoing_send() {
    let src = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"hello").unwrap();
    let (ask, mut asked) = mpsc::channel::<FileRequest>(4);
    let a = daemon("A", a_dir.path(), Approval::AcceptAll).await;
    let b = daemon("B", b_dir.path(), Approval::Ask(ask)).await;
    let sent = a
        .send_file(&loopback(&b), &src.path().join("a.txt"))
        .await
        .unwrap();
    let _request = asked.recv().await.unwrap();
    a.transfers.cancel(&sent).unwrap();
    assert_eq!(
        finished(&a.transfers, &sent).await.status,
        Status::Cancelled
    );
}
