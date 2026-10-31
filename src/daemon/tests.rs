use super::*;
use crate::pairing::store::PairedDevices;
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

/// Two daemons paired with each other over loopback: the owner shares
/// `Docs/` and asks "the user" on the returned channel; the requester takes
/// files without asking (only fetch offers may skip the prompt anyway).
struct FetchPair {
    owner: Arc<Daemon>,
    requester: Arc<Daemon>,
    asked: mpsc::Receiver<FileRequest>,
    _dirs: Vec<tempfile::TempDir>,
}

async fn fetch_pair(content: &[u8]) -> FetchPair {
    let owner_dir = tempfile::tempdir().unwrap();
    let requester_dir = tempfile::tempdir().unwrap();
    let docs = owner_dir.path().join("Docs");
    std::fs::create_dir(&docs).unwrap();
    std::fs::write(docs.join("q3-report.pdf"), content).unwrap();
    std::fs::write(docs.join("other.txt"), b"other").unwrap();
    let shares = Shares::new(&owner_dir.path().join("config"), None);
    shares.add(&docs).unwrap();

    let owner_id = DeviceIdentity::new("Mac");
    let requester_id = DeviceIdentity::new("PC");
    let pair = |store: &PairedDevices, other: &DeviceIdentity| {
        store
            .insert(crate::pairing::store::PairedDevice::new(
                other.id.clone(),
                other.name.clone(),
                other.public_key(),
            ))
            .unwrap()
    };
    let owner_store = Arc::new(PairedDevices::in_memory());
    let requester_store = Arc::new(PairedDevices::in_memory());
    pair(&owner_store, &requester_id);
    pair(&requester_store, &owner_id);

    let (ask, asked) = mpsc::channel(4);
    let owner = Daemon::start(Options {
        port: 0,
        discover: false,
        paired: owner_store,
        shares: Some(Arc::new(shares)),
        ..Options::new(owner_id, owner_dir.path().join("dl"), Approval::Ask(ask))
    })
    .await
    .unwrap();
    let requester = Daemon::start(Options {
        port: 0,
        discover: false,
        paired: requester_store,
        ..Options::new(
            requester_id,
            requester_dir.path().join("dl"),
            Approval::AcceptAll,
        )
    })
    .await
    .unwrap();
    FetchPair {
        owner,
        requester,
        asked,
        _dirs: vec![owner_dir, requester_dir],
    }
}

fn address(daemon: &Daemon) -> String {
    format!("127.0.0.1:{}", daemon.port)
}

/// Issue #21 acceptance (approve): the owner's user is asked with the
/// reason; on yes the file comes back intact and both rows end in done.
#[tokio::test]
async fn fetch_approved_arrives_intact() {
    let content: Vec<u8> = (0..crate::transfer::CHUNK_SIZE * 4 + 7)
        .map(|i| (i * 31) as u8)
        .collect();
    let mut p = fetch_pair(&content).await;
    let (_, files, _) = p
        .requester
        .list_shares(&address(&p.owner), None)
        .await
        .unwrap();
    assert_eq!(files.len(), 2);

    let id = p
        .requester
        .fetch(
            &address(&p.owner),
            "q3-report.pdf",
            "User asked for Q3",
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        p.requester.transfers.get(&id).unwrap().status,
        Status::AwaitingApproval
    );
    let request = p.asked.recv().await.unwrap();
    let fetch = request.fetch.clone().expect("asked as a fetch");
    assert_eq!(request.name, "q3-report.pdf");
    assert_eq!(request.peer_name, "PC");
    assert_eq!(fetch.reason, "User asked for Q3");
    assert!(fetch.via_assistant);
    let owner_row = p.owner.transfers.get(&request.transfer_id).unwrap();
    assert_eq!(owner_row.direction, Direction::Send);
    request.respond.send(true).unwrap();

    let got = finished(&p.requester.transfers, &id).await;
    assert_eq!(got.status, Status::Done, "{got:?}");
    assert_eq!(got.direction, Direction::Receive);
    assert_eq!(
        (got.bytes, got.size),
        (content.len() as u64, content.len() as u64)
    );
    assert_eq!(std::fs::read(got.path.as_ref().unwrap()).unwrap(), content);
    assert_eq!(
        got.sha256.as_deref(),
        Some(crate::transfer::sha256_hex(&content).as_str())
    );
    // One row per fetch: the arriving transfer updated the fetch's row.
    assert_eq!(p.requester.transfers.list().len(), 1);
    let sent = finished(&p.owner.transfers, &owner_row.transfer_id).await;
    assert_eq!(sent.status, Status::Done, "{sent:?}");
    assert_eq!(sent.bytes, content.len() as u64);
}

/// Issue #21 acceptance (decline): nothing is sent and the requester's row
/// says the owner declined.
#[tokio::test]
async fn fetch_declined_sends_nothing() {
    let mut p = fetch_pair(b"secret").await;
    let id = p
        .requester
        .fetch(&address(&p.owner), "Docs/q3-report.pdf", "", false)
        .await
        .unwrap();
    let request = p.asked.recv().await.unwrap();
    assert!(!request.fetch.as_ref().unwrap().via_assistant);
    request.respond.send(false).unwrap();
    let got = finished(&p.requester.transfers, &id).await;
    assert_eq!(got.status, Status::Declined, "{got:?}");
    assert_eq!(got.error.as_deref(), Some("the owner declined"));
    assert_eq!(got.bytes, 0);
    let owner_row = p.owner.transfers.list().pop().unwrap();
    assert_eq!(
        finished(&p.owner.transfers, &owner_row.transfer_id)
            .await
            .status,
        Status::Declined
    );
    assert!(!p.requester.download_dir.exists());
}

/// Issue #21 acceptance (timeout): nobody answers on the owner's side; after
/// 60 s the fetch is declined as timed out. Runs on a paused clock.
#[tokio::test]
async fn fetch_times_out_after_60s() {
    let mut p = fetch_pair(b"slow").await;
    let id = p
        .requester
        .fetch(&address(&p.owner), "q3-report.pdf", "", false)
        .await
        .unwrap();
    let request = p.asked.recv().await.unwrap();
    // Hold the request unanswered and let time run.
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    loop {
        let row = p.requester.transfers.get(&id).unwrap();
        if row.status.is_final() {
            assert_eq!(row.status, Status::Declined, "{row:?}");
            assert_eq!(
                row.error.as_deref(),
                Some("the owner didn't answer in time")
            );
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "never timed out"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let waited = started.elapsed();
    println!("fetch declined after {waited:?} of (paused) clock time");
    assert!(
        waited >= crate::network::APPROVAL_TIMEOUT - Duration::from_secs(1),
        "{waited:?}"
    );
    assert!(request.respond.is_closed());
}

#[tokio::test]
async fn fetching_an_unknown_or_ambiguous_name_fails_up_front() {
    let p = fetch_pair(b"x").await;
    let err = p
        .requester
        .fetch(&address(&p.owner), "nope.pdf", "", false)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("doesn't share a file named"),
        "{err}"
    );
    assert!(p.requester.transfers.list().is_empty());
    let err = p.requester.addresses_of("Nobody").unwrap_err();
    assert!(err.to_string().contains("no device named"), "{err}");
}
