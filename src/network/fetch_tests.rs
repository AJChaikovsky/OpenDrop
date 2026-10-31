//! Protocol-level tests of share listing and fetch messages (issue #20).

use super::*;
use crate::pairing::store::{PairedDevice, PairedDevices};
use crate::protocol::{ErrorCode, FetchDeclineReason, Message, read_message};
use crate::share::Shares;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

struct Node {
    addr: String,
    identity: DeviceIdentity,
    fetches: Arc<fetch::PendingFetches>,
    asked: mpsc::Receiver<server::FileRequest>,
}

/// A listening node that asks "the user" on `asked`, with `shares` and
/// `paired` as given.
async fn node(
    name: &str,
    downloads: &std::path::Path,
    shares: Option<Shares>,
    paired: Arc<PairedDevices>,
) -> Node {
    let identity = DeviceIdentity::new(name);
    let (ask, asked) = mpsc::channel(4);
    let fetches = Arc::new(fetch::PendingFetches::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(
        listener,
        server::Options {
            paired,
            shares: shares.map(Arc::new),
            fetches: Arc::clone(&fetches),
            ..server::Options::new(
                identity.clone(),
                downloads.to_owned(),
                server::Approval::Ask(ask),
            )
        },
    ));
    Node {
        addr,
        identity,
        fetches,
        asked,
    }
}

fn paired_with(devices: &[&DeviceIdentity]) -> Arc<PairedDevices> {
    let store = PairedDevices::in_memory();
    for d in devices {
        store
            .insert(PairedDevice::new(
                d.id.clone(),
                d.name.clone(),
                d.public_key(),
            ))
            .unwrap();
    }
    Arc::new(store)
}

/// Issue #20 acceptance: an offer naming a fetch we started is taken without
/// asking only if the device and the size match too; a spoofed one (wrong
/// device or wrong size) goes to the normal accept prompt.
#[tokio::test]
async fn spoofed_fetch_offers_fall_back_to_the_prompt() {
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("q3.pdf"), b"12345").unwrap();
    std::fs::write(src.path().join("q3-big.pdf"), b"123456").unwrap();
    let mut requester = node(
        "PC",
        dest.path(),
        None,
        Arc::new(PairedDevices::in_memory()),
    )
    .await;
    let owner = DeviceIdentity::new("Mac");
    let mut arrived = requester.fetches.expect("fetch-1", &owner.id, 5);

    // Wrong device: an impostor knows the fetch id.
    let impostor = DeviceIdentity::new("Mac");
    let mut conn = client::Connection::open(&requester.addr, &impostor)
        .await
        .unwrap();
    let send = tokio::spawn(async move {
        let path = src.path().to_owned();
        let result = conn
            .send_fetched(&path.join("q3.pdf"), "fetch-1", &mut |_| {})
            .await
            .unwrap();
        (result, conn, path, src)
    });
    let asked = requester
        .asked
        .recv()
        .await
        .expect("impostor was not asked about");
    assert_eq!(asked.name, "q3.pdf");
    assert!(asked.fetch.is_none());
    asked.respond.send(false).unwrap();
    let (result, _conn, path, _src) = send.await.unwrap();
    assert!(matches!(result, client::FileResult::Declined));

    // Right device, wrong size.
    let mut conn = client::Connection::open(&requester.addr, &owner)
        .await
        .unwrap();
    let send = tokio::spawn(async move {
        let result = conn
            .send_fetched(&path.join("q3-big.pdf"), "fetch-1", &mut |_| {})
            .await
            .unwrap();
        (result, conn, path)
    });
    let asked = requester
        .asked
        .recv()
        .await
        .expect("wrong size was not asked about");
    assert_eq!(asked.size, 6);
    asked.respond.send(false).unwrap();
    let (result, mut conn, path) = send.await.unwrap();
    assert!(matches!(result, client::FileResult::Declined));
    assert!(arrived.try_recv().is_err());

    // The real thing: no prompt, delivered, and the fetch learns its id.
    let result = conn
        .send_fetched(&path.join("q3.pdf"), "fetch-1", &mut |_| {})
        .await
        .unwrap();
    assert!(
        matches!(result, client::FileResult::Delivered(_)),
        "{result:?}"
    );
    assert!(
        requester.asked.try_recv().is_err(),
        "the real fetch was asked about"
    );
    assert!(arrived.try_recv().unwrap().starts_with("transfer-"));
    assert_eq!(std::fs::read(dest.path().join("q3.pdf")).unwrap(), b"12345");
}

/// Issue #20 acceptance: a v1 peer gets `unsupported_version` and is listed
/// as incompatible.
#[tokio::test]
async fn v1_peers_are_incompatible() {
    let dest = tempfile::tempdir().unwrap();
    let requester = node(
        "PC",
        dest.path(),
        None,
        Arc::new(PairedDevices::in_memory()),
    )
    .await;
    let mut stream = TcpStream::connect(&requester.addr).await.unwrap();
    let hello = br#"{"version":1,"type":"hello","device_id":"old","device_name":"Old Mac"}"#;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &(hello.len() as u32).to_be_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, hello)
        .await
        .unwrap();
    match read_message(&mut stream).await.unwrap() {
        Message::Error { code, .. } => assert_eq!(code, ErrorCode::UnsupportedVersion),
        other => panic!("expected unsupported_version, got {other:?}"),
    }

    let txt = |key: &str| match key {
        "device_id" => Some("old".to_owned()),
        "device_name" => Some("Old Mac".to_owned()),
        "protocol_version" => Some("1".to_owned()),
        _ => None,
    };
    let old = crate::discovery::peer_from_txt(txt, vec![[192, 168, 1, 9].into()], 45454).unwrap();
    let listed = crate::daemon::DeviceInfo::nearby(&old, &PairedDevices::in_memory());
    assert!(!listed.compatible);
    assert!(listed.online);
}

/// Only paired devices see shares or fetch; ids that aren't shared are
/// declined before anyone is asked.
#[tokio::test]
async fn listing_and_fetching_need_pairing_and_a_shared_id() {
    let tmp = tempfile::tempdir().unwrap();
    let docs = tmp.path().join("Docs");
    std::fs::create_dir(&docs).unwrap();
    std::fs::write(docs.join("q3.pdf"), b"report").unwrap();
    let shares = Shares::new(&tmp.path().join("config"), None);
    shares.add(&docs).unwrap();
    let id = shares.list(None).unwrap()[0].file_id.clone();

    let friend = DeviceIdentity::new("PC");
    let stranger = DeviceIdentity::new("Stranger");
    let friend_store = PairedDevices::in_memory();
    let mut owner = node(
        "Mac",
        &tmp.path().join("dl"),
        Some(shares),
        paired_with(&[&friend]),
    )
    .await;
    friend_store
        .insert(PairedDevice::new(
            owner.identity.id.clone(),
            "Mac".into(),
            owner.identity.public_key(),
        ))
        .unwrap();

    // A stranger can do neither.
    let mut conn = client::Connection::open(&owner.addr, &stranger)
        .await
        .unwrap();
    assert_eq!(
        conn.request_fetch("f1", &id, "", false, 1).await.unwrap(),
        Err(FetchDeclineReason::NotPaired)
    );
    let refused = conn.list_shares(None).await.unwrap_err();
    assert!(refused.to_string().contains("NotPaired"), "{refused}");

    // A paired device lists, and an unshared id is declined unasked.
    let mut conn = client::Connection::open_with(&owner.addr, &friend, &friend_store)
        .await
        .unwrap();
    assert!(conn.paired);
    let (files, truncated) = conn.list_shares(None).await.unwrap();
    assert!(!truncated);
    assert_eq!(files.len(), 1);
    assert_eq!((files[0].path.as_str(), files[0].size), ("Docs/q3.pdf", 6));
    assert!(
        conn.list_shares(Some("nothing"))
            .await
            .unwrap()
            .0
            .is_empty()
    );
    for bad in [
        "../q3.pdf",
        "f_00000000000000000000000000000000",
        "Docs/q3.pdf",
    ] {
        assert_eq!(
            conn.request_fetch("f2", bad, "", false, 1).await.unwrap(),
            Err(FetchDeclineReason::NotShared),
            "{bad}"
        );
    }
    assert!(owner.asked.try_recv().is_err());

    // A real request reaches the owner's user with the reason attached.
    let ask = tokio::spawn(async move {
        let request = owner.asked.recv().await.unwrap();
        let fetch = request.fetch.clone().unwrap();
        let _ = request.respond.send(false);
        (request.name, request.size, fetch)
    });
    assert_eq!(
        conn.request_fetch("f3", &id, "Assistant wants Q3", true, 1)
            .await
            .unwrap(),
        Err(FetchDeclineReason::Declined)
    );
    let (name, size, fetch) = ask.await.unwrap();
    assert_eq!((name.as_str(), size), ("q3.pdf", 6));
    assert_eq!(fetch.peer_id, friend.id);
    assert_eq!(fetch.reason, "Assistant wants Q3");
    assert!(fetch.via_assistant);
    // The connection is still usable afterwards.
    assert_eq!(conn.send_text("still here").await.unwrap(), 10);
}
