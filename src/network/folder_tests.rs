//! Issue #34: folders go as one transfer, and a peer can't use one to
//! write outside the download folder.

use super::tests::{handshake, start_server_in, start_server_with};
use super::*;
use crate::protocol::{ErrorCode, FolderEntry, Message, read_message, write_message};
use crate::transfer::sha256_hex;
use std::collections::BTreeMap;
use std::path::Path;

/// Every file under `root`, by relative path (with `/`), with its SHA-256.
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &rel, out);
            } else {
                out.insert(rel, sha256_hex(&std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

/// A 3-level tree of 500 files: 5 folders × 10 subfolders × 10 files, of
/// varied sizes (some empty).
fn make_tree(root: &Path) {
    let mut n = 0u32;
    for a in 0..5 {
        for b in 0..10 {
            let dir = root.join(format!("level1-{a}")).join(format!("level2 {b}"));
            std::fs::create_dir_all(&dir).unwrap();
            for c in 0..10 {
                n += 1;
                let len = (n * 997 % 20_000) as usize;
                let content: Vec<u8> = (0..len).map(|i| (i as u32 * 31 + n) as u8).collect();
                std::fs::write(dir.join(format!("file-{c}.dat")), content).unwrap();
            }
        }
    }
    assert_eq!(n, 500);
}

/// Acceptance: a 3-level tree of 500 files transfers; the received tree
/// listing is identical and every file's SHA-256 matches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_500_file_tree_arrives_identical() {
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let root = src.path().join("Project X");
    make_tree(&root);
    let addr = start_server_in(dest.path().to_owned()).await;
    let mut conn = client::Connection::open(&addr.to_string(), &DeviceIdentity::new("S"))
        .await
        .unwrap();
    let mut last = 0;
    let result = conn
        .send_folder_until(&root, &mut |n| last = n, None)
        .await
        .unwrap();
    let client::FileResult::Delivered(out) = result else {
        panic!("{result:?}");
    };
    let sent = tree(&root);
    let got = tree(&dest.path().join("Project X"));
    assert_eq!(got.len(), 500);
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        sent.keys().collect::<Vec<_>>(),
        "listing differs"
    );
    assert_eq!(got, sent, "a file's SHA-256 differs");
    let total: u64 = crate::transfer::folder::list_folder(&root)
        .unwrap()
        .iter()
        .map(|(_, e)| e.size)
        .sum();
    assert_eq!((out.size, last), (total, total));
    // The folder's own checksum, computed the same way on our side.
    let expected =
        crate::transfer::folder::tree_hash(sent.iter().map(|(p, h)| (p.as_str(), h.as_str())));
    assert_eq!(out.sha256, expected);
    println!("500 files, {total} bytes, tree SHA-256 {}", out.sha256);
    // Nothing but the folder in the download folder (no staging left).
    let names: Vec<String> = std::fs::read_dir(dest.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["Project X"]);

    // The same folder again lands beside it, never merged into it.
    conn.send_folder_until(&root, &mut |_| {}, None)
        .await
        .unwrap();
    assert_eq!(tree(&dest.path().join("Project X (1)")), sent);
}

/// Acceptance: listings with `..`, absolute paths or drive letters are
/// refused before anything is written, with or without asking the user.
#[tokio::test]
async fn unsafe_paths_in_a_folder_are_refused() {
    for bad in [
        "../evil.txt",
        "ok/../../evil.txt",
        "/etc/evil",
        "C:/Windows/evil.dll",
        "C:evil.txt",
        "a\\..\\..\\evil.txt",
    ] {
        let dest = tempfile::tempdir().unwrap();
        let inbox = dest.path().join("inbox");
        let (ask, mut asked) = tokio::sync::mpsc::channel(4);
        let addr = start_server_with(inbox.clone(), server::Approval::Ask(ask)).await;
        let mut stream = handshake(addr).await;
        let entries = vec![
            FolderEntry {
                path: "fine.txt".into(),
                size: 2,
            },
            FolderEntry {
                path: bad.into(),
                size: 4,
            },
        ];
        write_message(
            &mut stream,
            &Message::FolderOffer {
                transfer_id: "t1".into(),
                name: "Folder".into(),
                files: 2,
                size: 6,
            },
        )
        .await
        .unwrap();
        write_message(
            &mut stream,
            &Message::FolderEntries {
                transfer_id: "t1".into(),
                entries,
            },
        )
        .await
        .unwrap();
        match read_message(&mut stream).await.unwrap() {
            Message::Error {
                code: ErrorCode::FileRejected,
                message,
            } => {
                assert!(message.contains("unsafe path"), "{bad}: {message}")
            }
            other => panic!("{bad}: {other:?}"),
        }
        assert!(asked.try_recv().is_err(), "{bad}: the user was asked");
        assert!(
            !inbox.exists() || std::fs::read_dir(&inbox).unwrap().next().is_none(),
            "{bad}"
        );
        assert!(!dest.path().join("evil.txt").exists());
    }
}

/// A sender that lies about a file's contents gets the whole folder
/// refused, and nothing is kept.
#[tokio::test]
async fn a_corrupted_file_drops_the_whole_folder() {
    let dest = tempfile::tempdir().unwrap();
    let addr = start_server_in(dest.path().to_owned()).await;
    let mut stream = handshake(addr).await;
    let entries = vec![
        FolderEntry {
            path: "a.txt".into(),
            size: 2,
        },
        FolderEntry {
            path: "sub/b.txt".into(),
            size: 3,
        },
    ];
    write_message(
        &mut stream,
        &Message::FolderOffer {
            transfer_id: "t".into(),
            name: "F".into(),
            files: 2,
            size: 5,
        },
    )
    .await
    .unwrap();
    write_message(
        &mut stream,
        &Message::FolderEntries {
            transfer_id: "t".into(),
            entries,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_message(&mut stream).await.unwrap(),
        Message::FileAccept { .. }
    ));
    use tokio::io::AsyncWriteExt;
    stream.write_all(b"hi").await.unwrap();
    write_message(
        &mut stream,
        &Message::FileDone {
            transfer_id: "t".into(),
            sha256: sha256_hex(b"hi"),
        },
    )
    .await
    .unwrap();
    stream.write_all(b"bad").await.unwrap();
    write_message(
        &mut stream,
        &Message::FileDone {
            transfer_id: "t".into(),
            sha256: sha256_hex(b"bbb"),
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        Message::Error {
            code: ErrorCode::FileRejected,
            message,
        } => assert!(message.contains("corrupted"), "{message}"),
        other => panic!("{other:?}"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        std::fs::read_dir(dest.path()).unwrap().count(),
        0,
        "something was kept"
    );
}
