//! Issue #29: `send_file`, the reverse of a fetch.

use super::tests::*;
use super::*;
use std::time::Instant;

/// A folder for files to send whose name doesn't start with "." (temp
/// folders usually do, and hidden paths aren't sendable).
fn source_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("opendrop-send-")
        .tempdir()
        .unwrap()
}

/// Files in the owner's download folder, temp files included.
fn received(rig: &Rig) -> Vec<String> {
    std::fs::read_dir(&rig.owner.download_dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn send(client: &McpClient, rig: &Rig, path: &Path) -> String {
    let started = success(
        &call(
            client,
            "send_file",
            json!({"peer": rig.owner_address(), "path": path}),
        )
        .await,
    );
    assert_eq!(started["state"], "awaiting_approval", "{started}");
    started["transfer_id"].as_str().unwrap().to_owned()
}

async fn wait_for_end(client: &McpClient, id: &str) -> Value {
    let mut status = Value::Null;
    for _ in 0..6 {
        status = success(
            &call(
                client,
                "get_transfer_status",
                json!({"transfer_id": id, "wait_seconds": 10}),
            )
            .await,
        );
        if status["state"] != "awaiting_approval" && status["state"] != "transferring" {
            break;
        }
    }
    status
}

/// Acceptance: the Phase 5 scripted end-to-end, reversed. The assistant's
/// side sends; the other device's user approves, declines, or the send is
/// cancelled midway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_send_end_to_end_through_mcp() {
    let started = Instant::now();
    let mut rig = rig(b"pdf").await;
    let client = connect(&rig.requester_config).await;
    let src = source_dir();
    let big = src.path().join("holiday-video.bin");
    let mut content = Vec::with_capacity(64 * 1024 * 1024);
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    while content.len() < 64 * 1024 * 1024 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        content.extend_from_slice(&seed.to_le_bytes());
    }
    std::fs::write(&big, &content).unwrap();
    let original = crate::transfer::sha256_hex(&content);
    drop(content);

    // 1. Approve: the file arrives and its SHA-256 matches.
    let id = send(&client, &rig, &big).await;
    let asked = answer_next_request(&mut rig.asked, true).await;
    assert_eq!(asked.name, "holiday-video.bin");
    assert!(asked.verified, "a paired sender is verified");
    let status = wait_for_end(&client, &id).await;
    assert_eq!(status["state"], "done", "{status}");
    assert_eq!(status["sha256"], original.as_str());
    let copy = rig.owner.download_dir.join("holiday-video.bin");
    let copied = crate::transfer::sha256_hex(&std::fs::read(&copy).unwrap());
    println!("approved: original {original}, copy {copied}");
    assert_eq!(copied, original);
    std::fs::remove_file(&copy).unwrap();

    // 2. Decline: declined, and nothing written on the other side.
    let small = src.path().join("notes.txt");
    std::fs::write(&small, "not wanted").unwrap();
    let id = send(&client, &rig, &small).await;
    answer_next_request(&mut rig.asked, false).await;
    let status = wait_for_end(&client, &id).await;
    assert_eq!(status["state"], "declined", "{status}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(received(&rig), Vec::<String>::new());

    // 3. Cancel mid-transfer: cancelled, and no .part left on the other side.
    let id = send(&client, &rig, &big).await;
    answer_next_request(&mut rig.asked, true).await;
    let mut seen = Value::Null;
    for _ in 0..2000 {
        seen = success(&call(&client, "get_transfer_status", json!({"transfer_id": id})).await);
        if seen["state"] == "transferring" && seen["bytes"].as_u64().unwrap() > 0 {
            break;
        }
        assert_ne!(
            seen["state"], "done",
            "finished before it could be cancelled"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(seen["state"], "transferring", "{seen}");
    let cancelled = success(&call(&client, "cancel_transfer", json!({"transfer_id": id})).await);
    assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
    let mut left = received(&rig);
    for _ in 0..100 {
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        left = received(&rig);
    }
    assert_eq!(left, Vec::<String>::new(), "files left behind");

    let elapsed = started.elapsed();
    println!("scripted send end-to-end took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?}");
}

/// Hidden files, relative paths, folders, OpenDrop's own keys and devices
/// that aren't paired are all refused before anything is offered.
#[tokio::test]
async fn refuses_what_it_should_not_send() {
    let mut rig = rig(b"pdf").await;
    let client = connect(&rig.requester_config).await;
    let src = source_dir();
    let hidden_dir = src.path().join(".ssh");
    std::fs::create_dir(&hidden_dir).unwrap();
    std::fs::write(hidden_dir.join("id_rsa"), "secret").unwrap();
    std::fs::write(src.path().join(".env"), "secret").unwrap();
    std::fs::write(src.path().join("ok.txt"), "fine").unwrap();
    let key = rig.requester_config.join("device.key");
    std::fs::create_dir_all(&rig.requester_config).unwrap();
    if !key.exists() {
        std::fs::write(&key, "key").unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(hidden_dir.join("id_rsa"), src.path().join("innocent.txt")).unwrap();

    let owner = rig.owner_address();
    let mut cases = vec![
        (json!(hidden_dir.join("id_rsa")), "path_not_allowed"),
        (json!(src.path().join(".env")), "path_not_allowed"),
        (json!("ok.txt"), "path_not_allowed"),
        (json!(src.path()), "not_a_file"),
        (json!(src.path().join("missing.txt")), "not_a_file"),
        (json!(key), "path_not_allowed"),
    ];
    #[cfg(unix)]
    cases.push((json!(src.path().join("innocent.txt")), "path_not_allowed"));
    for (path, expected) in cases {
        let result = call(&client, "send_file", json!({"peer": owner, "path": path})).await;
        assert_eq!(error_code(&result), expected, "{path}");
    }
    // An unpaired device: forget the pairing on our side.
    let owner_id = rig.owner.identity.id.clone();
    rig.requester.paired.remove(&owner_id).unwrap();
    let result = call(
        &client,
        "send_file",
        json!({"peer": owner, "path": src.path().join("ok.txt")}),
    )
    .await;
    assert_eq!(error_code(&result), "not_paired");
    // Nobody on the other side was asked anything.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rig.asked.try_recv().is_err());
    assert!(rig.requester.transfers.list().is_empty());
}
