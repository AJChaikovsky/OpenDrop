//! Issue #31: every list, request, decision, grant and send of the scripted
//! runs is in the audit log, and no file contents are.

use super::tests::*;
use super::*;
use crate::audit::{Entry, Event};
use std::collections::HashMap;

fn counts(entries: &[Entry]) -> HashMap<Event, usize> {
    let mut counts = HashMap::new();
    for e in entries {
        *counts.entry(e.event).or_default() += 1;
    }
    counts
}

async fn finished(client: &McpClient, id: &str) -> Value {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_audit_log_counts_every_event_of_the_scripted_runs() {
    let mut rig = rig(b"%PDF report").await;
    let client = connect(&rig.requester_config).await;
    let owner = rig.owner_address();
    let file_id = |listed: &Value, name: &str| {
        listed["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap()["file_id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // Two listings.
    let listed = success(&call(&client, "list_shared_files", json!({"peer": owner})).await);
    success(
        &call(
            &client,
            "list_shared_files",
            json!({"peer": owner, "query": "notes"}),
        )
        .await,
    );
    let notes = file_id(&listed, "notes.txt");
    let logo = file_id(&listed, "logo.png");
    let request = |file_id: String| {
        let client = &client;
        let owner = owner.clone();
        async move {
            let started = success(
                &call(
                    client,
                    "request_file",
                    json!({"peer": owner, "file_id": file_id, "reason": "audit test"}),
                )
                .await,
            );
            started["transfer_id"].as_str().unwrap().to_owned()
        }
    };

    // A declined fetch.
    let id = request(notes.clone()).await;
    answer_next(&mut rig.asked, false).await;
    assert_eq!(finished(&client, &id).await["state"], "declined");

    // An approved fetch, with a grant for its folder.
    let id = request(notes).await;
    let asked = rig.asked.recv().await.unwrap();
    asked.fetch.unwrap().grant.unwrap().accept();
    asked.respond.send(true).unwrap();
    assert_eq!(finished(&client, &id).await["state"], "done");

    // A fetch the grant approves, without asking.
    let id = request(logo).await;
    assert_eq!(finished(&client, &id).await["state"], "done");
    assert!(rig.asked.try_recv().is_err());

    // Two sends the other way: accepted, then declined.
    let src = tempfile::Builder::new()
        .prefix("audit-src-")
        .tempdir()
        .unwrap();
    let marker = "AUDIT-CONTENT-MARKER-5150";
    let path = src.path().join("minutes.txt");
    std::fs::write(&path, marker).unwrap();
    for accept in [true, false] {
        let started =
            success(&call(&client, "send_file", json!({"peer": owner, "path": path})).await);
        let id = started["transfer_id"].as_str().unwrap().to_owned();
        answer_next_request(&mut rig.asked, accept).await;
        let expected = if accept { "done" } else { "declined" };
        assert_eq!(finished(&client, &id).await["state"], expected);
    }

    // Each fetch through the daemon lists first to find the file, so 2 + 3
    // listings. The owner sends the 2 approved fetches back.
    let expected_owner = HashMap::from([
        (Event::List, 5),
        (Event::Request, 3),
        (Event::Approve, 3), // 2 fetches + 1 incoming file
        (Event::Decline, 2), // 1 fetch + 1 incoming file
        (Event::Grant, 1),
        (Event::Send, 2),
    ]);
    let expected_requester = HashMap::from([(Event::Send, 2)]);
    let mut owner_counts = HashMap::new();
    let mut requester_counts = HashMap::new();
    for _ in 0..100 {
        owner_counts = counts(&rig.owner.audit.entries().unwrap());
        requester_counts = counts(&rig.requester.audit.entries().unwrap());
        if owner_counts == expected_owner && requester_counts == expected_requester {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("owner: {owner_counts:?}\nrequester: {requester_counts:?}");
    assert_eq!(owner_counts, expected_owner);
    assert_eq!(requester_counts, expected_requester);

    // Names and decisions are there; file contents never are.
    let owner_log = std::fs::read_to_string(rig.owner.audit.path().unwrap()).unwrap();
    let requester_log = std::fs::read_to_string(rig.requester.audit.path().unwrap()).unwrap();
    assert!(owner_log.contains("notes.txt") && owner_log.contains("minutes.txt"));
    assert!(owner_log.contains("under a folder grant"));
    for log in [&owner_log, &requester_log] {
        assert!(!log.contains(SENTENCE), "file contents in the audit log");
        assert!(!log.contains(marker), "file contents in the audit log");
        assert!(!log.contains("%PDF"), "file contents in the audit log");
    }
}
