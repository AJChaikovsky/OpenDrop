use super::*;
use crate::daemon::{Daemon, Options};
use crate::network::DeviceIdentity;
use crate::network::server::{Approval, FetchInfo, FileRequest};
use crate::pairing::store::{PairedDevice, PairedDevices};
use crate::share::Shares;
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use std::sync::Arc;
use tokio::sync::mpsc;

pub(super) const SENTENCE: &str = "The quarterly numbers are filed under blue folder nine.";

/// An owner sharing `Docs/` (notes.txt, q3-report.pdf, logo.png) and a
/// requester with the control API, paired with each other over loopback.
/// The owner's approvals arrive on `asked`.
pub(super) struct Rig {
    pub owner: Arc<Daemon>,
    pub requester: Arc<Daemon>,
    pub asked: mpsc::Receiver<FileRequest>,
    pub requester_config: PathBuf,
    pub docs: PathBuf,
    _dirs: Vec<tempfile::TempDir>,
}

pub(super) fn pair(store: &PairedDevices, other: &DeviceIdentity) {
    store
        .insert(PairedDevice::new(
            other.id.clone(),
            other.name.clone(),
            other.public_key(),
        ))
        .unwrap();
}

pub(super) async fn rig(pdf: &[u8]) -> Rig {
    let owner_dir = tempfile::tempdir().unwrap();
    let requester_dir = tempfile::tempdir().unwrap();
    let docs = owner_dir.path().join("Docs");
    std::fs::create_dir(&docs).unwrap();
    std::fs::write(docs.join("notes.txt"), format!("Hello.\n{SENTENCE}\n")).unwrap();
    std::fs::write(docs.join("q3-report.pdf"), pdf).unwrap();
    std::fs::write(docs.join("logo.png"), b"\x89PNG\r\n\x1a\nnot really").unwrap();
    let shares = Shares::new(&owner_dir.path().join("config"), None);
    shares.add(&docs).unwrap();

    let owner_id = DeviceIdentity::new("Mac");
    let requester_id = DeviceIdentity::new("PC");
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
    let requester_config = requester_dir.path().join("config");
    let requester = Daemon::start(Options {
        port: 0,
        discover: false,
        paired: requester_store,
        control: Some(requester_config.clone()),
        ..Options::new(
            requester_id,
            requester_dir.path().join("dl"),
            Approval::AcceptAll,
        )
    })
    .await
    .unwrap();
    Rig {
        owner,
        requester,
        asked,
        requester_config,
        docs,
        _dirs: vec![owner_dir, requester_dir],
    }
}

impl Rig {
    /// How the requester reaches the owner (no mDNS in tests).
    pub fn owner_address(&self) -> String {
        format!("127.0.0.1:{}", self.owner.port)
    }
}

pub(super) type McpClient = RunningService<RoleClient, ()>;

/// An MCP client connected, over an in-memory pipe, to an `OpenDropMcp`
/// for `config_dir`, waiting until the daemon's control endpoint answers.
pub(super) async fn connect(config_dir: &Path) -> McpClient {
    let endpoint = Endpoint::for_config_dir(config_dir);
    for _ in 0..100 {
        if Client::connect_to(&endpoint).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let server = OpenDropMcp::new(endpoint).serve(server_io).await.unwrap();
        let _ = server.waiting().await;
    });
    ().serve(client_io).await.unwrap()
}

pub(super) async fn call(client: &McpClient, tool: &'static str, args: Value) -> CallToolResult {
    let mut params = CallToolRequestParams::new(tool);
    if let Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    client.call_tool(params).await.unwrap()
}

/// The structured part of a successful result.
pub(super) fn success(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .clone()
        .expect("structured content")
}

/// The error code of a failed result.
pub(super) fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    let body = result.structured_content.clone().expect("structured error");
    assert!(body["message"].is_string(), "{body}");
    body["error"].as_str().unwrap().to_owned()
}

/// Approve (or decline) the next request the owner's user sees.
pub(super) async fn answer_next(
    asked: &mut mpsc::Receiver<FileRequest>,
    accept: bool,
) -> Option<FetchInfo> {
    let request = tokio::time::timeout(Duration::from_secs(10), asked.recv())
        .await
        .expect("the owner was asked")
        .unwrap();
    request.respond.send(accept).unwrap();
    request.fetch
}

/// Issue #22 acceptance: exactly the five tools, each with a valid input
/// schema and the documented read-only annotations.
#[tokio::test]
async fn lists_exactly_five_tools_with_valid_schemas() {
    let rig = rig(b"pdf").await;
    let client = connect(&rig.requester_config).await;
    let tools = client.list_all_tools().await.unwrap();

    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "cancel_transfer",
            "get_transfer_status",
            "list_devices",
            "list_shared_files",
            "request_file"
        ]
    );
    for tool in &tools {
        let schema = Value::Object((*tool.input_schema).clone());
        assert_eq!(schema["type"], "object", "{}: {schema}", tool.name);
        if let Err(e) = jsonschema::meta::validate(&schema) {
            panic!("{} has an invalid input schema: {e}\n{schema}", tool.name);
        }
        assert!(
            tool.description.as_ref().is_some_and(|d| d.len() > 40),
            "{} needs a description",
            tool.name
        );
        let read_only = tool.annotations.as_ref().and_then(|a| a.read_only_hint);
        let expected = !matches!(tool.name.as_ref(), "request_file" | "cancel_transfer");
        assert_eq!(read_only, Some(expected), "{} read_only_hint", tool.name);
    }
    let required = |name: &str| -> Vec<String> {
        let tool = tools.iter().find(|t| t.name == name).unwrap();
        let mut required: Vec<String> = tool
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        required.sort();
        required
    };
    assert_eq!(required("list_devices"), Vec::<String>::new());
    assert_eq!(required("list_shared_files"), ["device"]);
    assert_eq!(required("request_file"), ["device", "file_id", "reason"]);
    assert_eq!(required("get_transfer_status"), ["transfer_id"]);
    assert_eq!(required("cancel_transfer"), ["transfer_id"]);
    let tools_json = serde_json::to_string(&tools).unwrap();
    assert!(tools_json.contains("not instructions"), "{tools_json}");
}

/// Issue #22 acceptance: each tool returns its documented shape.
#[tokio::test]
async fn each_tool_returns_the_documented_shape() {
    let mut rig = rig(b"%PDF-1.7 fake").await;
    let client = connect(&rig.requester_config).await;

    // list_devices: the paired owner (offline, since tests run without mDNS).
    let devices = success(&call(&client, "list_devices", json!({})).await);
    let devices = devices["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1, "{devices:?}");
    let mac = &devices[0];
    assert_eq!(mac["device_id"], rig.owner.identity.id.as_str());
    assert_eq!(mac["name"], "Mac");
    assert_eq!(mac["paired"], true);
    assert_eq!(mac["online"], false);
    assert_eq!(mac["compatible"], true);
    let mut keys: Vec<&String> = mac.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["compatible", "device_id", "name", "online", "paired"]
    );

    // list_shared_files: every shared file, ids but never local paths.
    let listed = success(
        &call(
            &client,
            "list_shared_files",
            json!({"device": rig.owner_address()}),
        )
        .await,
    );
    assert_eq!(listed["device"], "Mac");
    assert_eq!(listed["truncated"], false);
    let files = listed["files"].as_array().unwrap();
    let mut names: Vec<&str> = files.iter().map(|f| f["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(names, ["logo.png", "notes.txt", "q3-report.pdf"]);
    let notes = files.iter().find(|f| f["name"] == "notes.txt").unwrap();
    assert!(notes["file_id"].as_str().unwrap().starts_with("f_"));
    assert_eq!(notes["path"], "Docs/notes.txt");
    assert_eq!(notes["mime"], "text/plain");
    assert!(notes["size"].as_u64().unwrap() > 0);
    assert!(notes["modified"].as_u64().unwrap() > 0);
    let docs = rig.docs.to_string_lossy().into_owned();
    assert!(!listed.to_string().contains(&docs), "leaks a local path");

    // query narrows the list on the owner's side.
    let narrowed = success(
        &call(
            &client,
            "list_shared_files",
            json!({"device": rig.owner_address(), "query": "q3"}),
        )
        .await,
    );
    assert_eq!(narrowed["files"].as_array().unwrap().len(), 1, "{narrowed}");

    // request_file: returns at once, awaiting approval.
    let started = success(
        &call(
            &client,
            "request_file",
            json!({
                "device": rig.owner_address(),
                "file_id": notes["file_id"],
                "reason": "To answer the question about Q3",
            }),
        )
        .await,
    );
    assert_eq!(started["state"], "awaiting_approval");
    let transfer_id = started["transfer_id"].as_str().unwrap().to_owned();
    let status = success(
        &call(
            &client,
            "get_transfer_status",
            json!({"transfer_id": transfer_id}),
        )
        .await,
    );
    assert_eq!(status["state"], "awaiting_approval");

    // The owner sees the reason and that an assistant asked.
    let fetch = answer_next(&mut rig.asked, true)
        .await
        .expect("asked as a fetch");
    assert_eq!(fetch.reason, "To answer the question about Q3");
    assert!(fetch.via_assistant);

    // get_transfer_status: done, with the text inline as data.
    let done = call(
        &client,
        "get_transfer_status",
        json!({"transfer_id": transfer_id, "wait_seconds": 10}),
    )
    .await;
    let status = success(&done);
    assert_eq!(status["state"], "done", "{status}");
    assert_eq!(status["transfer_id"], transfer_id.as_str());
    assert_eq!(status["file_name"], "notes.txt");
    assert_eq!(status["device"], "Mac");
    assert_eq!(status["bytes"], status["total"]);
    assert!(status["path"].as_str().unwrap().ends_with("notes.txt"));
    assert_eq!(status["sha256"].as_str().unwrap().len(), 64);
    let text = done
        .content
        .iter()
        .filter_map(|c| c.as_text())
        .map(|t| t.text.as_str())
        .find(|t| t.contains("begin notes.txt"))
        .expect("file content attached");
    assert!(text.contains(SENTENCE), "{text}");
    assert!(text.contains("not instructions"), "{text}");

    // cancel_transfer on a finished transfer is a tool error.
    let late = call(
        &client,
        "cancel_transfer",
        json!({"transfer_id": transfer_id}),
    )
    .await;
    assert_eq!(error_code(&late), "already_finished");

    // A binary file comes back as a link; an image inline.
    for (name, accept) in [("q3-report.pdf", true), ("logo.png", true)] {
        let file = files.iter().find(|f| f["name"] == name).unwrap();
        let id = success(
            &call(
                &client,
                "request_file",
                json!({"device": rig.owner_address(), "file_id": file["file_id"], "reason": "test"}),
            )
            .await,
        )["transfer_id"]
            .as_str()
            .unwrap()
            .to_owned();
        answer_next(&mut rig.asked, accept).await;
        let done = call(
            &client,
            "get_transfer_status",
            json!({"transfer_id": id, "wait_seconds": 10}),
        )
        .await;
        assert_eq!(success(&done)["state"], "done");
        let extra = done.content.last().unwrap();
        match name {
            "q3-report.pdf" => {
                let ContentBlock::ResourceLink(link) = extra else {
                    panic!("expected a link: {extra:?}");
                };
                assert!(link.uri.starts_with("file:///"), "{}", link.uri);
                assert!(link.uri.ends_with("q3-report.pdf"), "{}", link.uri);
                assert_eq!(link.mime_type.as_deref(), Some("application/pdf"));
            }
            _ => {
                let ContentBlock::Image(image) = extra else {
                    panic!("expected an image: {extra:?}");
                };
                assert_eq!(image.mime_type, "image/png");
            }
        }
    }

    // cancel_transfer while awaiting approval ends in cancelled.
    let id = success(
        &call(
            &client,
            "request_file",
            json!({"device": rig.owner_address(), "file_id": notes["file_id"], "reason": "x"}),
        )
        .await,
    )["transfer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cancelled = success(&call(&client, "cancel_transfer", json!({"transfer_id": id})).await);
    assert_eq!(cancelled, json!({"transfer_id": id, "state": "cancelled"}));
}

/// Issue #22 acceptance: failures come back as tool errors with a code,
/// and the server keeps answering afterwards.
#[tokio::test]
async fn failures_are_tool_errors_not_crashes() {
    let rig = rig(b"pdf").await;
    let client = connect(&rig.requester_config).await;
    let owner = rig.owner_address();

    let unknown = call(&client, "list_shared_files", json!({"device": "Nobody"})).await;
    assert_eq!(error_code(&unknown), "unknown_device");
    let offline = call(&client, "list_shared_files", json!({"device": "Mac"})).await;
    assert_eq!(error_code(&offline), "device_offline");

    for file_id in [
        "f_doesnotexist",
        "~/.ssh/id_rsa",
        "/etc/passwd",
        "../config/key",
    ] {
        let refused = call(
            &client,
            "request_file",
            json!({"device": owner, "file_id": file_id, "reason": "x"}),
        )
        .await;
        assert_eq!(error_code(&refused), "not_shared", "{file_id}");
    }
    assert!(
        rig.requester.transfers.list().is_empty(),
        "no transfer started"
    );
    assert!(rig.owner.transfers.list().is_empty(), "owner saw nothing");

    let missing = call(
        &client,
        "get_transfer_status",
        json!({"transfer_id": "fetch-nope"}),
    )
    .await;
    assert_eq!(error_code(&missing), "unknown_transfer");
    let missing = call(
        &client,
        "cancel_transfer",
        json!({"transfer_id": "fetch-nope"}),
    )
    .await;
    assert_eq!(error_code(&missing), "unknown_transfer");

    // Missing arguments are refused by the server, which stays up.
    let mut params = CallToolRequestParams::new("request_file");
    params = params.with_arguments(json!({"device": owner}).as_object().unwrap().clone());
    match client.call_tool(params).await {
        Err(_) => {}
        Ok(result) => assert_eq!(result.is_error, Some(true), "{result:?}"),
    }

    // A device we aren't paired with refuses to list.
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger_config = stranger_dir.path().join("config");
    let _stranger = Daemon::start(Options {
        port: 0,
        discover: false,
        control: Some(stranger_config.clone()),
        ..Options::new(
            DeviceIdentity::new("Stranger"),
            stranger_dir.path().join("dl"),
            Approval::AcceptAll,
        )
    })
    .await
    .unwrap();
    let stranger = connect(&stranger_config).await;
    let refused = call(&stranger, "list_shared_files", json!({"device": owner})).await;
    assert_eq!(error_code(&refused), "not_paired");
    let refused = call(
        &stranger,
        "request_file",
        json!({"device": owner, "file_id": "notes.txt", "reason": "x"}),
    )
    .await;
    assert_eq!(error_code(&refused), "not_paired");

    // No daemon at all.
    let empty = tempfile::tempdir().unwrap();
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let endpoint = Endpoint::for_config_dir(empty.path());
    tokio::spawn(async move {
        let server = OpenDropMcp::new(endpoint).serve(server_io).await.unwrap();
        let _ = server.waiting().await;
    });
    let lonely: McpClient = ().serve(client_io).await.unwrap();
    let down = call(&lonely, "list_devices", json!({})).await;
    assert_eq!(error_code(&down), "daemon_not_running");

    // Still answering after all that.
    success(&call(&client, "list_devices", json!({})).await);
}

#[test]
fn file_uris_work_for_every_os() {
    assert_eq!(
        file_uri(Path::new("/Users/aj/Downloads/OpenDrop/q3 report.pdf")),
        "file:///Users/aj/Downloads/OpenDrop/q3%20report.pdf"
    );
    assert_eq!(
        file_uri(Path::new(r"C:\Users\aj\Downloads\OpenDrop\notes.txt")),
        "file:///C:/Users/aj/Downloads/OpenDrop/notes.txt"
    );
    assert_eq!(mime_of("Photo.JPG"), "image/jpeg");
    assert_eq!(mime_of("no-extension"), "application/octet-stream");
}

/// Files left in a download folder, temp files included.
fn files_in(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Pseudo-random bytes (xorshift), so nothing compresses or dedupes.
fn random_bytes(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The file_id of shared `name`, found the way an assistant would.
async fn file_id_of(client: &McpClient, rig: &Rig, name: &str) -> String {
    let listed = success(
        &call(
            client,
            "list_shared_files",
            json!({"device": rig.owner_address()}),
        )
        .await,
    );
    listed["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {listed}"))["file_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn request(client: &McpClient, rig: &Rig, file_id: &str) -> String {
    let started = success(
        &call(
            client,
            "request_file",
            json!({"device": rig.owner_address(), "file_id": file_id, "reason": "e2e"}),
        )
        .await,
    );
    assert_eq!(started["state"], "awaiting_approval");
    started["transfer_id"].as_str().unwrap().to_owned()
}

/// Issue #23 acceptance: two real daemons, driven only through MCP the way
/// an assistant would, with the owner's approvals scripted. Approve: the
/// file arrives and its SHA-256 matches. Decline: `declined`, nothing
/// written. Cancel mid-transfer: `cancelled`, no `.part` left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_end_to_end_through_mcp() {
    let started = std::time::Instant::now();
    let big = random_bytes(64 * 1024 * 1024, 0x9e37_79b9_7f4a_7c15);
    let mut rig = rig(&big).await;
    let original = crate::transfer::sha256_hex(&big);
    let client = connect(&rig.requester_config).await;
    let downloads = rig.requester.download_dir.clone();

    // list_devices: the owner is there, paired and compatible.
    let devices = success(&call(&client, "list_devices", json!({})).await);
    let mac = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "Mac")
        .unwrap_or_else(|| panic!("owner not listed: {devices}"))
        .clone();
    assert_eq!(mac["paired"], true);
    assert_eq!(mac["compatible"], true);

    // 1. Approve: list -> request -> approve -> status until done.
    let report = file_id_of(&client, &rig, "q3-report.pdf").await;
    let id = request(&client, &rig, &report).await;
    let fetch = answer_next(&mut rig.asked, true).await.unwrap();
    assert!(fetch.via_assistant);
    let mut status = Value::Null;
    for _ in 0..6 {
        status = success(
            &call(
                &client,
                "get_transfer_status",
                json!({"transfer_id": id, "wait_seconds": 10}),
            )
            .await,
        );
        if status["state"] == "done" {
            break;
        }
    }
    assert_eq!(status["state"], "done", "{status}");
    let saved = PathBuf::from(status["path"].as_str().unwrap());
    let copy = crate::transfer::sha256_hex(&std::fs::read(&saved).unwrap());
    println!("approved: original {original}, copy {copy}");
    assert_eq!(copy, original);
    assert_eq!(status["sha256"], original.as_str());
    assert_eq!(status["bytes"], big.len() as u64);
    std::fs::remove_file(&saved).unwrap();

    // 2. Decline: declined, and nothing written.
    let notes = file_id_of(&client, &rig, "notes.txt").await;
    let id = request(&client, &rig, &notes).await;
    answer_next(&mut rig.asked, false).await;
    let status = success(
        &call(
            &client,
            "get_transfer_status",
            json!({"transfer_id": id, "wait_seconds": 10}),
        )
        .await,
    );
    assert_eq!(status["state"], "declined", "{status}");
    assert!(status.get("path").is_none(), "{status}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(files_in(&downloads), Vec::<String>::new());

    // 3. Cancel mid-transfer: cancelled, and no .part file left.
    let id = request(&client, &rig, &report).await;
    answer_next(&mut rig.asked, true).await;
    let mut seen = Value::Null;
    for _ in 0..2000 {
        seen = success(&call(&client, "get_transfer_status", json!({"transfer_id": id})).await);
        if seen["state"] == "transferring" && seen["bytes"].as_u64().unwrap() > 0 {
            break;
        }
        assert!(
            !seen["state"].as_str().unwrap().ends_with("done"),
            "finished before it could be cancelled: {seen}"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(seen["state"], "transferring", "{seen}");
    let cancelled = success(&call(&client, "cancel_transfer", json!({"transfer_id": id})).await);
    println!(
        "cancelled after {} of {} bytes: {cancelled}",
        seen["bytes"], seen["total"]
    );
    assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
    // The receive stops and cleans up right after the row turns cancelled.
    let mut left = files_in(&downloads);
    for _ in 0..100 {
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        left = files_in(&downloads);
    }
    assert_eq!(left, Vec::<String>::new(), "files left behind");
    let status = success(&call(&client, "get_transfer_status", json!({"transfer_id": id})).await);
    assert_eq!(status["state"], "cancelled", "stays cancelled: {status}");
    // The owner's side ended too, without delivering.
    let mut owner_row = None;
    for _ in 0..100 {
        owner_row = rig.owner.transfers.list().into_iter().last();
        if owner_row.as_ref().is_some_and(|t| t.status.is_final()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let owner_row = owner_row.unwrap();
    assert_ne!(owner_row.status, Status::Done, "{owner_row:?}");
    assert!(owner_row.status.is_final(), "{owner_row:?}");

    let elapsed = started.elapsed();
    println!("scripted end-to-end took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?}");
}
