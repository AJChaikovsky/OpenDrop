//! B4 acceptance tests: an assistant (or another device) gets a file from a
//! device anywhere, through the relay, after a yes on that device; standing
//! access skips the prompt until it is revoked; OpenDrop's own config is
//! never served; a no leaves nothing behind.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use opendrop::audit::AuditLog;
use opendrop::daemon::{Status, TransferTable};
use opendrop::identity::DeviceIdentity;
use opendrop::network::server::FileRequest;
use opendrop::relay::{self, access::Access, remote::Remote};
use opendrop_relay::{Config, Mailer, Relay, inbox::Blobs, store::Store};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, ResourceContents};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Default, Clone)]
struct Links(Arc<Mutex<Vec<String>>>);

impl Mailer for Links {
    fn send_login_link(&self, _email: &str, link: &str) {
        self.0.lock().unwrap().push(link.to_owned());
    }
}

struct TestRelay {
    url: String,
    links: Links,
}

async fn start_relay() -> TestRelay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let links = Links::default();
    let relay = Relay::new(
        Store::in_memory().unwrap(),
        Blobs::in_memory(),
        Box::new(links.clone()),
        Config::new(&url),
    );
    tokio::spawn(opendrop_relay::serve(listener, relay));
    TestRelay { url, links }
}

async fn get(link: &str) {
    let rest = link.strip_prefix("http://").unwrap();
    let (host, path) = rest.split_once('/').unwrap();
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    stream
        .write_all(
            format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).await.unwrap();
}

async fn sign_in(relay: &TestRelay, identity: &DeviceIdentity) -> relay::Config {
    let login = tokio::spawn({
        let (url, identity) = (relay.url.clone(), identity.clone());
        async move {
            relay::login(&url, "aj@example.com", &identity, || {})
                .await
                .map_err(|e| e.to_string())
        }
    });
    let link = loop {
        if let Some(link) = relay.links.0.lock().unwrap().pop() {
            break link;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    get(&link).await;
    login.await.unwrap().unwrap()
}

/// A signed-in device answering relayed requests. Its prompts come out of
/// `prompts`; the test answers them.
struct TestDevice {
    remote: Arc<Remote>,
    config: relay::Config,
    config_dir: PathBuf,
    download_dir: PathBuf,
    home: PathBuf,
    transfers: Arc<TransferTable>,
    prompts: mpsc::Receiver<FileRequest>,
    _dirs: Vec<tempfile::TempDir>,
}

impl TestDevice {
    async fn start(relay: &TestRelay, name: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let config_dir = root.path().join("OpenDrop");
        let download_dir = root.path().join("Downloads");
        let home = root.path().join("home");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let identity = DeviceIdentity::load_or_create(&config_dir, name).unwrap();
        std::fs::write(config_dir.join("relay-secret.txt"), b"never leaves").unwrap();
        let config = sign_in(relay, &identity).await;
        let (approval, prompts) = mpsc::channel(8);
        let transfers = Arc::new(TransferTable::new());
        let remote = Remote::new(
            identity.clone(),
            config.clone(),
            config_dir.clone(),
            download_dir.clone(),
            approval,
            Arc::clone(&transfers),
            Arc::new(AuditLog::in_memory()),
        );
        let (status, mut watch) = tokio::sync::watch::channel(relay::Status::Connecting);
        tokio::spawn(relay::run(
            config.clone(),
            identity,
            status,
            Some(Arc::clone(&remote)),
        ));
        tokio::time::timeout(
            Duration::from_secs(5),
            watch.wait_for(|s| *s == relay::Status::Online),
        )
        .await
        .expect("online in time")
        .unwrap();
        Self {
            remote,
            config,
            config_dir,
            download_dir,
            home,
            transfers,
            prompts,
            _dirs: vec![root],
        }
    }

    /// The next prompt on this device.
    async fn prompt(&mut self) -> FileRequest {
        tokio::time::timeout(Duration::from_secs(10), self.prompts.recv())
            .await
            .expect("a prompt in time")
            .unwrap()
    }

    fn no_prompt(&mut self) {
        assert!(self.prompts.try_recv().is_err(), "asked unexpectedly");
    }

    fn file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.home.join(name);
        std::fs::write(&path, data).unwrap();
        path.canonicalize().unwrap()
    }
}

/// Answer `prompt`: yes (with the standing access it offers, if `always`)
/// or no.
fn answer(prompt: FileRequest, yes: bool, always: bool) {
    if yes
        && always
        && let Some(grant) = prompt.fetch.as_ref().and_then(|f| f.grant.as_ref())
    {
        assert!(grant.always, "a relayed ask offers standing access");
        grant.accept();
    }
    prompt.respond.send(yes).unwrap();
}

type Client = RunningService<RoleClient, ()>;

async fn mcp(relay: &TestRelay, token: &str) -> Client {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", relay.url))
            .auth_header(token),
    );
    ().serve(transport).await.expect("MCP client connects")
}

async fn call(client: &Client, tool: &'static str, args: Value) -> CallToolResult {
    let mut params = CallToolRequestParams::new(tool);
    if let Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    client.call_tool(params).await.unwrap()
}

fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    result.structured_content.as_ref().unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The file bytes inside a request_file result.
fn file_bytes(result: &CallToolResult) -> Vec<u8> {
    assert_ne!(result.is_error, Some(true), "{result:?}");
    match &result.content[1] {
        ContentBlock::Resource(r) => match &r.resource {
            ResourceContents::BlobResourceContents { blob, .. } => B64.decode(blob).unwrap(),
            other => panic!("expected a blob, got {other:?}"),
        },
        ContentBlock::Text(t) => {
            let text = &t.text;
            let start = text.find("-----\n").unwrap() + 6;
            let end = text.rfind("\n----- end").unwrap();
            text.as_bytes()[start..end].to_vec()
        }
        other => panic!("unexpected content {other:?}"),
    }
}

/// Run `tool` while `respond` handles the device's side.
async fn ask_while<F>(
    client: &Client,
    tool: &'static str,
    args: Value,
    respond: F,
) -> CallToolResult
where
    F: std::future::Future<Output = ()>,
{
    let (result, ()) = tokio::join!(call(client, tool, args), respond);
    result
}

#[tokio::test]
async fn an_assistant_gets_a_file_after_one_yes_then_without_asking_until_revoked() {
    let relay = start_relay().await;
    let mut windows = TestDevice::start(&relay, "Windows").await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let path = windows.file("report.bin", &data);
    let token = relay::create_token(&windows.config, "Claude")
        .await
        .unwrap();
    let client = mcp(&relay, &token).await;
    let args =
        json!({ "device": "windows", "path": path.display().to_string(), "reason": "the numbers" });

    // 1. The first request is asked on the device; yes + standing access.
    let first = ask_while(&client, "request_file", args.clone(), async {
        let prompt = windows.prompt().await;
        assert_eq!(prompt.peer_name, "Claude");
        assert_eq!(prompt.name, path.display().to_string());
        let fetch = prompt.fetch.as_ref().unwrap();
        assert!(fetch.via_assistant);
        assert_eq!(fetch.reason, "the numbers");
        answer(prompt, true, true);
    })
    .await;
    assert_eq!(sha256_hex(&file_bytes(&first)), sha256_hex(&data));

    // 2. Standing access: no prompt this time (3 more, all identical).
    for _ in 0..3 {
        let again = call(&client, "request_file", args.clone()).await;
        assert_eq!(sha256_hex(&file_bytes(&again)), sha256_hex(&data));
        windows.no_prompt();
    }
    // The file was read straight away: nothing waits in the inbox.
    let inbox = call(&client, "list_inbox", json!({})).await;
    assert_eq!(inbox.structured_content.unwrap()["files"], json!([]));

    // 3. Revoked on the device: asked again, and a no leaves nothing.
    let gone = Access::new(&windows.config_dir).revoke("Claude").unwrap();
    assert_eq!(gone.len(), 1);
    let declined = ask_while(&client, "request_file", args.clone(), async {
        answer(windows.prompt().await, false, false);
    })
    .await;
    assert_eq!(error_code(&declined), "declined");
    let inbox = call(&client, "list_inbox", json!({})).await;
    assert_eq!(inbox.structured_content.unwrap()["files"], json!([]));
}

#[tokio::test]
async fn opendrop_settings_are_never_served_even_with_standing_access() {
    let relay = start_relay().await;
    let mut windows = TestDevice::start(&relay, "Windows").await;
    let token = relay::create_token(&windows.config, "Claude")
        .await
        .unwrap();
    let client = mcp(&relay, &token).await;
    let ok = windows.file("fine.txt", b"fine");
    ask_while(
        &client,
        "request_file",
        json!({ "device": "Windows", "path": ok.display().to_string() }),
        async { answer(windows.prompt().await, true, true) },
    )
    .await;
    let config = windows.config_dir.canonicalize().unwrap();
    for path in [
        config.join("relay-secret.txt"),
        config.join("identity.json"),
        config.join("../OpenDrop/relay.json"),
    ] {
        let refused = call(
            &client,
            "request_file",
            json!({ "device": "Windows", "path": path.display().to_string() }),
        )
        .await;
        let code = error_code(&refused);
        assert!(code == "refused" || code == "not_found", "{path:?}: {code}");
        windows.no_prompt();
    }
    // A listing of the folder holding it leaves it out.
    let parent = config.parent().unwrap().display().to_string();
    let listed = call(
        &client,
        "list_files",
        json!({ "device": "Windows", "folder": parent }),
    )
    .await;
    let entries = listed.structured_content.unwrap()["entries"].clone();
    let names: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"home"), "{names:?}");
    assert!(!names.contains(&"OpenDrop"), "{names:?}");
}

#[tokio::test]
async fn an_assistant_lists_and_searches_a_device() {
    let relay = start_relay().await;
    let mut windows = TestDevice::start(&relay, "Windows").await;
    std::fs::create_dir_all(windows.home.join("Documents/2026")).unwrap();
    std::fs::write(windows.home.join("Documents/2026/q3-report.pdf"), b"pdf").unwrap();
    std::fs::write(windows.home.join("notes.txt"), b"notes").unwrap();
    let token = relay::create_token(&windows.config, "Claude")
        .await
        .unwrap();
    let client = mcp(&relay, &token).await;
    let home = windows.home.display().to_string();
    let listed = ask_while(
        &client,
        "list_files",
        json!({ "device": "Windows", "folder": home }),
        async { answer(windows.prompt().await, true, false) },
    )
    .await;
    let entries = listed.structured_content.unwrap()["entries"].clone();
    assert_eq!(entries[0]["name"], "Documents");
    assert_eq!(entries[0]["is_dir"], true);
    assert_eq!(entries[1]["name"], "notes.txt");
    // No standing access was given: the search is asked too.
    let found = ask_while(
        &client,
        "list_files",
        json!({ "device": "Windows", "folder": windows.home.display().to_string(), "query": "Q3" }),
        async { answer(windows.prompt().await, true, false) },
    )
    .await;
    let entries = found.structured_content.unwrap()["entries"].clone();
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert!(
        entries[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("q3-report.pdf")
    );
}

/// Wait until transfer `id` on `device` ends; returns it.
async fn finished(device: &TestDevice, id: &str) -> opendrop::daemon::Transfer {
    for _ in 0..500 {
        if let Some(t) = device.transfers.get(id)
            && t.status.is_final()
        {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "transfer {id} didn't finish: {:?}",
        device.transfers.get(id)
    );
}

#[tokio::test]
async fn a_device_fetches_from_another_device_anywhere() {
    let relay = start_relay().await;
    let mut windows = TestDevice::start(&relay, "Windows").await;
    let mac = TestDevice::start(&relay, "Mac").await;
    let data = b"from windows to mac".repeat(5000);
    let path = windows.file("deck.key", &data);

    let id = mac
        .remote
        .fetch("Windows", &path.display().to_string(), "for the meeting")
        .unwrap();
    let prompt = windows.prompt().await;
    assert_eq!(prompt.peer_name, "Mac");
    assert!(!prompt.fetch.as_ref().unwrap().via_assistant);
    answer(prompt, true, true);
    let done = finished(&mac, &id).await;
    assert_eq!(done.status, Status::Done, "{done:?}");
    let saved = done.path.unwrap();
    assert!(saved.starts_with(&mac.download_dir));
    assert_eq!(
        sha256_hex(&std::fs::read(&saved).unwrap()),
        sha256_hex(&data)
    );

    // Standing access for the Mac: the second fetch isn't asked.
    let id = mac
        .remote
        .fetch("Windows", &path.display().to_string(), "")
        .unwrap();
    let done = finished(&mac, &id).await;
    assert_eq!(done.status, Status::Done, "{done:?}");
    windows.no_prompt();

    // Revoked: the next one is asked, and a no is reported as declined.
    Access::new(&windows.config_dir).revoke("all").unwrap();
    let id = mac
        .remote
        .fetch("Windows", &path.display().to_string(), "")
        .unwrap();
    answer(windows.prompt().await, false, false);
    let done = finished(&mac, &id).await;
    assert_eq!(done.status, Status::Declined, "{done:?}");

    // Listing works the same way, device to device.
    std::fs::write(windows.home.join("a.txt"), b"a").unwrap();
    let home = windows.home.display().to_string();
    let (listing, ()) = tokio::join!(mac.remote.list("Windows", Some(&home), None), async {
        answer(windows.prompt().await, true, false)
    });
    let listing = listing.unwrap();
    assert_eq!(listing.device_name, "Windows");
    assert!(listing.entries.iter().any(|e| e.name == "a.txt"));
}

#[tokio::test]
async fn an_assistant_copies_a_file_from_one_device_to_another() {
    let relay = start_relay().await;
    let mut windows = TestDevice::start(&relay, "Windows").await;
    let mut mac = TestDevice::start(&relay, "Mac").await;
    let data = b"slides".repeat(1000);
    let path = windows.file("slides.pdf", &data);
    let token = relay::create_token(&windows.config, "Claude")
        .await
        .unwrap();
    let client = mcp(&relay, &token).await;
    let args = json!({ "device": "Windows", "path": path.display().to_string(), "send_to": "Mac" });
    let result = ask_while(&client, "request_file", args, async {
        let ask = windows.prompt().await;
        assert!(
            ask.fetch
                .as_ref()
                .unwrap()
                .reason
                .contains("to be saved on Mac")
        );
        answer(ask, true, false);
        // The Mac is asked to take it, as an incoming file.
        let incoming = mac.prompt().await;
        assert!(incoming.fetch.is_none());
        assert_eq!(incoming.name, "slides.pdf");
        assert_eq!(incoming.peer_name, "Claude (from Windows)");
        answer(incoming, true, false);
    })
    .await;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    assert_eq!(
        result.structured_content.as_ref().unwrap()["status"],
        "delivered"
    );
    let saved = mac.download_dir.join("slides.pdf");
    for _ in 0..100 {
        if saved.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        sha256_hex(&std::fs::read(&saved).unwrap()),
        sha256_hex(&data)
    );
}

#[tokio::test]
async fn an_offline_or_unknown_device_is_reported_plainly() {
    let relay = start_relay().await;
    let windows = TestDevice::start(&relay, "Windows").await;
    let token = relay::create_token(&windows.config, "Claude")
        .await
        .unwrap();
    let client = mcp(&relay, &token).await;
    let missing = call(
        &client,
        "request_file",
        json!({ "device": "Linux box", "path": "~/a.txt" }),
    )
    .await;
    assert_eq!(error_code(&missing), "not_found");
    let devices = call(&client, "list_devices", json!({})).await;
    let list = devices.structured_content.unwrap()["devices"].clone();
    assert_eq!(list[0]["name"], "Windows");
    assert_eq!(list[0]["online"], true);
}
