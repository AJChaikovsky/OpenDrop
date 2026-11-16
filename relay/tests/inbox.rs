//! B2 acceptance tests: a file sent from a device to the assistant inbox comes
//! back through the hosted MCP server with the same SHA-256, exactly once,
//! not after it expires, and never to another account.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use opendrop::identity::DeviceIdentity;
use opendrop::relay;
use opendrop_relay::{Clock, Config, Mailer, Relay, inbox::Blobs, store::Store};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, ResourceContents};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default, Clone)]
struct Inbox(Arc<Mutex<Vec<String>>>);

impl Mailer for Inbox {
    fn send_login_link(&self, _email: &str, link: &str) {
        self.0.lock().unwrap().push(link.to_owned());
    }
}

struct TestRelay {
    url: String,
    relay: Arc<Relay>,
    links: Inbox,
    /// The relay's clock, in ms; tests move it forward.
    now: Arc<AtomicU64>,
}

async fn start_relay() -> TestRelay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let links = Inbox::default();
    let now = Arc::new(AtomicU64::new(1_800_000_000_000));
    let clock_now = Arc::clone(&now);
    let config = Config {
        clock: Clock(Arc::new(move || clock_now.load(Ordering::SeqCst))),
        ..Config::new(&url)
    };
    let relay = Relay::new(
        Store::in_memory().unwrap(),
        Blobs::in_memory(),
        Box::new(links.clone()),
        config,
    );
    tokio::spawn(opendrop_relay::serve(listener, Arc::clone(&relay)));
    TestRelay {
        url,
        relay,
        links,
        now,
    }
}

async fn get(link: &str) -> String {
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
    page
}

async fn sign_in(relay: &TestRelay, email: &str, identity: &DeviceIdentity) -> relay::Config {
    let login = tokio::spawn({
        let (url, email, identity) = (relay.url.clone(), email.to_owned(), identity.clone());
        async move {
            relay::login(&url, &email, &identity, || {})
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

fn files(result: &CallToolResult) -> Vec<Value> {
    result.structured_content.as_ref().unwrap()["files"]
        .as_array()
        .unwrap()
        .clone()
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

/// The file bytes inside a get_inbox_file result.
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
        ContentBlock::Image(i) => B64.decode(&i.data).unwrap(),
        other => panic!("unexpected content {other:?}"),
    }
}

#[tokio::test]
async fn a_10_mb_file_comes_back_once_with_the_same_sha256() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "aj@example.com", &mac).await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dataset.bin");
    let data: Vec<u8> = (0..10 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(&path, &data).unwrap();
    let up = relay::upload(&config, &mac, &path).await.unwrap();
    assert_eq!(up.sha256, sha256_hex(&data));
    assert_eq!(up.size, 10 * 1024 * 1024);

    // Stored encrypted: the plaintext isn't in the stored blob.
    let sealed = relay.relay.sealed_blob(&up.inbox_id).unwrap();
    assert!(!sealed.windows(64).any(|w| w == &data[1000..1064]));

    let token = relay::create_token(&config, "test").await.unwrap();
    let client = mcp(&relay, &token).await;
    let listed = files(&call(&client, "list_inbox", json!({})).await);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["name"], "dataset.bin");
    assert_eq!(listed[0]["from_device"], "Mac");
    assert_eq!(listed[0]["sha256"], up.sha256.as_str());

    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    let bytes = file_bytes(&got);
    println!(
        "10 MB round trip: sent {} got {}",
        up.sha256,
        sha256_hex(&bytes)
    );
    assert_eq!(sha256_hex(&bytes), up.sha256);

    // Gone after the first read.
    assert!(files(&call(&client, "list_inbox", json!({})).await).is_empty());
    let again = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_eq!(error_code(&again), "not_found");
    assert!(
        relay.relay.sealed_blob(&up.inbox_id).is_none(),
        "blob deleted too"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn files_expire_after_24_hours() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "aj@example.com", &mac).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    std::fs::write(&path, "remember the milk").unwrap();
    let up = relay::upload(&config, &mac, &path).await.unwrap();
    let token = relay::create_token(&config, "test").await.unwrap();
    let client = mcp(&relay, &token).await;

    // 23 h 59 min later it's still there.
    relay
        .now
        .fetch_add(24 * 3600 * 1000 - 60_000, Ordering::SeqCst);
    assert_eq!(
        files(&call(&client, "list_inbox", json!({})).await).len(),
        1
    );
    // At 24 h it's gone, even before the sweep runs...
    relay.now.fetch_add(60_000, Ordering::SeqCst);
    assert!(files(&call(&client, "list_inbox", json!({})).await).is_empty());
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_eq!(error_code(&got), "not_found");
    // ...and the sweep deletes the stored blob.
    assert!(relay.relay.sealed_blob(&up.inbox_id).is_some());
    assert_eq!(relay.relay.expire_inbox(), 1);
    assert!(relay.relay.sealed_blob(&up.inbox_id).is_none());
    client.cancel().await.ok();
}

#[tokio::test]
async fn another_accounts_token_cannot_see_or_read_it() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let mine = sign_in(&relay, "aj@example.com", &mac).await;
    let stranger = DeviceIdentity::new("Stranger");
    let theirs = sign_in(&relay, "someone@example.com", &stranger).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.txt");
    std::fs::write(&path, "only for me").unwrap();
    let up = relay::upload(&mine, &mac, &path).await.unwrap();

    let their_token = relay::create_token(&theirs, "theirs").await.unwrap();
    let client = mcp(&relay, &their_token).await;
    assert!(files(&call(&client, "list_inbox", json!({})).await).is_empty());
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_eq!(error_code(&got), "not_found");
    let del = call(
        &client,
        "delete_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_eq!(error_code(&del), "not_found");
    client.cancel().await.ok();

    // Still there for its owner, and it's text, so it comes back as text.
    let my_token = relay::create_token(&mine, "mine").await.unwrap();
    let client = mcp(&relay, &my_token).await;
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert!(matches!(got.content[1], ContentBlock::Text(_)));
    assert_eq!(file_bytes(&got), b"only for me");
    client.cancel().await.ok();
}

#[tokio::test]
async fn requests_without_a_valid_token_get_401() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "aj@example.com", &mac).await;
    let token = relay::create_token(&config, "test").await.unwrap();

    let status = |auth: Option<String>| {
        let url = relay.url.clone();
        async move {
            let host = url.strip_prefix("http://").unwrap().to_owned();
            let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
            let auth = auth
                .map(|a| format!("Authorization: {a}\r\n"))
                .unwrap_or_default();
            let mut s = tokio::net::TcpStream::connect(&host).await.unwrap();
            s.write_all(
                format!(
                    "POST /mcp HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\n\
                     Accept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut response = String::new();
            s.read_to_string(&mut response).await.unwrap();
            response.split(' ').nth(1).unwrap().to_owned()
        }
    };
    assert_eq!(status(None).await, "401");
    assert_eq!(status(Some("Bearer made-up".into())).await, "401");
    assert_ne!(status(Some(format!("Bearer {token}"))).await, "401");

    assert_eq!(relay::revoke_tokens(&config).await.unwrap(), 1);
    assert_eq!(
        status(Some(format!("Bearer {token}"))).await,
        "401",
        "revoked"
    );
}

#[tokio::test]
async fn uploads_need_a_registered_device_and_stay_within_limits() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "aj@example.com", &mac).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.txt");
    std::fs::write(&path, "hi").unwrap();

    // A device that never registered can't put files in this account.
    let stranger = DeviceIdentity::new("Stranger");
    let err = relay::upload(&config, &stranger, &path)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("isn't registered"), "{err}");

    // Over 25 MB is refused before any data is sent.
    let big = dir.path().join("big.bin");
    std::fs::write(&big, vec![0u8; 25 * 1024 * 1024 + 1]).unwrap();
    let err = relay::upload(&config, &mac, &big)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("at most 25 MB"), "{err}");
}
