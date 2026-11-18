//! B3: the OAuth 2.1 flow claude.ai and ChatGPT use, end to end against a
//! real relay: discovery, dynamic client registration, authorization code
//! with PKCE approved from a device, tokens on `/mcp`, refresh rotation,
//! expiry and revocation (`401`), scopes, and the usual attacks (wrong
//! verifier, reused code, foreign redirect URI, another client's code).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use opendrop::identity::DeviceIdentity;
use opendrop::relay;
use opendrop_relay::{Clock, Config, Mailer, Relay, inbox::Blobs, store::Store};
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

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
    now: Arc<AtomicU64>,
    http: reqwest::Client,
}

async fn start_relay() -> TestRelay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let links = Links::default();
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
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    TestRelay {
        url,
        links,
        now,
        http,
    }
}

impl TestRelay {
    fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    async fn get(&self, path_or_url: &str) -> reqwest::Response {
        let url = if path_or_url.starts_with("http") {
            path_or_url.to_owned()
        } else {
            format!("{}{path_or_url}", self.url)
        };
        self.http.get(url).send().await.unwrap()
    }

    async fn json(&self, path: &str) -> Value {
        serde_json::from_slice(&self.get(path).await.bytes().await.unwrap()).unwrap()
    }

    async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> (u16, Value) {
        let body: Vec<String> = form
            .iter()
            .map(|(k, v)| format!("{k}={}", enc(v)))
            .collect();
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.join("&"))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (
            status,
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Value::Null),
        )
    }

    async fn post_json(&self, path: &str, body: Value) -> (u16, Value) {
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (
            status,
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap(),
        )
    }
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn dec(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")).map(dec))
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
    relay.get(&link).await;
    login.await.unwrap().unwrap()
}

/// A PKCE verifier and its S256 challenge.
fn pkce() -> (String, String) {
    let verifier = B64URL.encode(opendrop::identity::random_bytes());
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn register(relay: &TestRelay, name: &str) -> String {
    let (status, body) = relay
        .post_json(
            "/oauth/register",
            json!({
                "client_name": name,
                "redirect_uris": [CALLBACK],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
            }),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    body["client_id"].as_str().unwrap().to_owned()
}

/// What the browser page holds: its request id and the code to approve.
struct Page {
    request: String,
    user_code: String,
}

async fn start_authorize(
    relay: &TestRelay,
    client_id: &str,
    challenge: &str,
    scope: Option<&str>,
) -> Page {
    let mut url = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state=xyz&code_challenge={challenge}\
         &code_challenge_method=S256&resource={}",
        enc(client_id),
        enc(CALLBACK),
        enc(&format!("{}/mcp", relay.url)),
    );
    if let Some(scope) = scope {
        url.push_str(&format!("&scope={}", enc(scope)));
    }
    let response = relay.get(&url).await;
    assert_eq!(response.status().as_u16(), 200);
    let html = response.text().await.unwrap();
    let user_code = html
        .split("opendrop relay approve ")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned();
    let request = html
        .split("continue?request=")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap()
        .to_owned();
    Page {
        request: dec(&request),
        user_code,
    }
}

/// Follow the page once approved: returns the `code` from the redirect.
async fn finish_authorize(relay: &TestRelay, page: &Page) -> String {
    let status = relay
        .json(&format!(
            "/oauth/authorize/status?request={}",
            enc(&page.request)
        ))
        .await;
    assert_eq!(status["status"], "approved");
    let response = relay
        .get(&format!(
            "/oauth/authorize/continue?request={}",
            enc(&page.request)
        ))
        .await;
    assert!(response.status().is_redirection(), "{}", response.status());
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.starts_with(CALLBACK), "{location}");
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
    assert_eq!(
        query_param(&location, "iss").as_deref(),
        Some(relay.url.as_str())
    );
    query_param(&location, "code").unwrap()
}

async fn exchange(relay: &TestRelay, client_id: &str, code: &str, verifier: &str) -> (u16, Value) {
    relay
        .post_form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CALLBACK),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("resource", &format!("{}/mcp", relay.url)),
            ],
        )
        .await
}

/// Register, authorize, approve on the device, exchange: the token response.
async fn connect(
    relay: &TestRelay,
    device: &relay::Config,
    scope: Option<&str>,
) -> (String, Value) {
    let client_id = register(relay, "Claude").await;
    let (verifier, challenge) = pkce();
    let page = start_authorize(relay, &client_id, &challenge, scope).await;
    let request = relay::authorize_lookup(device, &page.user_code)
        .await
        .unwrap();
    assert_eq!(request.client_name, "Claude");
    assert_eq!(request.redirect_host, "claude.ai");
    relay::authorize_decide(device, &page.user_code, true)
        .await
        .unwrap();
    let code = finish_authorize(relay, &page).await;
    let (status, tokens) = exchange(relay, &client_id, &code, &verifier).await;
    assert_eq!(status, 200, "{tokens}");
    (client_id, tokens)
}

type Client = RunningService<RoleClient, ()>;

async fn mcp(relay: &TestRelay, token: &str) -> Result<Client, String> {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", relay.url))
            .auth_header(token),
    );
    ().serve(transport).await.map_err(|e| e.to_string())
}

/// The HTTP status of an MCP `initialize` with this bearer token.
async fn mcp_status(relay: &TestRelay, token: Option<&str>) -> (u16, String) {
    let mut request = relay
        .http
        .post(format!("{}/mcp", relay.url))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"t","version":"1"}}})
            .to_string(),
        );
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (response.status().as_u16(), challenge)
}

async fn call(client: &Client, tool: &'static str, args: Value) -> CallToolResult {
    let mut params = CallToolRequestParams::new(tool);
    if let Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    client.call_tool(params).await.unwrap()
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| match c {
            ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn discovery_metadata_points_clients_at_the_oauth_server() {
    let relay = start_relay().await;
    let (status, challenge) = mcp_status(&relay, None).await;
    assert_eq!(status, 401);
    let metadata_url = format!("{}/.well-known/oauth-protected-resource/mcp", relay.url);
    assert!(
        challenge.contains(&format!("resource_metadata=\"{metadata_url}\"")),
        "{challenge}"
    );
    assert!(
        challenge.contains("scope=\"inbox:read inbox:write\""),
        "{challenge}"
    );

    for path in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    ] {
        let prm = relay.json(path).await;
        assert_eq!(prm["resource"], format!("{}/mcp", relay.url));
        assert_eq!(prm["authorization_servers"][0], relay.url);
    }
    let asm = relay.json("/.well-known/oauth-authorization-server").await;
    assert_eq!(asm["issuer"], relay.url);
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        asm["registration_endpoint"],
        format!("{}/oauth/register", relay.url)
    );
    assert_eq!(asm["authorization_response_iss_parameter_supported"], true);
    assert!(
        asm["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("none"))
    );
}

#[tokio::test]
async fn an_app_connects_with_pkce_and_quotes_a_sent_text_file() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let device = sign_in(&relay, "aj@example.com", &mac).await;
    let (_, tokens) = connect(&relay, &device, None).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);
    assert_eq!(tokens["scope"], "inbox:read inbox:write");
    let access = tokens["access_token"].as_str().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.txt");
    let note = "The quick brown fox: OpenDrop B3 test line 7f3a.";
    std::fs::write(&path, note).unwrap();
    let up = relay::upload(&device, &mac, &path).await.unwrap();

    let client = mcp(&relay, access).await.unwrap();
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_ne!(got.is_error, Some(true), "{got:?}");
    assert!(text_of(&got).contains(note), "{}", text_of(&got));
}

#[tokio::test]
async fn expired_refreshed_and_revoked_tokens() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let device = sign_in(&relay, "aj@example.com", &mac).await;
    let (client_id, tokens) = connect(&relay, &device, None).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(mcp_status(&relay, Some(&access)).await.0, 200);

    // An hour later the access token is expired: 401 with invalid_token.
    relay.advance(60 * 60 * 1000 + 1);
    let (status, challenge) = mcp_status(&relay, Some(&access)).await;
    println!("expired access token: {status} {challenge}");
    assert_eq!(status, 401);
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");

    // The refresh token gets a new pair, and works only once (rotation).
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh.as_str()),
        ("client_id", client_id.as_str()),
    ];
    let (status, renewed) = relay.post_form("/oauth/token", &form).await;
    assert_eq!(status, 200, "{renewed}");
    let (status, again) = relay.post_form("/oauth/token", &form).await;
    assert_eq!(
        (status, again["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    let access2 = renewed["access_token"].as_str().unwrap().to_owned();
    let refresh2 = renewed["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(mcp_status(&relay, Some(&access2)).await.0, 200);

    // Revoking from the device: the access token gets 401 and the refresh
    // token is refused.
    let count = relay::revoke_tokens(&device).await.unwrap();
    assert_eq!(count, 1);
    let (status, challenge) = mcp_status(&relay, Some(&access2)).await;
    println!("revoked access token: {status} {challenge}");
    assert_eq!(status, 401);
    let (status, body) = relay
        .post_form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh2.as_str()),
                ("client_id", client_id.as_str()),
            ],
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn codes_need_the_verifier_work_once_and_only_for_their_client() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let device = sign_in(&relay, "aj@example.com", &mac).await;
    let client_id = register(&relay, "Claude").await;
    let other_client = register(&relay, "Other").await;
    let (verifier, challenge) = pkce();
    let page = start_authorize(&relay, &client_id, &challenge, None).await;
    // Not approved yet: the page keeps waiting, no code.
    assert_eq!(
        relay
            .json(&format!(
                "/oauth/authorize/status?request={}",
                enc(&page.request)
            ))
            .await["status"],
        "pending"
    );
    let response = relay
        .get(&format!(
            "/oauth/authorize/continue?request={}",
            enc(&page.request)
        ))
        .await;
    assert_eq!(response.status().as_u16(), 200);
    // A guessed request id gets nothing.
    let response = relay.get("/oauth/authorize/continue?request=guess").await;
    assert_eq!(response.status().as_u16(), 400);

    relay::authorize_decide(&device, &page.user_code.to_lowercase(), true)
        .await
        .unwrap();
    // The code can't be approved twice.
    assert!(
        relay::authorize_decide(&device, &page.user_code, true)
            .await
            .is_err()
    );
    let code = finish_authorize(&relay, &page).await;
    // Only one redirect per sign-in.
    let response = relay
        .get(&format!(
            "/oauth/authorize/continue?request={}",
            enc(&page.request)
        ))
        .await;
    assert_eq!(response.status().as_u16(), 400);

    let (status, body) = exchange(&relay, &other_client, &code, &verifier).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    // That attempt used the code up (codes are single-use, even on failure).
    let (status, _) = exchange(&relay, &client_id, &code, &verifier).await;
    assert_eq!(status, 400);

    // A fresh sign-in: the wrong verifier fails, and a used code fails.
    let (verifier, challenge) = pkce();
    let page = start_authorize(&relay, &client_id, &challenge, None).await;
    relay::authorize_decide(&device, &page.user_code, true)
        .await
        .unwrap();
    let code = finish_authorize(&relay, &page).await;
    let (wrong, _) = pkce();
    let (status, body) = exchange(&relay, &client_id, &code, &wrong).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    let page = start_authorize(&relay, &client_id, &pkce().1, None).await;
    relay::authorize_decide(&device, &page.user_code, true)
        .await
        .unwrap();
    let _ = finish_authorize(&relay, &page).await;
    let (verifier2, challenge2) = pkce();
    let page = start_authorize(&relay, &client_id, &challenge2, None).await;
    relay::authorize_decide(&device, &page.user_code, true)
        .await
        .unwrap();
    let code = finish_authorize(&relay, &page).await;
    assert_eq!(exchange(&relay, &client_id, &code, &verifier2).await.0, 200);
    assert_eq!(exchange(&relay, &client_id, &code, &verifier2).await.0, 400);
    let _ = verifier;
}

#[tokio::test]
async fn denied_expired_and_foreign_redirects_get_no_code() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let device = sign_in(&relay, "aj@example.com", &mac).await;
    let client_id = register(&relay, "Claude").await;

    // Denied on the device: the app gets access_denied.
    let page = start_authorize(&relay, &client_id, &pkce().1, None).await;
    relay::authorize_decide(&device, &page.user_code, false)
        .await
        .unwrap();
    let response = relay
        .get(&format!(
            "/oauth/authorize/continue?request={}",
            enc(&page.request)
        ))
        .await;
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(&location, "code").is_none());

    // Codes stop working after 10 minutes.
    let page = start_authorize(&relay, &client_id, &pkce().1, None).await;
    relay.advance(10 * 60 * 1000 + 1);
    assert!(
        relay::authorize_lookup(&device, &page.user_code)
            .await
            .is_err()
    );

    // A redirect URI the client didn't register: an error page, no redirect.
    let response = relay
        .get(&format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            enc(&client_id),
            enc("https://evil.example/cb"),
            pkce().1
        ))
        .await;
    assert_eq!(response.status().as_u16(), 400);
    assert!(response.headers().get("location").is_none());

    // No PKCE: refused (back to the app with invalid_request).
    let response = relay
        .get(&format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}",
            enc(&client_id),
            enc(CALLBACK)
        ))
        .await;
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );

    // A token for another resource isn't issued.
    let response = relay
        .get(&format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}\
             &code_challenge_method=S256&resource={}",
            enc(&client_id),
            enc(CALLBACK),
            pkce().1,
            enc("https://other.example/mcp")
        ))
        .await;
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_target")
    );

    // Registration refuses non-HTTPS, non-loopback redirect URIs.
    let (status, body) = relay
        .post_json(
            "/oauth/register",
            json!({ "redirect_uris": ["http://evil.example/cb"] }),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_redirect_uri"))
    );
}

#[tokio::test]
async fn an_inbox_read_only_token_cannot_delete_and_sees_only_its_account() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let device = sign_in(&relay, "aj@example.com", &mac).await;
    let pc = DeviceIdentity::new("PC");
    let other = sign_in(&relay, "someone@example.com", &pc).await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.txt");
    std::fs::write(&path, "hello").unwrap();
    let up = relay::upload(&device, &mac, &path).await.unwrap();

    let (_, tokens) = connect(&relay, &device, Some("inbox:read")).await;
    assert_eq!(tokens["scope"], "inbox:read");
    let client = mcp(&relay, tokens["access_token"].as_str().unwrap())
        .await
        .unwrap();
    let refused = call(
        &client,
        "delete_inbox_file",
        json!({ "inbox_id": up.inbox_id }),
    )
    .await;
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(
        refused.structured_content.as_ref().unwrap()["code"],
        "insufficient_scope"
    );

    // Another account's connection doesn't see the file.
    let (_, theirs) = connect(&relay, &other, None).await;
    let client = mcp(&relay, theirs["access_token"].as_str().unwrap())
        .await
        .unwrap();
    let listed = call(&client, "list_inbox", json!({})).await;
    assert_eq!(listed.structured_content.unwrap()["files"], json!([]));
}
