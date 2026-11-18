//! B3 tests: an assistant connects with OAuth 2.1 (discovery, dynamic client
//! registration, email sign-in, PKCE), reads a file sent from a device, and
//! loses access when its token expires or is revoked.

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
struct Links(Arc<Mutex<Vec<(String, String)>>>);

impl Mailer for Links {
    fn send_login_link(&self, email: &str, link: &str) {
        self.0
            .lock()
            .unwrap()
            .push((email.to_owned(), link.to_owned()));
    }
}

impl Links {
    async fn next(&self) -> String {
        for _ in 0..300 {
            if let Some((_, link)) = self.0.lock().unwrap().pop() {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no link was sent");
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
    tokio::spawn(opendrop_relay::serve(listener, relay));
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

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The value of query parameter `name` in `url`.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| {
            let mut out = Vec::new();
            let bytes = v.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            String::from_utf8(out).unwrap()
        })
    })
}

impl TestRelay {
    async fn get_json(&self, path: &str) -> Value {
        let text = self
            .http
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    async fn post(&self, path: &str, content_type: &str, body: String) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.url))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn register(&self, redirect: &str) -> reqwest::Response {
        let body = json!({ "client_name": "Claude", "redirect_uris": [redirect] }).to_string();
        self.post("/oauth/register", "application/json", body).await
    }

    async fn client_id(&self) -> String {
        let response = self.register(CALLBACK).await;
        assert_eq!(response.status(), 201);
        let json: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        json["client_id"].as_str().unwrap().to_owned()
    }

    /// Go through the consent page as the person would; returns the
    /// redirect back to the client.
    async fn consent(
        &self,
        client_id: &str,
        email: &str,
        verifier: &str,
        decision: &str,
    ) -> String {
        let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        let resource = format!("{}/mcp", self.url);
        let params = [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", CALLBACK),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", "st&ate 1"),
            ("scope", "inbox"),
            ("resource", &resource),
        ];
        let page = self
            .http
            .get(format!("{}/oauth/authorize?{}", self.url, form(&params)))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("Connect Claude to OpenDrop"), "{page}");
        assert!(page.contains("claude.ai"), "shows where it goes back to");

        let mut with_email = params.to_vec();
        with_email.push(("email", email));
        let sent = self
            .post(
                "/oauth/authorize",
                "application/x-www-form-urlencoded",
                form(&with_email),
            )
            .await
            .text()
            .await
            .unwrap();
        assert!(sent.contains("Check your email"), "{sent}");

        let link = self.links.next().await;
        let token = query_param(&link, "token").unwrap();
        // Opening the link only shows the question.
        let approve = self
            .http
            .get(&link)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(approve.contains("Allow Claude?"), "{approve}");
        let answered = self
            .post(
                "/oauth/approve",
                "application/x-www-form-urlencoded",
                form(&[("token", &token), ("decision", decision)]),
            )
            .await;
        assert_eq!(answered.status(), 303);
        answered.headers()["location"].to_str().unwrap().to_owned()
    }

    async fn code(&self, client_id: &str, email: &str, verifier: &str) -> String {
        let back = self.consent(client_id, email, verifier, "allow").await;
        assert!(back.starts_with(CALLBACK), "{back}");
        assert_eq!(query_param(&back, "state").as_deref(), Some("st&ate 1"));
        assert_eq!(
            query_param(&back, "iss").as_deref(),
            Some(self.url.as_str())
        );
        query_param(&back, "code").unwrap()
    }

    async fn token(&self, pairs: &[(&str, &str)]) -> (u16, Value) {
        let response = self
            .post(
                "/oauth/token",
                "application/x-www-form-urlencoded",
                form(pairs),
            )
            .await;
        let status = response.status().as_u16();
        let json = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        (status, json)
    }

    async fn exchange(&self, client_id: &str, code: &str, verifier: &str) -> (u16, Value) {
        let resource = format!("{}/mcp", self.url);
        self.token(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", verifier),
            ("resource", &resource),
        ])
        .await
    }

    async fn refresh(&self, client_id: &str, refresh_token: &str) -> (u16, Value) {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    /// The status `/mcp` gives a bearer token, and its challenge header.
    async fn mcp_status(&self, token: Option<&str>) -> (u16, String) {
        let mut request = self
            .http
            .post(format!("{}/mcp", self.url))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            );
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = request.send().await.unwrap();
        let challenge = response
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        (response.status().as_u16(), challenge)
    }

    fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }
}

const VERIFIER: &str = "a-very-long-pkce-verifier-0123456789-abcdefghijklmnop";

async fn sign_in_device(
    relay: &TestRelay,
    email: &str,
    identity: &DeviceIdentity,
) -> relay::Config {
    let login = tokio::spawn({
        let (url, email, identity) = (relay.url.clone(), email.to_owned(), identity.clone());
        async move {
            relay::login(&url, &email, &identity, || {})
                .await
                .map_err(|e| e.to_string())
        }
    });
    let link = relay.links.next().await;
    relay.http.get(&link).send().await.unwrap();
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

#[tokio::test]
async fn discovery_points_clients_at_the_authorization_server() {
    let relay = start_relay().await;
    let (status, challenge) = relay.mcp_status(None).await;
    assert_eq!(status, 401);
    let metadata_url = format!("{}/.well-known/oauth-protected-resource", relay.url);
    assert!(
        challenge.contains(&format!("resource_metadata=\"{metadata_url}\"")),
        "{challenge}"
    );

    let resource = relay
        .get_json("/.well-known/oauth-protected-resource")
        .await;
    assert_eq!(resource["resource"], format!("{}/mcp", relay.url));
    assert_eq!(resource["authorization_servers"][0], relay.url.as_str());
    let same = relay
        .get_json("/.well-known/oauth-protected-resource/mcp")
        .await;
    assert_eq!(same, resource);

    let server = relay
        .get_json("/.well-known/oauth-authorization-server")
        .await;
    assert_eq!(server["issuer"], relay.url.as_str());
    assert_eq!(server["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        server["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(
        server["registration_endpoint"],
        format!("{}/oauth/register", relay.url)
    );
}

#[tokio::test]
async fn an_assistant_connects_and_reads_a_sent_text_file() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in_device(&relay, "aj@example.com", &mac).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.txt");
    let text = "The blue heron landed on the third pier at 7:42.\n";
    std::fs::write(&path, text).unwrap();
    let sent = relay::upload(&config, &mac, &path).await.unwrap();

    let client_id = relay.client_id().await;
    let code = relay.code(&client_id, "AJ@example.com", VERIFIER).await;
    let (status, tokens) = relay.exchange(&client_id, &code, VERIFIER).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);
    let access = tokens["access_token"].as_str().unwrap();

    let client = mcp(&relay, access).await;
    let listed = call(&client, "list_inbox", json!({})).await;
    let files = listed.structured_content.unwrap()["files"].clone();
    assert_eq!(files[0]["name"], "note.txt");
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": sent.inbox_id }),
    )
    .await;
    let ContentBlock::Text(content) = &got.content[1] else {
        panic!("expected text, got {got:?}");
    };
    assert!(content.text.contains(text.trim()), "{}", content.text);

    // The code works once.
    let (status, error) = relay.exchange(&client_id, &code, VERIFIER).await;
    assert_eq!(
        (status, error["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn pkce_redirects_and_clients_are_checked() {
    let relay = start_relay().await;
    let client_id = relay.client_id().await;

    // Only HTTPS or loopback redirect URIs register.
    assert_eq!(relay.register("http://evil.example/cb").await.status(), 400);

    // A redirect URI the client didn't register gets an error page, not a redirect.
    let challenge = B64URL.encode(Sha256::digest(VERIFIER.as_bytes()));
    let wrong = relay
        .http
        .get(format!(
            "{}/oauth/authorize?{}",
            relay.url,
            form(&[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", "https://evil.example/cb"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 200);
    assert!(wrong.text().await.unwrap().contains("be trusted"));

    // Without PKCE the client gets an error at its redirect URI.
    let no_pkce = relay
        .http
        .get(format!(
            "{}/oauth/authorize?{}",
            relay.url,
            form(&[
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", CALLBACK),
                ("state", "s"),
            ])
        ))
        .send()
        .await
        .unwrap();
    let location = no_pkce.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );

    // The wrong verifier is refused (and uses up the code).
    let code = relay.code(&client_id, "aj@example.com", VERIFIER).await;
    let (status, error) = relay
        .exchange(
            &client_id,
            &code,
            "the-wrong-verifier-0123456789-abcdefghijklmnopqrs",
        )
        .await;
    assert_eq!(
        (status, error["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    // Another client can't use this client's code.
    let other_client = relay.client_id().await;
    let code = relay.code(&client_id, "aj@example.com", VERIFIER).await;
    let (status, _) = relay.exchange(&other_client, &code, VERIFIER).await;
    assert_eq!(status, 400);

    // Saying no sends the person back with access_denied.
    let back = relay
        .consent(&client_id, "aj@example.com", VERIFIER, "deny")
        .await;
    assert_eq!(
        query_param(&back, "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(&back, "code").is_none());
}

#[tokio::test]
async fn tokens_expire_rotate_and_revoke() {
    let relay = start_relay().await;
    let client_id = relay.client_id().await;
    let code = relay.code(&client_id, "aj@example.com", VERIFIER).await;
    let (_, tokens) = relay.exchange(&client_id, &code, VERIFIER).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(relay.mcp_status(Some(&access)).await.0, 200);

    // An hour later the access token is refused with invalid_token.
    relay.advance(60 * 60 * 1000 + 1);
    let (status, challenge) = relay.mcp_status(Some(&access)).await;
    assert_eq!(status, 401);
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");

    // The refresh token gets a new pair, once.
    let (status, renewed) = relay.refresh(&client_id, &refresh).await;
    assert_eq!(status, 200, "{renewed}");
    let access2 = renewed["access_token"].as_str().unwrap().to_owned();
    let refresh2 = renewed["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(refresh2, refresh);
    assert_eq!(relay.mcp_status(Some(&access2)).await.0, 200);

    // Replaying the old refresh token ends the whole chain.
    let (status, error) = relay.refresh(&client_id, &refresh).await;
    assert_eq!(
        (status, error["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert_eq!(relay.mcp_status(Some(&access2)).await.0, 401);
    assert_eq!(relay.refresh(&client_id, &refresh2).await.0, 400);

    // A fresh connection, then `opendrop relay revoke-tokens` from a device.
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in_device(&relay, "aj@example.com", &mac).await;
    let code = relay.code(&client_id, "aj@example.com", VERIFIER).await;
    let (_, tokens) = relay.exchange(&client_id, &code, VERIFIER).await;
    let access3 = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh3 = tokens["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(relay.mcp_status(Some(&access3)).await.0, 200);
    let revoked = relay::revoke_tokens(&config).await.unwrap();
    assert!(revoked >= 2, "access and refresh revoked: {revoked}");
    assert_eq!(relay.mcp_status(Some(&access3)).await.0, 401);
    assert_eq!(relay.refresh(&client_id, &refresh3).await.0, 400);

    // The refresh token itself is not an access token.
    assert_eq!(relay.mcp_status(Some(&refresh2)).await.0, 401);
}

#[tokio::test]
async fn another_accounts_assistant_sees_nothing() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in_device(&relay, "aj@example.com", &mac).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.txt");
    std::fs::write(&path, "secret").unwrap();
    let sent = relay::upload(&config, &mac, &path).await.unwrap();

    let client_id = relay.client_id().await;
    let code = relay
        .code(&client_id, "someone@example.com", VERIFIER)
        .await;
    let (_, tokens) = relay.exchange(&client_id, &code, VERIFIER).await;
    let client = mcp(&relay, tokens["access_token"].as_str().unwrap()).await;
    let listed = call(&client, "list_inbox", json!({})).await;
    assert_eq!(listed.structured_content.unwrap()["files"], json!([]));
    let got = call(
        &client,
        "get_inbox_file",
        json!({ "inbox_id": sent.inbox_id }),
    )
    .await;
    assert_eq!(got.is_error, Some(true));
}
