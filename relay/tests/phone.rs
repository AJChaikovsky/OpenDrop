//! B5 tests: a phone signs in with an emailed link and shares files into
//! the assistant inbox, from the web app (cookie) or the iPhone Shortcut
//! (bearer key), and can do nothing else.

use opendrop_relay::{Clock, Config, Mailer, Relay, inbox::Blobs, store::Store};
use reqwest::multipart::{Form, Part};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default, Clone)]
struct Links(Arc<Mutex<Vec<String>>>);

impl Mailer for Links {
    fn send_login_link(&self, _email: &str, link: &str) {
        self.0.lock().unwrap().push(link.to_owned());
    }
}

impl Links {
    async fn next(&self) -> String {
        for _ in 0..300 {
            if let Some(link) = self.0.lock().unwrap().pop() {
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
    http: reqwest::Client,
    db: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

const NOW: u64 = 1_800_000_000_000;

async fn start_relay() -> TestRelay {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let links = Links::default();
    let now = Arc::new(AtomicU64::new(NOW));
    let config = Config {
        clock: Clock(Arc::new(move || now.load(Ordering::SeqCst))),
        ..Config::new(&url)
    };
    let relay = Relay::new(
        Store::open(&db).unwrap(),
        Blobs::in_memory(),
        Box::new(links.clone()),
        config,
    );
    tokio::spawn(opendrop_relay::serve(listener, relay));
    opendrop_relay::email::install_crypto_provider();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    TestRelay {
        url,
        links,
        http,
        db,
        _dir: dir,
    }
}

impl TestRelay {
    /// What's waiting in the (first) account's inbox.
    fn inbox(&self) -> Vec<opendrop_relay::inbox::Item> {
        Store::open(&self.db).unwrap().inbox(1, NOW).unwrap()
    }

    /// Sign a phone in through the emailed link; returns its key.
    async fn sign_in(&self, name: &str) -> String {
        let r = self
            .http
            .post(format!("{}/phone/login", self.url))
            .form(&[("email", "AJ@example.com"), ("name", name)])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("on this phone"));
        let link = self.links.next().await;
        assert!(link.starts_with(&format!("{}/phone/verify?token=", self.url)));
        let token = link.split("token=").nth(1).unwrap().to_owned();
        // Opening the link (or a scanner opening it) changes nothing.
        for _ in 0..2 {
            let page = self
                .http
                .get(&link)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(page.contains("Sign in this phone"), "{page}");
            assert!(page.contains("aj@example.com"));
        }
        let r = self
            .http
            .post(format!("{}/phone/verify", self.url))
            .form(&[("token", token.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers()["location"], "/phone/");
        let cookie = r.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Path=/phone"), "{cookie}");
        let key = cookie
            .strip_prefix("od_phone=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(key.starts_with("odp_"));
        // The link works once.
        let again = self
            .http
            .post(format!("{}/phone/verify", self.url))
            .form(&[("token", token.as_str())])
            .send()
            .await
            .unwrap();
        assert!(again.text().await.unwrap().contains("already used"));
        key
    }

    async fn share(&self, auth: Auth<'_>, files: &[(&str, &str, Vec<u8>)]) -> reqwest::Response {
        let mut form = Form::new().text("title", "").text("text", "");
        for (name, mime, data) in files {
            form = form.part(
                "file",
                Part::bytes(data.clone())
                    .file_name(name.to_string())
                    .mime_str(mime)
                    .unwrap(),
            );
        }
        let request = self
            .http
            .post(format!("{}/phone/share", self.url))
            .multipart(form);
        let request = match auth {
            Auth::Cookie(key) => request.header("cookie", format!("od_phone={key}")),
            Auth::Bearer(key) => request.bearer_auth(key),
            Auth::None => request,
        };
        request.send().await.unwrap()
    }
}

#[derive(Clone, Copy)]
enum Auth<'a> {
    Cookie(&'a str),
    Bearer(&'a str),
    None,
}

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn a_phone_signs_in_and_shares_photos_into_the_inbox() {
    let relay = start_relay().await;
    let page = relay
        .http
        .get(format!("{}/phone/", relay.url))
        .header(
            "user-agent",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Email me a sign-in link"));
    assert!(page.contains("/phone/manifest.webmanifest"));
    assert!(
        page.contains("value=\"iPhone\""),
        "guesses the phone's name"
    );

    let key = relay.sign_in("AJ's iPhone").await;
    let home = relay
        .http
        .get(format!("{}/phone/", relay.url))
        .header("cookie", format!("od_phone={key}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        home.contains("Signed in as <b>aj@example.com</b>"),
        "{home}"
    );
    assert!(
        home.contains(&key),
        "the page shows the key for the Shortcut"
    );

    // The web app's share sheet (cookie): a page back.
    let photo = b"\xff\xd8\xff\xe0 pretend jpeg".to_vec();
    let r = relay
        .share(
            Auth::Cookie(&key),
            &[("IMG_0001.jpg", "image/jpeg", photo.clone())],
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("Sent IMG_0001.jpg to your assistant")
    );

    // The Shortcut (bearer): one line of text back.
    let second = b"\xff\xd8\xff\xe0 another".to_vec();
    let r = relay
        .share(Auth::Bearer(&key), &[("", "image/jpeg", second.clone())])
        .await;
    assert_eq!(r.status(), 200);
    let line = r.text().await.unwrap();
    assert!(
        line.starts_with("Sent shared-1800000000.jpg to your assistant."),
        "{line}"
    );
    assert!(!line.contains('<'));

    // Several at once.
    let r = relay
        .share(
            Auth::Cookie(&key),
            &[
                ("a.png", "image/png", b"png-a".to_vec()),
                ("notes.txt", "text/plain", b"hello".to_vec()),
            ],
        )
        .await;
    assert!(r.text().await.unwrap().contains("Sent 2 files"));

    let inbox = relay.inbox();
    assert_eq!(inbox.len(), 4);
    let first = inbox.iter().find(|i| i.name == "IMG_0001.jpg").unwrap();
    assert_eq!(first.sha256, sha(&photo));
    assert_eq!(first.size, photo.len() as u64);
    assert_eq!(first.mime, "image/jpeg");
    assert_eq!(first.from_device, "AJ's iPhone");
    let unnamed = inbox
        .iter()
        .find(|i| i.name.starts_with("shared-"))
        .unwrap();
    assert_eq!(unnamed.sha256, sha(&second));
}

#[tokio::test]
async fn shares_without_a_signed_in_phone_are_refused() {
    let relay = start_relay().await;
    let file = [("x.jpg", "image/jpeg", b"x".to_vec())];
    let r = relay.share(Auth::None, &file).await;
    assert_eq!(r.status(), 303, "a browser is sent to sign in");
    let r = relay.share(Auth::Bearer("odp_made_up"), &file).await;
    assert_eq!(r.status(), 401);
    let r = relay.share(Auth::Cookie("odp_made_up"), &file).await;
    assert_eq!(r.status(), 303);
    // An MCP token isn't a phone key, nor the other way round.
    let key = relay.sign_in("Phone").await;
    let r = relay
        .http
        .post(format!("{}/mcp", relay.url))
        .bearer_auth(&key)
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "a phone key can't read the inbox");
    assert!(relay.inbox().is_empty());
}

#[tokio::test]
async fn signing_out_ends_the_key() {
    let relay = start_relay().await;
    let key = relay.sign_in("Phone").await;
    let r = relay
        .http
        .post(format!("{}/phone/signout", relay.url))
        .header("cookie", format!("od_phone={key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert!(
        r.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let r = relay
        .share(
            Auth::Bearer(&key),
            &[("x.jpg", "image/jpeg", b"x".to_vec())],
        )
        .await;
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn phone_links_and_assistant_links_dont_mix() {
    let relay = start_relay().await;
    relay
        .http
        .post(format!("{}/phone/login", relay.url))
        .form(&[("email", "aj@example.com"), ("name", "Phone")])
        .send()
        .await
        .unwrap();
    let link = relay.links.next().await;
    let token = link.split("token=").nth(1).unwrap();
    // The OAuth consent page doesn't take a phone sign-in link.
    let page = relay
        .http
        .get(format!("{}/oauth/approve?token={token}", relay.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("already used"), "{page}");
    // And it's still good for the phone afterwards.
    let page = relay
        .http
        .get(&link)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Sign in this phone"));
}

#[tokio::test]
async fn the_web_app_can_be_installed_with_a_share_target() {
    let relay = start_relay().await;
    let manifest: serde_json::Value = relay
        .http
        .get(format!("{}/phone/manifest.webmanifest", relay.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(manifest["short_name"], "Send to assistant");
    assert_eq!(manifest["display"], "standalone");
    assert_eq!(manifest["share_target"]["action"], "/phone/share");
    assert_eq!(manifest["share_target"]["enctype"], "multipart/form-data");
    assert_eq!(
        manifest["share_target"]["params"]["files"][0]["name"],
        "file"
    );
    for icon in manifest["icons"].as_array().unwrap() {
        let r = relay
            .http
            .get(format!("{}{}", relay.url, icon["src"].as_str().unwrap()))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "image/png");
    }
    let sw = relay
        .http
        .get(format!("{}/phone/sw.js", relay.url))
        .send()
        .await
        .unwrap();
    assert_eq!(sw.headers()["content-type"], "text/javascript");
    assert!(sw.text().await.unwrap().contains("/phone/share"));
}
