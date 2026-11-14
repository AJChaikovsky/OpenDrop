//! B1 acceptance tests, run against a real relay on loopback: sign in with a
//! link, register, show online and offline in time, refuse forged keys.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use opendrop::identity::DeviceIdentity;
use opendrop::relay::proto::{ClientMsg, ServerMsg, codes, hello_message, register_message};
use opendrop::relay::{self, Status};
use opendrop_relay::{Config, Mailer, Relay, store::Store};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

/// Keeps sign-in links instead of emailing them.
#[derive(Default, Clone)]
struct Inbox(Arc<Mutex<Vec<(String, String)>>>);

impl Mailer for Inbox {
    fn send_login_link(&self, email: &str, link: &str) {
        self.0
            .lock()
            .unwrap()
            .push((email.to_owned(), link.to_owned()));
    }
}

impl Inbox {
    async fn next_link(&self) -> String {
        for _ in 0..200 {
            if let Some((_, link)) = self.0.lock().unwrap().pop() {
                return link;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no sign-in link was sent");
    }
}

struct TestRelay {
    url: String,
    relay: Arc<Relay>,
    inbox: Inbox,
}

async fn start_relay() -> TestRelay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let inbox = Inbox::default();
    let config = Config {
        ping_interval: Duration::from_millis(200),
        idle_timeout: Duration::from_millis(800),
        ..Config::new(&url)
    };
    let relay = Relay::new(Store::in_memory().unwrap(), Box::new(inbox.clone()), config);
    tokio::spawn(opendrop_relay::serve(listener, Arc::clone(&relay)));
    TestRelay { url, relay, inbox }
}

/// Open a link as a browser would; returns the page.
async fn open_link(link: &str) -> String {
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
    let link = relay.inbox.next_link().await;
    assert!(open_link(&link).await.contains("You're signed in"));
    login.await.unwrap().unwrap()
}

async fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if done() {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

#[tokio::test]
async fn sign_in_register_and_show_online_then_offline() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "AJ@Example.com", &mac).await;
    assert_eq!(config.account, "aj@example.com");

    let devices = relay::devices(&config).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        (devices[0].device_id.as_str(), devices[0].online),
        (mac.id.as_str(), false)
    );

    // Online within 5 s of starting.
    let (tx, mut rx) = tokio::sync::watch::channel(Status::Connecting);
    let task = tokio::spawn(relay::run(config.clone(), mac.clone(), tx));
    let up = wait_until(Duration::from_secs(5), || relay.relay.is_online(&mac.id))
        .await
        .expect("online within 5 s");
    println!("online after {up:?}");
    rx.wait_for(|s| *s == Status::Online).await.unwrap();
    assert!(relay::devices(&config).await.unwrap()[0].online);

    // It answers pings, so it stays online well past the idle timeout.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        relay.relay.is_online(&mac.id),
        "a device that answers pings stays online"
    );

    // Offline within 30 s of stopping.
    task.abort();
    let down = wait_until(Duration::from_secs(30), || !relay.relay.is_online(&mac.id))
        .await
        .expect("offline within 30 s");
    println!("offline after {down:?}");
    let listed = relay::devices(&config).await.unwrap();
    assert!(!listed[0].online);
    assert!(listed[0].last_seen_ms > 0);
}

/// A raw connection: the relay's challenge, decoded.
async fn raw(
    url: &str,
) -> (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Vec<u8>,
) {
    let (mut ws, _) = tokio_tungstenite::connect_async(relay::ws_url(url).unwrap())
        .await
        .unwrap();
    let Some(Ok(Message::Text(text))) = ws.next().await else {
        panic!("no challenge")
    };
    let ServerMsg::Challenge { nonce } = serde_json::from_str(&text).unwrap() else {
        panic!()
    };
    (ws, B64.decode(nonce).unwrap())
}

async fn reply(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> ServerMsg {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            _ => continue,
        }
    }
}

fn error_code(msg: ServerMsg) -> String {
    match msg {
        ServerMsg::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn forged_keys_are_refused() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let config = sign_in(&relay, "aj@example.com", &mac).await;
    let thief = DeviceIdentity::new("Thief");

    // Hello as the Mac, signed with another key.
    let (mut ws, nonce) = raw(&relay.url).await;
    let sig = thief.sign(&hello_message(&mac.id, &nonce));
    let hello = ClientMsg::Hello {
        device_id: mac.id.clone(),
        signature: B64.encode(sig),
    };
    ws.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws).await), codes::BAD_SIGNATURE);
    assert!(!relay.relay.is_online(&mac.id));

    // A real signature replayed on another connection (other challenge).
    let (mut ws, nonce) = raw(&relay.url).await;
    let (mut ws2, _) = raw(&relay.url).await;
    let sig = mac.sign(&hello_message(&mac.id, &nonce));
    let hello = ClientMsg::Hello {
        device_id: mac.id.clone(),
        signature: B64.encode(sig),
    };
    ws2.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws2).await), codes::BAD_SIGNATURE);
    ws.send(Message::Close(None)).await.ok();

    // A device that never registered.
    let (mut ws, nonce) = raw(&relay.url).await;
    let sig = thief.sign(&hello_message(&thief.id, &nonce));
    let hello = ClientMsg::Hello {
        device_id: thief.id.clone(),
        signature: B64.encode(sig),
    };
    ws.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws).await), codes::UNKNOWN_DEVICE);

    // Registering the Mac's id with another key, even with a valid session.
    let (mut ws, nonce) = raw(&relay.url).await;
    let register = ClientMsg::Register {
        session: config.session.clone(),
        device_id: mac.id.clone(),
        name: "Mac".into(),
        public_key: B64.encode(thief.public_key()),
        signature: B64.encode(thief.sign(&register_message(&config.account, &mac.id, &nonce))),
    };
    ws.send(Message::text(serde_json::to_string(&register).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws).await), codes::BAD_SIGNATURE);

    // A made-up session.
    let (mut ws, _) = raw(&relay.url).await;
    let list = ClientMsg::ListDevices {
        session: "made-up".into(),
    };
    ws.send(Message::text(serde_json::to_string(&list).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws).await), codes::BAD_SESSION);

    // Another account can't take over the Mac's registration.
    let other = sign_in(&relay, "someone@example.com", &thief).await;
    let (mut ws, nonce) = raw(&relay.url).await;
    let register = ClientMsg::Register {
        session: other.session.clone(),
        device_id: mac.id.clone(),
        name: "Mac".into(),
        public_key: B64.encode(mac.public_key()),
        signature: B64.encode(mac.sign(&register_message(&other.account, &mac.id, &nonce))),
    };
    ws.send(Message::text(serde_json::to_string(&register).unwrap()))
        .await
        .unwrap();
    assert_eq!(error_code(reply(&mut ws).await), codes::DEVICE_TAKEN);
    let theirs = relay::devices(&other).await.unwrap();
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0].device_id, thief.id);
}

#[tokio::test]
async fn a_device_that_goes_quiet_is_dropped() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    sign_in(&relay, "aj@example.com", &mac).await;
    let (mut ws, nonce) = raw(&relay.url).await;
    let sig = mac.sign(&hello_message(&mac.id, &nonce));
    let hello = ClientMsg::Hello {
        device_id: mac.id.clone(),
        signature: B64.encode(sig),
    };
    ws.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    assert!(matches!(reply(&mut ws).await, ServerMsg::Welcome { .. }));
    assert!(relay.relay.is_online(&mac.id));
    // Stop reading: pings go unanswered, like a laptop whose Wi-Fi dropped.
    let gone = wait_until(Duration::from_secs(5), || !relay.relay.is_online(&mac.id))
        .await
        .expect("dropped after the idle timeout");
    println!("quiet device dropped after {gone:?}");
    assert!(
        gone >= Duration::from_millis(700),
        "not before the idle timeout"
    );
    drop(ws);
}

#[tokio::test]
async fn sign_in_links_work_once() {
    let relay = start_relay().await;
    let mac = DeviceIdentity::new("Mac");
    let login = tokio::spawn({
        let url = relay.url.clone();
        let mac = mac.clone();
        async move {
            relay::login(&url, "aj@example.com", &mac, || {})
                .await
                .map_err(|e| e.to_string())
        }
    });
    let link = relay.inbox.next_link().await;
    assert!(open_link(&link).await.contains("You're signed in"));
    login.await.unwrap().unwrap();
    assert!(open_link(&link).await.contains("doesn't work"));
}
