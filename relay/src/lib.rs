//! OpenDrop relay server (Phase 9, stage B1; design doc
//! `docs/design/ai-file-requests.md`, "Option B").
//!
//! B1 is the skeleton: email sign-in links, a device registry keyed by each
//! device's Ed25519 identity, and a WebSocket gateway that shows which of an
//! account's devices are online. Later stages add the assistant inbox, the
//! hosted MCP server and OAuth on top.
//!
//! Every device exchange runs over `GET /v1/ws` (messages in
//! `opendrop::relay::proto`); the only other routes are the sign-in link a
//! person opens in a browser and a health check.

pub mod store;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use opendrop::relay::proto::{ClientMsg, DeviceStatus, ServerMsg, codes};
use opendrop::relay::proto::{hello_message, register_message};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::{Store, Verified};
use tokio::sync::Notify;

/// How the relay emails sign-in links.
pub trait Mailer: Send + Sync {
    fn send_login_link(&self, email: &str, link: &str);
}

/// Prints sign-in links to the relay's output instead of emailing them:
/// for running a relay yourself, where you can read its log.
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send_login_link(&self, email: &str, link: &str) {
        println!("sign-in link for {email}: {link}");
    }
}

/// Timings and addresses. Tests shorten the timings.
#[derive(Debug, Clone)]
pub struct Config {
    /// How people reach this relay, for links in emails, e.g.
    /// `https://relay.example.com`.
    pub public_url: String,
    /// How often the relay pings a connected device.
    pub ping_interval: Duration,
    /// A device that sends nothing (not even a pong) for this long is
    /// dropped and shown offline.
    pub idle_timeout: Duration,
    /// How long the relay waits for a device's request.
    pub request_timeout: Duration,
    /// Sign-in links one email address may request per 15 minutes.
    pub logins_per_window: usize,
}

impl Config {
    pub fn new(public_url: impl Into<String>) -> Self {
        Self {
            public_url: public_url.into().trim_end_matches('/').to_owned(),
            ping_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(25),
            request_timeout: Duration::from_secs(15),
            logins_per_window: 5,
        }
    }
}

pub struct Relay {
    store: Store,
    mailer: Box<dyn Mailer>,
    config: Config,
    /// Connections per online device id.
    online: Mutex<HashMap<String, usize>>,
    /// Sign-ins waiting for their link to be opened.
    waiting: Mutex<HashMap<String, Arc<Notify>>>,
    /// Recent sign-in requests per email, for rate limiting.
    recent_logins: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Relay {
    pub fn new(store: Store, mailer: Box<dyn Mailer>, config: Config) -> Arc<Self> {
        Arc::new(Self {
            store,
            mailer,
            config,
            online: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            recent_logins: Mutex::new(HashMap::new()),
        })
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.online.lock().unwrap().contains_key(device_id)
    }

    fn set_online(&self, device_id: &str, up: bool) {
        let mut online = self.online.lock().unwrap();
        let count = online.entry(device_id.to_owned()).or_insert(0);
        if up {
            *count += 1;
        } else {
            *count = count.saturating_sub(1);
            if *count == 0 {
                online.remove(device_id);
            }
        }
    }

    fn login_allowed(&self, email: &str) -> bool {
        let window = Duration::from_secs(15 * 60);
        let mut recent = self.recent_logins.lock().unwrap();
        let times = recent.entry(email.to_owned()).or_default();
        times.retain(|t| t.elapsed() < window);
        if times.len() >= self.config.logins_per_window {
            return false;
        }
        times.push(Instant::now());
        true
    }
}

pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/v1/ws", get(ws))
        .route("/v1/login/verify", get(verify))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(relay)
}

/// Serve on `listener` until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, relay: Arc<Relay>) -> std::io::Result<()> {
    axum::serve(listener, router(relay)).await
}

fn random_token() -> String {
    B64URL.encode(opendrop::identity::random_bytes())
}

#[derive(serde::Deserialize)]
struct VerifyQuery {
    token: String,
}

async fn verify(State(relay): State<Arc<Relay>>, Query(q): Query<VerifyQuery>) -> Response {
    let page = |title: &str, body: &str| {
        Html(format!(
            "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>\
             <title>OpenDrop</title><body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>\
             <h1>{title}</h1><p>{body}</p>"
        ))
        .into_response()
    };
    match relay.store.verify_login(&q.token) {
        Ok(Verified::Ok(login_id)) => {
            if let Some(waiter) = relay.waiting.lock().unwrap().get(&login_id) {
                waiter.notify_one();
            }
            page(
                "You're signed in",
                "Go back to OpenDrop: it has finished signing in.",
            )
        }
        Ok(Verified::Expired) => page(
            "This link has expired",
            "Sign-in links work for 15 minutes. Run the sign-in again for a new one.",
        ),
        Ok(Verified::Unknown) => page(
            "This link doesn't work",
            "It was already used or is wrong. Run the sign-in again for a new one.",
        ),
        Err(e) => {
            eprintln!("verify: {e}");
            page("Something went wrong", "Try the link again in a moment.")
        }
    }
}

async fn ws(State(relay): State<Arc<Relay>>, upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            if let Err(e) = handle(relay, socket).await {
                // Only the reason, never secrets: messages hold none we log.
                eprintln!("connection ended: {e}");
            }
        })
}

/// Ends the connection with this result (an error message was already sent
/// when it's a refusal).
type Done = Result<(), String>;

async fn send(socket: &mut WebSocket, msg: &ServerMsg) -> Result<(), String> {
    let text = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    socket
        .send(Message::text(text))
        .await
        .map_err(|e| format!("send failed: {e}"))
}

async fn refuse(socket: &mut WebSocket, code: &str, message: &str) -> Done {
    let _ = send(
        socket,
        &ServerMsg::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
    .await;
    let _ = socket.send(Message::Close(None)).await;
    Err(format!("refused: {code}"))
}

/// The device's next request, or `None` when it hung up.
async fn receive(socket: &mut WebSocket, timeout: Duration) -> Result<Option<ClientMsg>, String> {
    loop {
        let frame = tokio::time::timeout(timeout, socket.recv())
            .await
            .map_err(|_| "no request in time".to_owned())?;
        match frame {
            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return Ok(None),
            Some(Ok(Message::Text(text))) => {
                return match serde_json::from_str(&text) {
                    Ok(msg) => Ok(Some(msg)),
                    Err(e) => Err(format!("bad request: {e}")),
                };
            }
            Some(Ok(_)) => continue,
        }
    }
}

async fn handle(relay: Arc<Relay>, mut socket: WebSocket) -> Done {
    let nonce = opendrop::identity::random_bytes();
    send(
        &mut socket,
        &ServerMsg::Challenge {
            nonce: B64.encode(nonce),
        },
    )
    .await?;
    let mut logged_in = false;
    loop {
        let msg = match receive(&mut socket, relay.config.request_timeout).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return Ok(()),
            Err(e) => return refuse(&mut socket, codes::BAD_REQUEST, &e).await,
        };
        match msg {
            ClientMsg::LoginStart { email } if !logged_in => {
                login(&relay, &mut socket, &email).await?;
                logged_in = true;
            }
            ClientMsg::LoginStart { .. } => {
                return refuse(&mut socket, codes::BAD_REQUEST, "already signed in").await;
            }
            ClientMsg::Register {
                session,
                device_id,
                name,
                public_key,
                signature,
            } => {
                register(
                    &relay,
                    &mut socket,
                    &nonce,
                    &session,
                    &device_id,
                    &name,
                    &public_key,
                    &signature,
                )
                .await?
            }
            ClientMsg::ListDevices { session } => {
                list_devices(&relay, &mut socket, &session).await?
            }
            ClientMsg::Hello {
                device_id,
                signature,
            } => return hello(&relay, socket, &nonce, &device_id, &signature).await,
        }
    }
}

async fn login(relay: &Relay, socket: &mut WebSocket, email: &str) -> Done {
    let email = email.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') || email.contains(char::is_whitespace) {
        return refuse(socket, codes::BAD_REQUEST, "that isn't an email address").await;
    }
    if !relay.login_allowed(&email) {
        return refuse(
            socket,
            codes::RATE_LIMITED,
            "too many sign-in links for this address; wait 15 minutes",
        )
        .await;
    }
    let login_id = random_token();
    let token = random_token();
    let waiter = Arc::new(Notify::new());
    relay
        .waiting
        .lock()
        .unwrap()
        .insert(login_id.clone(), Arc::clone(&waiter));
    let result = async {
        relay.store.start_login(&login_id, &token, &email)?;
        let link = format!("{}/v1/login/verify?token={token}", relay.config.public_url);
        relay.mailer.send_login_link(&email, &link);
        send(socket, &ServerMsg::LoginStarted).await?;
        let deadline = Instant::now() + Duration::from_millis(store::LOGIN_TTL_MS);
        loop {
            let session = random_token();
            if let Some((account, _)) = relay.store.finish_login(&login_id, &session)? {
                return send(socket, &ServerMsg::LoginDone { account, session }).await;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("expired".to_owned());
            }
            // Woken by the link; the timeout also catches a device that
            // hung up meanwhile (the next send fails).
            let _ =
                tokio::time::timeout(left.min(Duration::from_secs(30)), waiter.notified()).await;
        }
    }
    .await;
    relay.waiting.lock().unwrap().remove(&login_id);
    match result {
        Err(e) if e == "expired" => {
            refuse(
                socket,
                codes::LOGIN_EXPIRED,
                "the sign-in link wasn't opened in time",
            )
            .await
        }
        other => other,
    }
}

fn decode_key(b64: &str) -> Option<[u8; 32]> {
    B64.decode(b64).ok()?.try_into().ok()
}

fn decode_signature(b64: &str) -> Option<[u8; 64]> {
    B64.decode(b64).ok()?.try_into().ok()
}

#[allow(clippy::too_many_arguments)]
async fn register(
    relay: &Relay,
    socket: &mut WebSocket,
    nonce: &[u8],
    session: &str,
    device_id: &str,
    name: &str,
    public_key: &str,
    signature: &str,
) -> Done {
    let Some((account_id, email)) = relay.store.session_account(session)? else {
        return refuse(
            socket,
            codes::BAD_SESSION,
            "not signed in; run `opendrop relay login`",
        )
        .await;
    };
    let (Some(key), Some(sig)) = (decode_key(public_key), decode_signature(signature)) else {
        return refuse(socket, codes::BAD_REQUEST, "malformed key or signature").await;
    };
    let name: String = name.chars().take(100).collect();
    if opendrop::identity::device_id_for(&key) != device_id
        || !opendrop::identity::verify(&key, &register_message(&email, device_id, nonce), &sig)
    {
        return refuse(
            socket,
            codes::BAD_SIGNATURE,
            "the device's signature doesn't match its key",
        )
        .await;
    }
    if relay
        .store
        .register_device(account_id, device_id, &name, &key)?
        .is_err()
    {
        return refuse(
            socket,
            codes::DEVICE_TAKEN,
            "this device is registered to another account",
        )
        .await;
    }
    send(
        socket,
        &ServerMsg::Registered {
            device_id: device_id.to_owned(),
        },
    )
    .await
}

async fn list_devices(relay: &Relay, socket: &mut WebSocket, session: &str) -> Done {
    let Some((account_id, _)) = relay.store.session_account(session)? else {
        return refuse(
            socket,
            codes::BAD_SESSION,
            "not signed in; run `opendrop relay login`",
        )
        .await;
    };
    let devices = relay
        .store
        .devices(account_id)?
        .into_iter()
        .map(|d| DeviceStatus {
            online: relay.is_online(&d.device_id),
            device_id: d.device_id,
            name: d.name,
            last_seen_ms: d.last_seen_ms,
        })
        .collect();
    send(socket, &ServerMsg::DeviceList { devices }).await
}

async fn hello(
    relay: &Relay,
    mut socket: WebSocket,
    nonce: &[u8],
    device_id: &str,
    signature: &str,
) -> Done {
    let Some(device) = relay.store.device(device_id)? else {
        return refuse(
            &mut socket,
            codes::UNKNOWN_DEVICE,
            "this device isn't registered; run `opendrop relay login`",
        )
        .await;
    };
    let Some(sig) = decode_signature(signature) else {
        return refuse(&mut socket, codes::BAD_REQUEST, "malformed signature").await;
    };
    if !opendrop::identity::verify(&device.public_key, &hello_message(device_id, nonce), &sig) {
        return refuse(
            &mut socket,
            codes::BAD_SIGNATURE,
            "the device's signature doesn't match its key",
        )
        .await;
    }
    let account = relay.store.account_email(device.account_id)?;
    send(&mut socket, &ServerMsg::Welcome { account }).await?;
    relay.set_online(device_id, true);
    relay.store.touch_device(device_id)?;
    let result = stay_online(relay, &mut socket).await;
    relay.set_online(device_id, false);
    relay.store.touch_device(device_id)?;
    result
}

/// Ping the device and wait; return when it hangs up or goes quiet.
async fn stay_online(relay: &Relay, socket: &mut WebSocket) -> Done {
    let mut ping = tokio::time::interval(relay.config.ping_interval);
    ping.tick().await;
    let mut last_heard = Instant::now();
    loop {
        tokio::select! {
            frame = socket.recv() => match frame {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return Ok(()),
                // Anything, pongs included, shows the device is still there.
                Some(Ok(_)) => last_heard = Instant::now(),
            },
            _ = ping.tick() => {
                if last_heard.elapsed() >= relay.config.idle_timeout {
                    let _ = socket.send(Message::Close(None)).await;
                    return Err("device went quiet".to_owned());
                }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}
