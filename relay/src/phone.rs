//! "Send to assistant" from phones (stage B5).
//!
//! A phone signs in with the same emailed link as everything else and gets
//! a key that can do one thing: put files in the account's assistant inbox.
//! It can't list devices, fetch files or read the inbox.
//!
//! - Android: `/phone/` is an installable web app whose manifest declares a
//!   share target, so once it's added to the home screen "Send to assistant"
//!   shows up in the share sheet. The key lives in an HttpOnly cookie.
//! - iPhone: a "Send to assistant" Shortcut posts to `/phone/share` with the
//!   key as a bearer token (the phone page shows the key to paste in).
//!
//! Big photos are scaled down so an assistant can look at them (they come
//! back as images only up to 5 MB).

use crate::oauth::{esc, page};
use crate::{Relay, inbox};
use axum::Router;
use axum::extract::{DefaultBodyLimit, Form, Multipart, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const COOKIE: &str = "od_phone";
/// Photos bigger than this are scaled down before they go in the inbox.
pub const SCALE_ABOVE: usize = 4 * 1024 * 1024;
/// The longest side of a scaled-down photo.
pub const SCALED_EDGE: u32 = 2048;

/// The iPhone Shortcut, built by `assets/make_shortcut.py` and signed on a
/// Mac (`shortcuts sign`), since iOS only imports signed ones.
const SHORTCUT: &[u8] = include_bytes!("../assets/send-to-assistant.shortcut");

const ICON_256: &[u8] = include_bytes!("../../app/src-tauri/icons/128x128@2x.png");
const ICON_512: &[u8] = include_bytes!("../../app/src-tauri/icons/icon.png");

pub fn router() -> Router<Arc<Relay>> {
    Router::new()
        .route("/phone", get(|| async { Redirect::permanent("/phone/") }))
        .route("/phone/", get(home))
        .route("/phone/login", post(login))
        .route("/phone/verify", get(verify_page).post(verify))
        .route(
            "/phone/share",
            post(share).layer(DefaultBodyLimit::max(
                (inbox::ACCOUNT_QUOTA + 1024 * 1024) as usize,
            )),
        )
        .route("/phone/signout", post(signout))
        .route("/phone/shortcut", get(shortcut))
        .route("/phone/manifest.webmanifest", get(manifest))
        .route("/phone/sw.js", get(service_worker))
        .route("/phone/icon-256.png", get(|| async { png(ICON_256) }))
        .route("/phone/icon-512.png", get(|| async { png(ICON_512) }))
}

fn png(bytes: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
}

/// The phone key from the cookie or an `Authorization: Bearer` header.
fn phone_key(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get(header::AUTHORIZATION)
        && let Some(token) = auth.to_str().ok().and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(token.trim().to_owned());
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_owned())
}

/// The signed-in phone: `(key, account id, phone name)`.
fn signed_in(relay: &Relay, headers: &HeaderMap) -> Option<(String, i64, String)> {
    let key = phone_key(headers)?;
    match relay.store.phone(&key, relay.now()) {
        Ok(Some((account, name))) => Some((key, account, name)),
        Ok(None) => None,
        Err(e) => {
            eprintln!("phone: {e}");
            None
        }
    }
}

fn cookie(relay: &Relay, value: &str, max_age: u64) -> String {
    let secure = if relay.config.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{COOKIE}={value}; Path=/phone; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
}

/// A page that belongs to the web app (manifest and service worker linked).
fn app_page(title: &str, body: &str) -> Response {
    let head = "<link rel=manifest href=/phone/manifest.webmanifest>\
                <meta name=theme-color content='#2563eb'>\
                <link rel=apple-touch-icon href=/phone/icon-256.png>\
                <script>if('serviceWorker' in navigator)navigator.serviceWorker.register('/phone/sw.js',{scope:'/phone/'})</script>";
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
        ],
        axum::response::Html(page_html(title, body, head)),
    )
        .into_response()
}

fn page_html(title: &str, body: &str, head: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>\
         <title>OpenDrop</title>{head}<body style='font-family:system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.5'>\
         <h1>{}</h1>{body}",
        esc(title)
    )
}

const BUTTON: &str = "font-size:1rem;padding:.5rem 1rem";
const INPUT: &str = "font-size:1rem;padding:.4rem;width:100%;box-sizing:border-box";

async fn home(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    let Some((key, account, name)) = signed_in(&relay, &headers) else {
        return app_page(
            "Send to assistant",
            &format!(
                "<p>Share photos and files from this phone straight to your AI assistant's \
                 OpenDrop inbox.</p>\
                 <form method=post action=/phone/login>\
                 <p><label>Your OpenDrop email<br><input name=email type=email required \
                 autocomplete=email style='{INPUT}'></label></p>\
                 <p><label>Name this phone<br><input name=name required maxlength=60 \
                 value=\"{}\" style='{INPUT}'></label></p>\
                 <p><button style='{BUTTON}'>Email me a sign-in link</button></p></form>",
                esc(guess_name(&headers))
            ),
        );
    };
    let email = relay.store.account_email(account).unwrap_or_default();
    let iphone = is_iphone(&headers);
    let android = "<h2>Android</h2><p>In Chrome, open the <b>⋮</b> menu and choose <b>Add to Home screen</b> \
         (or <b>Install app</b>). After that, <b>Send to assistant</b> is in the share sheet \
         whenever you share a photo.</p>"
        .to_owned();
    let ios = format!(
        "<h2>iPhone</h2><p>Add the <b>Send to assistant</b> shortcut: open \
         <a href=/phone/shortcut>this link</a> in Safari and choose <b>Add Shortcut</b>. When it asks \
         for your key, paste this:</p>\
         <p><input id=key readonly value=\"{key}\" style='{INPUT};font-family:monospace'></p>\
         <p><button style='{BUTTON}' onclick=\"navigator.clipboard.writeText(document.getElementById('key').value);this.textContent='Copied'\">Copy key</button></p>\
         <p>The key can only send files to your assistant. Keep it to yourself anyway.</p>",
        key = esc(&key)
    );
    let (first, second) = if iphone {
        (ios, android)
    } else {
        (android, ios)
    };
    app_page(
        "Send to assistant",
        &format!(
            "<p>Signed in as <b>{email}</b> on <b>{name}</b>.</p>\
             <form method=post action=/phone/share enctype=multipart/form-data>\
             <p><input type=file name=file multiple required style='{INPUT}'></p>\
             <p><button style='{BUTTON}'>Send to assistant</button></p></form>\
             {first}{second}\
             <form method=post action=/phone/signout><p><button style='{BUTTON}'>Sign this phone out</button></p></form>",
            email = esc(&email),
            name = esc(&name),
        ),
    )
}

fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

fn is_iphone(headers: &HeaderMap) -> bool {
    let ua = user_agent(headers);
    ua.contains("iPhone") || ua.contains("iPad")
}

fn guess_name(headers: &HeaderMap) -> &'static str {
    let ua = user_agent(headers);
    if ua.contains("iPhone") {
        "iPhone"
    } else if ua.contains("iPad") {
        "iPad"
    } else if ua.contains("Android") {
        "Android phone"
    } else {
        "Phone"
    }
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    name: String,
}

/// What a phone sign-in request remembers until the link is opened. Kept
/// with OAuth's pending requests; the `phone` field keeps the two apart.
#[derive(Serialize, Deserialize)]
struct PhoneGrant {
    phone: String,
}

async fn login(State(relay): State<Arc<Relay>>, Form(f): Form<LoginForm>) -> Response {
    let email = f.email.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') || email.contains(char::is_whitespace) {
        return page(
            "That isn't an email address",
            "<p>Go back and try again.</p>",
        );
    }
    let name: String = f
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(60)
        .collect();
    let name = if name.is_empty() {
        "Phone".to_owned()
    } else {
        name
    };
    if !relay.login_allowed(&email) {
        return page(
            "Too many sign-in links",
            "<p>Wait 15 minutes and try again.</p>",
        );
    }
    let token = crate::random_token();
    let grant = serde_json::to_string(&PhoneGrant { phone: name }).unwrap();
    if let Err(e) = relay
        .store
        .add_oauth_request(&token, &grant, &email, relay.now())
    {
        eprintln!("phone login: {e}");
        return page("Something went wrong", "<p>Try again in a moment.</p>");
    }
    let link = format!("{}/phone/verify?token={token}", relay.config.public_url);
    relay.mailer.send_login_link(&email, &link);
    page(
        "Check your email",
        &format!(
            "<p>We sent a sign-in link to <b>{}</b>. Open it <b>on this phone</b>, in this \
             browser. It works for 15 minutes.</p>",
            esc(&email)
        ),
    )
}

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

fn expired() -> Response {
    page(
        "This link doesn't work",
        "<p>It was already used or has expired. Start again from <a href=/phone/>the phone page</a>.</p>",
    )
}

/// The emailed link. Opening it changes nothing (link scanners open links
/// too); only the button signs the phone in.
async fn verify_page(State(relay): State<Arc<Relay>>, Query(q): Query<TokenQuery>) -> Response {
    let (grant, email) = match relay.store.oauth_request(&q.token, relay.now()) {
        Ok(Some(found)) => found,
        Ok(None) => return expired(),
        Err(e) => {
            eprintln!("phone verify: {e}");
            return page(
                "Something went wrong",
                "<p>Try the link again in a moment.</p>",
            );
        }
    };
    let Ok(grant) = serde_json::from_str::<PhoneGrant>(&grant) else {
        return expired();
    };
    page(
        &format!("Sign in {}?", grant.phone),
        &format!(
            "<p>Signed in as <b>{email}</b>.</p>\
             <p>This phone will be able to send files to your assistant's inbox, and nothing \
             else, until you sign it out.</p>\
             <form method=post action=/phone/verify><input type=hidden name=token value=\"{token}\">\
             <button style='{BUTTON}'>Sign in this phone</button></form>",
            email = esc(&email),
            token = esc(&q.token),
        ),
    )
}

async fn verify(State(relay): State<Arc<Relay>>, Form(f): Form<TokenQuery>) -> Response {
    // Check it's a phone request before using it up.
    match relay.store.oauth_request(&f.token, relay.now()) {
        Ok(Some((grant, _))) if serde_json::from_str::<PhoneGrant>(&grant).is_ok() => {}
        Ok(_) => return expired(),
        Err(e) => {
            eprintln!("phone verify: {e}");
            return page("Something went wrong", "<p>Try again in a moment.</p>");
        }
    }
    let now = relay.now();
    let (grant, account) = match relay.store.take_oauth_request(&f.token, now) {
        Ok(Some(found)) => found,
        Ok(None) => return expired(),
        Err(e) => {
            eprintln!("phone verify: {e}");
            return page("Something went wrong", "<p>Try again in a moment.</p>");
        }
    };
    let Ok(grant) = serde_json::from_str::<PhoneGrant>(&grant) else {
        return expired();
    };
    let key = format!("odp_{}", crate::random_token());
    if let Err(e) = relay.store.add_phone(account, &key, &grant.phone, now) {
        eprintln!("phone verify: {e}");
        return page("Something went wrong", "<p>Try again in a moment.</p>");
    }
    (
        [(header::SET_COOKIE, cookie(&relay, &key, 400 * 24 * 60 * 60))],
        Redirect::to("/phone/"),
    )
        .into_response()
}

async fn signout(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    if let Some(key) = phone_key(&headers)
        && let Err(e) = relay.store.remove_phone(&key)
    {
        eprintln!("phone signout: {e}");
    }
    (
        [(header::SET_COOKIE, cookie(&relay, "", 0))],
        Redirect::to("/phone/"),
    )
        .into_response()
}

/// Whether the answer should be a page (a browser) or one line of text (a
/// Shortcut or script, which sends a bearer token).
fn wants_text(headers: &HeaderMap) -> bool {
    headers.contains_key(header::AUTHORIZATION)
}

fn answer(text_mode: bool, status: StatusCode, title: &str, detail: &str) -> Response {
    if text_mode {
        (
            status,
            format!("{title}. {detail}")
                .trim_end_matches(". ")
                .to_owned(),
        )
            .into_response()
    } else {
        let mut response = page(
            title,
            &format!("<p>{}</p><p><a href=/phone/>Back</a></p>", esc(detail)),
        );
        *response.status_mut() = status;
        response
    }
}

/// Files shared from the phone: the share sheet (web app), the Shortcut,
/// or the form on the phone page. Field `file`, one or more.
async fn share(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    mut form: Multipart,
) -> Response {
    let text_mode = wants_text(&headers);
    let Some((_, account, phone)) = signed_in(&relay, &headers) else {
        if text_mode {
            return (
                StatusCode::UNAUTHORIZED,
                "This key isn't signed in. Get a new one from the OpenDrop phone page.",
            )
                .into_response();
        }
        return Redirect::to("/phone/").into_response();
    };
    let mut sent = Vec::new();
    loop {
        let field = match form.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => {
                return answer(
                    text_mode,
                    StatusCode::BAD_REQUEST,
                    "The upload broke off",
                    &e.body_text(),
                );
            }
        };
        if field.name() != Some("file") {
            continue;
        }
        let name = field.file_name().map(crate::clean_name).unwrap_or_default();
        let content_type = field.content_type().unwrap_or_default().to_owned();
        let data = match field.bytes().await {
            Ok(data) => data,
            Err(e) => {
                return answer(
                    text_mode,
                    StatusCode::BAD_REQUEST,
                    "The upload broke off",
                    &e.body_text(),
                );
            }
        };
        if data.is_empty() {
            continue;
        }
        let name = if name.is_empty() {
            default_name(&content_type, relay.now())
        } else {
            name
        };
        let (name, data) =
            tokio::task::spawn_blocking(move || fit_for_assistant(name, data.to_vec()))
                .await
                .unwrap_or_else(|_| (String::new(), Vec::new()));
        if data.is_empty() {
            return answer(
                text_mode,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Try again in a moment.",
            );
        }
        if let Err((_, message)) = relay.inbox_room(account, data.len() as u64) {
            return answer(
                text_mode,
                StatusCode::PAYLOAD_TOO_LARGE,
                "Not sent",
                &message,
            );
        }
        let digest: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        match relay.put_in_inbox(account, &phone, name, &data, digest) {
            Ok(item) => sent.push(item.name),
            Err(e) => {
                eprintln!("phone share: {e}");
                return answer(
                    text_mode,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong",
                    "Try again in a moment.",
                );
            }
        }
    }
    if sent.is_empty() {
        return answer(
            text_mode,
            StatusCode::BAD_REQUEST,
            "Nothing was sent",
            "There was no file in what was shared.",
        );
    }
    let what = if sent.len() == 1 {
        sent[0].clone()
    } else {
        format!("{} files", sent.len())
    };
    answer(
        text_mode,
        StatusCode::OK,
        &format!("Sent {what} to your assistant"),
        "Ask your assistant to look at it. It waits in the inbox for 24 hours.",
    )
}

/// A name for a shared file that came without one.
fn default_name(content_type: &str, now_ms: u64) -> String {
    let ext = match content_type {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/heic" | "image/heif" => "heic",
        "image/webp" => "webp",
        "image/gif" => "gif",
        "application/pdf" => "pdf",
        t if t.starts_with("text/") => "txt",
        _ => "bin",
    };
    format!("shared-{}.{ext}", now_ms / 1000)
}

/// Scale a big JPEG, PNG or WebP photo down to at most [`SCALED_EDGE`]
/// pixels on its longest side, as a JPEG, so an assistant can look at it.
/// Anything else, or anything that won't decode, is kept as it is.
pub fn fit_for_assistant(name: String, data: Vec<u8>) -> (String, Vec<u8>) {
    use image::ImageDecoder;
    let scalable = matches!(
        inbox::mime_for(&name),
        "image/jpeg" | "image/png" | "image/webp"
    );
    if !scalable || data.len() <= SCALE_ABOVE {
        return (name, data);
    }
    let scaled = (|| -> Result<Vec<u8>, image::ImageError> {
        let reader = image::ImageReader::new(std::io::Cursor::new(&data)).with_guessed_format()?;
        let mut decoder = reader.into_decoder()?;
        let orientation = decoder.orientation()?;
        let mut img = image::DynamicImage::from_decoder(decoder)?;
        img.apply_orientation(orientation);
        let img = img.resize(
            SCALED_EDGE,
            SCALED_EDGE,
            image::imageops::FilterType::Lanczos3,
        );
        let mut out = Vec::new();
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
        img.to_rgb8().write_with_encoder(encoder)?;
        Ok(out)
    })();
    match scaled {
        Ok(out) => {
            let stem = name.rsplit_once('.').map_or(name.as_str(), |(s, _)| s);
            (format!("{stem}.jpg"), out)
        }
        Err(e) => {
            eprintln!("phone share: couldn't scale {name}: {e}");
            (name, data)
        }
    }
}

async fn shortcut() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"Send to assistant.shortcut\"",
            ),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        SHORTCUT,
    )
        .into_response()
}

async fn manifest() -> Response {
    let body = serde_json::json!({
        "name": "OpenDrop: Send to assistant",
        "short_name": "Send to assistant",
        "id": "/phone/",
        "start_url": "/phone/",
        "scope": "/phone/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#2563eb",
        "icons": [
            {"src": "/phone/icon-256.png", "sizes": "256x256", "type": "image/png"},
            {"src": "/phone/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ],
        "share_target": {
            "action": "/phone/share",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
                "title": "title",
                "text": "text",
                "files": [{"name": "file", "accept": ["image/*", "video/*", "application/pdf", "text/*"]}]
            }
        }
    });
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        body.to_string(),
    )
        .into_response()
}

/// Passes shares through as a same-origin request, so the sign-in cookie
/// goes with them however the browser treats the share navigation.
const SERVICE_WORKER: &str = r#"self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method === 'POST' && url.pathname === '/phone/share' && e.request.mode === 'navigate') {
    e.respondWith((async () => {
      const form = await e.request.formData();
      return fetch('/phone/share', { method: 'POST', body: form, credentials: 'same-origin' });
    })());
  }
});
"#;

async fn service_worker() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        SERVICE_WORKER,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise_png(w: u32, h: u32) -> Vec<u8> {
        let mut seed = 0x2545_f491_u32;
        let img = image::RgbImage::from_fn(w, h, |_, _| {
            let mut px = [0u8; 3];
            for c in &mut px {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *c = seed as u8;
            }
            image::Rgb(px)
        });
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn big_photos_are_scaled_down_to_a_jpeg_an_assistant_can_read() {
        let big = noise_png(3000, 1000);
        assert!(big.len() > SCALE_ABOVE, "{} bytes", big.len());
        let (name, out) = fit_for_assistant("IMG_1.png".into(), big);
        assert_eq!(name, "IMG_1.jpg");
        assert!(out.len() <= SCALE_ABOVE, "{} bytes", out.len());
        let img = image::load_from_memory(&out).unwrap();
        assert_eq!((img.width(), img.height()), (2048, 683));
    }

    #[test]
    fn small_photos_and_other_files_are_kept_as_they_are() {
        let small = noise_png(100, 100);
        assert_eq!(
            fit_for_assistant("a.png".into(), small.clone()),
            ("a.png".into(), small)
        );
        let big_text = vec![b'a'; SCALE_ABOVE + 1];
        assert_eq!(
            fit_for_assistant("a.txt".into(), big_text.clone()),
            ("a.txt".into(), big_text)
        );
        let broken = vec![0u8; SCALE_ABOVE + 1];
        assert_eq!(
            fit_for_assistant("broken.jpg".into(), broken.clone()),
            ("broken.jpg".into(), broken)
        );
    }
}
