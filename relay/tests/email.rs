//! Sign-in links go out through Resend when a key is set: the request has
//! the key, the address and the link, and a failure still logs the link.

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::post;
use opendrop_relay::Mailer;
use opendrop_relay::email::{DEFAULT_FROM, ResendMailer};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

async fn fake_resend(status: u16) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let app = Router::new().route(
        "/emails",
        post({
            let seen = Arc::clone(&seen);
            move |headers: HeaderMap, body: String| async move {
                let auth = headers["authorization"].to_str().unwrap().to_owned();
                seen.lock()
                    .unwrap()
                    .push((auth, serde_json::from_str(&body).unwrap()));
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    r#"{"id":"test"}"#,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/emails", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, seen)
}

async fn wait_for(seen: &Seen) -> (String, Value) {
    for _ in 0..300 {
        if let Some(first) = seen.lock().unwrap().first().cloned() {
            return first;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no email was sent");
}

#[tokio::test]
async fn a_sign_in_link_is_emailed_through_resend() {
    let (url, seen) = fake_resend(200).await;
    let mailer = ResendMailer::with_endpoint("re_test_key", DEFAULT_FROM, url);
    let link = "https://relay.example.com/oauth/approve?token=abc123";
    mailer.send_login_link("aj@example.com", link);
    let (auth, body) = wait_for(&seen).await;
    assert_eq!(auth, "Bearer re_test_key");
    assert_eq!(body["to"], serde_json::json!(["aj@example.com"]));
    assert_eq!(body["from"], DEFAULT_FROM);
    assert_eq!(body["subject"], "Your OpenDrop sign-in link");
    assert!(body["text"].as_str().unwrap().contains(link));
    assert!(body["html"].as_str().unwrap().contains(link));
}

#[tokio::test]
async fn a_refused_email_does_not_panic() {
    // Resend refusing (e.g. an address the shared sender can't reach) is
    // logged with the link; the relay carries on.
    let (url, seen) = fake_resend(403).await;
    let mailer = ResendMailer::with_endpoint("re_test_key", DEFAULT_FROM, url);
    mailer.send_login_link("someone@example.com", "https://relay.example.com/x");
    wait_for(&seen).await;
}
