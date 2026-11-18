//! OAuth 2.1 for the hosted MCP server (stage B3), so claude.ai custom
//! connectors and ChatGPT apps can connect on their own.
//!
//! What the MCP authorization spec and both platforms need:
//! - protected resource metadata (RFC 9728) at
//!   `/.well-known/oauth-protected-resource[/mcp]`, pointed to by the `401`
//!   from `/mcp`;
//! - authorization server metadata (RFC 8414) at
//!   `/.well-known/oauth-authorization-server`;
//! - dynamic client registration (RFC 7591) at `/oauth/register`;
//! - the authorization code flow with PKCE (S256 only), the `resource`
//!   indicator (RFC 8707) and the `iss` response parameter (RFC 9207);
//! - opaque access tokens (1 hour) and rotating refresh tokens (30 days).
//!
//! How a person approves: the relay has no email provider yet, so the
//! browser page shows a short code and the person types it on one of their
//! signed-in devices (`opendrop relay approve <code>`). The device decides
//! which account the app gets, and shows the app's name, where the browser
//! goes back to and the scopes before asking. Only the browser that started
//! the sign-in (holding its unguessable request id) can turn the approval
//! into a code, and only the app holding the PKCE verifier can turn the
//! code into tokens.

use crate::Relay;
use crate::store::{AuthRequest, CodeGrant, Grant, OAuthClient};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const SCOPE_INBOX_READ: &str = "inbox:read";
pub const SCOPE_INBOX_WRITE: &str = "inbox:write";
pub const SCOPE_DEVICES_READ: &str = "devices:read";
pub const SCOPE_DEVICES_REQUEST: &str = "devices:request";
/// Every scope there is (devices ones are for stage B4's tools).
pub const ALL_SCOPES: [&str; 4] = [
    SCOPE_INBOX_READ,
    SCOPE_INBOX_WRITE,
    SCOPE_DEVICES_READ,
    SCOPE_DEVICES_REQUEST,
];
/// What an app gets when it asks for no scope in particular, and what the
/// `401` from `/mcp` asks for.
pub const DEFAULT_SCOPE: &str = "inbox:read inbox:write";

/// How long the browser page waits for someone to approve its code.
pub const REQUEST_TTL_MS: u64 = 10 * 60 * 1000;
pub const CODE_TTL_MS: u64 = 60 * 1000;
pub const ACCESS_TTL_MS: u64 = 60 * 60 * 1000;
pub const REFRESH_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Letters for user codes: no vowels (no words), no 0/O/1/I look-alikes.
const CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";

impl Relay {
    /// The issuer: the relay's public URL.
    pub fn issuer(&self) -> &str {
        &self.config.public_url
    }

    /// The MCP server's canonical URL, the `resource` tokens are bound to.
    pub fn mcp_resource(&self) -> String {
        format!("{}/mcp", self.config.public_url)
    }

    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/mcp",
            self.config.public_url
        )
    }

    /// Whether `resource` (from a client) names this relay's MCP server.
    fn is_our_resource(&self, resource: &str) -> bool {
        resource
            .trim_end_matches('/')
            .eq_ignore_ascii_case(&self.mcp_resource())
    }

    /// Delete expired OAuth codes, tokens and abandoned sign-ins.
    pub fn expire_oauth(&self) {
        let now = self.now();
        if let Err(e) = self
            .store
            .expire_oauth(now, now.saturating_sub(REQUEST_TTL_MS))
        {
            eprintln!("oauth cleanup: {e}");
        }
    }

    /// The pending sign-in with this user code (any spelling: case, dashes
    /// and spaces don't matter).
    pub fn pending_authorization(&self, user_code: &str) -> Result<Option<AuthRequest>, String> {
        let not_before = self.now().saturating_sub(REQUEST_TTL_MS);
        self.store
            .pending_auth_request(&normalize_code(user_code), not_before)
    }

    /// A device's answer to a sign-in; false when the code isn't pending.
    pub fn decide_authorization(
        &self,
        user_code: &str,
        account_id: i64,
        allow: bool,
    ) -> Result<bool, String> {
        let not_before = self.now().saturating_sub(REQUEST_TTL_MS);
        self.store
            .decide_auth_request(&normalize_code(user_code), not_before, account_id, allow)
    }
}

pub fn router() -> Router<Arc<Relay>> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/authorize/status", get(status))
        .route("/oauth/authorize/continue", get(continue_sign_in))
        .route("/oauth/authorize/cancel", get(cancel))
        .route("/oauth/token", post(token))
}

/// `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728).
async fn protected_resource(State(relay): State<Arc<Relay>>) -> Response {
    cors_json(json!({
        "resource": relay.mcp_resource(),
        "authorization_servers": [relay.issuer()],
        "scopes_supported": ALL_SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_name": "OpenDrop assistant inbox",
    }))
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
async fn authorization_server(State(relay): State<Arc<Relay>>) -> Response {
    let base = relay.issuer();
    cors_json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "scopes_supported": ALL_SCOPES,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

fn cors_json(value: serde_json::Value) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// An OAuth error body (RFC 6749 section 5.2).
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"opendrop\""),
        );
    }
    response
}

fn internal(e: impl std::fmt::Display) -> Response {
    eprintln!("oauth: {e}");
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "something went wrong; try again",
    )
}

fn random_secret() -> String {
    B64URL.encode(opendrop::identity::random_bytes())
}

fn user_code() -> String {
    let bytes = opendrop::identity::random_bytes();
    let letters: String = bytes[..8]
        .iter()
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &letters[..4], &letters[4..])
}

/// `abcd 2345`, `ABCD2345` and `ABCD-2345` are the same code.
pub fn normalize_code(code: &str) -> String {
    let letters: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if letters.len() == 8 {
        format!("{}-{}", &letters[..4], &letters[4..])
    } else {
        letters
    }
}

/// Redirect URIs must be HTTPS, or HTTP on the loopback address (native
/// apps such as Claude Code), with no fragment.
fn valid_redirect_uri(uri: &str) -> bool {
    if uri.len() > 2000 || uri.contains('#') || uri.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    loopback_parts(uri).is_some()
}

/// For `http://localhost:1234/cb` or `http://127.0.0.1/cb`: the host and the
/// path (the port doesn't matter, RFC 8252 section 7.3).
fn loopback_parts(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host = match authority.strip_prefix("[::1]") {
        Some(port) if port.is_empty() || port.starts_with(':') => "[::1]",
        Some(_) => return None,
        None => authority.split(':').next().unwrap_or(authority),
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]").then_some((host, path))
}

/// Whether `uri` from an authorization request is one the client registered:
/// exactly, or a loopback one on any port.
fn redirect_matches(registered: &[String], uri: &str) -> bool {
    registered.iter().any(|r| {
        r == uri
            || matches!(
                (loopback_parts(r), loopback_parts(uri)),
                (Some(a), Some(b)) if a == b
            )
    })
}

fn redirect_host(uri: &str) -> String {
    let rest = uri.split("://").nth(1).unwrap_or(uri);
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    authority.rsplit('@').next().unwrap_or(authority).to_owned()
}

#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

/// `POST /oauth/register` (RFC 7591).
async fn register(State(relay): State<Arc<Relay>>, body: axum::body::Bytes) -> Response {
    let Ok(reg) = serde_json::from_slice::<Registration>(&body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "the body must be JSON client metadata",
        );
    };
    if reg.redirect_uris.is_empty() || reg.redirect_uris.len() > 10 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "give between 1 and 10 redirect_uris",
        );
    }
    if let Some(bad) = reg.redirect_uris.iter().find(|u| !valid_redirect_uri(u)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!("redirect URIs must use https:// (or http:// on localhost): {bad}"),
        );
    }
    let method = reg
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_owned());
    let secret = match method.as_str() {
        "none" => None,
        "client_secret_post" | "client_secret_basic" => Some(random_secret()),
        other => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                &format!("unsupported token_endpoint_auth_method {other}"),
            );
        }
    };
    let name: String = reg
        .client_name
        .as_deref()
        .map(|n| n.chars().filter(|c| !c.is_control()).take(80).collect())
        .filter(|n: &String| !n.trim().is_empty())
        .unwrap_or_else(|| "An assistant app".to_owned());
    let client = OAuthClient {
        client_id: format!("odc_{}", &random_secret()[..24]),
        name,
        redirect_uris: reg.redirect_uris,
        secret_hash: secret.as_deref().map(crate::store::hash),
    };
    if let Err(e) = relay.store.add_oauth_client(&client) {
        return internal(e);
    }
    let mut body = json!({
        "client_id": client.client_id,
        "client_id_issued_at": relay.now() / 1000,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": method,
    });
    if let Some(secret) = secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A page from the relay: never framed, cached or leaking its URL (which
/// holds the request id) to other sites.
fn page(title: &str, body: &str) -> Response {
    let mut response = Html(format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>\
         <title>OpenDrop</title>\
         <body style='font-family:system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5'>\
         <h1 style='font-size:1.5rem'>{}</h1>{body}",
        escape(title)
    ))
    .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("frame-ancestors 'none'; default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

fn error_page(message: &str) -> Response {
    let mut response = page(
        "This sign-in can't continue",
        &format!("<p>{}</p>", escape(message)),
    );
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// Append query parameters to `uri` (which may already have some).
fn with_query(uri: &str, params: &[(&str, &str)]) -> String {
    let mut out = uri.to_owned();
    for (i, (k, v)) in params.iter().enumerate() {
        out.push(if i == 0 && !uri.contains('?') {
            '?'
        } else {
            '&'
        });
        out.push_str(k);
        out.push('=');
        out.push_str(&urlencode(v));
    }
    out
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Send the browser back to the app with an error (once the redirect URI is
/// known to be the client's own).
fn redirect_error(
    relay: &Relay,
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    params.push(("iss", relay.issuer()));
    Redirect::to(&with_query(redirect_uri, &params)).into_response()
}

/// Turn the requested scopes into the granted ones.
fn granted_scope(requested: Option<&str>) -> Result<String, String> {
    let requested: Vec<&str> = requested.unwrap_or("").split_whitespace().collect();
    if requested.is_empty() {
        return Ok(DEFAULT_SCOPE.to_owned());
    }
    let mut granted: Vec<&str> = Vec::new();
    for scope in requested {
        if ALL_SCOPES.contains(&scope) {
            if !granted.contains(&scope) {
                granted.push(scope);
            }
        } else if !matches!(scope, "offline_access" | "openid" | "profile" | "email") {
            // Standard extras are ignored; anything else is a mistake.
            return Err(format!("unknown scope {scope}"));
        }
    }
    if granted.is_empty() {
        return Ok(DEFAULT_SCOPE.to_owned());
    }
    Ok(granted.join(" "))
}

/// What each scope lets an app do, for the device prompt and the page.
pub fn describe_scope(scope: &str) -> &'static str {
    match scope {
        SCOPE_INBOX_READ => "read (and so remove) files you send to your assistant",
        SCOPE_INBOX_WRITE => "delete files from your assistant inbox",
        SCOPE_DEVICES_READ => "see your devices and what they share",
        SCOPE_DEVICES_REQUEST => "ask your devices for files (you approve each one)",
        _ => "something unknown",
    }
}

/// `GET /oauth/authorize`: check the request and show the code to approve.
async fn authorize(State(relay): State<Arc<Relay>>, Query(q): Query<AuthorizeQuery>) -> Response {
    let Some(client_id) = q.client_id.as_deref() else {
        return error_page("The app didn't say who it is (no client_id).");
    };
    let client = match relay.store.oauth_client(client_id) {
        Ok(Some(client)) => client,
        Ok(None) => {
            return error_page(
                "This app isn't registered with this relay. Remove the connector and add it again.",
            );
        }
        Err(e) => return internal(e),
    };
    let redirect_uri = match q.redirect_uri.as_deref() {
        Some(uri) if redirect_matches(&client.redirect_uris, uri) => uri.to_owned(),
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        _ => return error_page("The app asked to return to an address it didn't register."),
    };
    let state = q.state.as_deref();
    if q.response_type.as_deref() != Some("code") {
        return redirect_error(
            &relay,
            &redirect_uri,
            state,
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let challenge = match (
        q.code_challenge.as_deref(),
        q.code_challenge_method.as_deref(),
    ) {
        (Some(c), Some("S256")) if (43..=128).contains(&c.len()) => c.to_owned(),
        _ => {
            return redirect_error(
                &relay,
                &redirect_uri,
                state,
                "invalid_request",
                "PKCE with code_challenge_method=S256 is required",
            );
        }
    };
    if let Some(resource) = q.resource.as_deref()
        && !relay.is_our_resource(resource)
    {
        return redirect_error(
            &relay,
            &redirect_uri,
            state,
            "invalid_target",
            "this relay only issues tokens for its own /mcp",
        );
    }
    let scope = match granted_scope(q.scope.as_deref()) {
        Ok(scope) => scope,
        Err(e) => return redirect_error(&relay, &redirect_uri, state, "invalid_scope", &e),
    };
    let request_id = random_secret();
    let code = user_code();
    let request = AuthRequest {
        client_id: client.client_id.clone(),
        client_name: client.name.clone(),
        redirect_uri: redirect_uri.clone(),
        state: q.state.clone(),
        code_challenge: challenge,
        scope: scope.clone(),
        resource: relay.mcp_resource(),
        created_ms: relay.now(),
        allowed: None,
        account_id: None,
    };
    if let Err(e) = relay.store.add_auth_request(&request_id, &code, &request) {
        return internal(e);
    }
    waiting_page(&request_id, &code, &request)
}

fn waiting_page(request_id: &str, code: &str, request: &AuthRequest) -> Response {
    let scopes: String = request
        .scope
        .split_whitespace()
        .map(|s| format!("<li>{}</li>", escape(describe_scope(s))))
        .collect();
    let host = redirect_host(&request.redirect_uri);
    let loopback_warning = if loopback_parts(&request.redirect_uri).is_some() {
        "<p><b>Careful:</b> this app returns to a program on this computer. Only approve if you just \
         started connecting a program you trust.</p>"
    } else {
        ""
    };
    let id = urlencode(request_id);
    page(
        "Connect to your OpenDrop inbox",
        &format!(
            "<p><b>{name}</b> (returning to <b>{host}</b>) wants to:</p><ul>{scopes}</ul>{loopback_warning}\
             <p>To allow it, run this on one of your devices signed in to OpenDrop:</p>\
             <pre style='font-size:1.4rem;background:#8882;padding:.75rem 1rem;border-radius:.5rem'>opendrop relay approve {code}</pre>\
             <p>This page continues on its own once you approve. The code works for 10 minutes.</p>\
             <p><a href='/oauth/authorize/continue?request={id}'>Continue</a> · \
             <a href='/oauth/authorize/cancel?request={id}'>Cancel</a></p>\
             <script>\
             (function poll(){{fetch('/oauth/authorize/status?request={id}').then(function(r){{return r.json()}})\
             .then(function(s){{if(s.status==='pending'){{setTimeout(poll,2000)}}else{{location.href='/oauth/authorize/continue?request={id}'}}}})\
             .catch(function(){{setTimeout(poll,5000)}})}})();\
             </script>",
            name = escape(&request.client_name),
            host = escape(&host),
            code = escape(code),
        ),
    )
}

#[derive(Deserialize)]
struct RequestQuery {
    request: String,
}

fn request_state(relay: &Relay, request: &AuthRequest) -> &'static str {
    if request.created_ms + REQUEST_TTL_MS <= relay.now() {
        return "expired";
    }
    match request.allowed {
        None => "pending",
        Some(true) => "approved",
        Some(false) => "denied",
    }
}

/// `GET /oauth/authorize/status?request=…`: the page's poll.
async fn status(State(relay): State<Arc<Relay>>, Query(q): Query<RequestQuery>) -> Response {
    let state = match relay.store.auth_request(&q.request) {
        Ok(Some(request)) => request_state(&relay, &request),
        Ok(None) => "gone",
        Err(e) => return internal(e),
    };
    let mut response = Json(json!({ "status": state })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /oauth/authorize/continue?request=…`: once approved, send the
/// browser back to the app with a code (exactly once).
async fn continue_sign_in(
    State(relay): State<Arc<Relay>>,
    Query(q): Query<RequestQuery>,
) -> Response {
    let request = match relay.store.auth_request(&q.request) {
        Ok(Some(request)) => request,
        Ok(None) => {
            return error_page(
                "This sign-in already finished or expired. Start connecting again from the app.",
            );
        }
        Err(e) => return internal(e),
    };
    let state = request.state.as_deref();
    match request_state(&relay, &request) {
        "pending" => {
            // Reload the waiting page (the code doesn't change).
            let code = match relay.store.user_code(&q.request) {
                Ok(Some(code)) => code,
                Ok(None) => return error_page("This sign-in already finished."),
                Err(e) => return internal(e),
            };
            waiting_page(&q.request, &code, &request)
        }
        "expired" => {
            let _ = relay.store.remove_auth_request(&q.request);
            redirect_error(
                &relay,
                &request.redirect_uri,
                state,
                "access_denied",
                "nobody approved the code in time",
            )
        }
        "denied" => {
            let _ = relay.store.remove_auth_request(&q.request);
            redirect_error(
                &relay,
                &request.redirect_uri,
                state,
                "access_denied",
                "the request was denied on your device",
            )
        }
        _ => {
            match relay.store.remove_auth_request(&q.request) {
                Ok(true) => {}
                Ok(false) => return error_page("This sign-in already finished."),
                Err(e) => return internal(e),
            }
            let Some(account_id) = request.account_id else {
                return internal("approved request without an account");
            };
            let code = random_secret();
            let grant = CodeGrant {
                grant: Grant {
                    client_id: request.client_id.clone(),
                    account_id,
                    scope: request.scope.clone(),
                    resource: request.resource.clone(),
                },
                redirect_uri: request.redirect_uri.clone(),
                code_challenge: request.code_challenge.clone(),
            };
            if let Err(e) = relay
                .store
                .add_code(&code, &grant, relay.now() + CODE_TTL_MS)
            {
                return internal(e);
            }
            let mut params = vec![("code", code.as_str())];
            if let Some(state) = state {
                params.push(("state", state));
            }
            params.push(("iss", relay.issuer()));
            Redirect::to(&with_query(&request.redirect_uri, &params)).into_response()
        }
    }
}

/// `GET /oauth/authorize/cancel?request=…`.
async fn cancel(State(relay): State<Arc<Relay>>, Query(q): Query<RequestQuery>) -> Response {
    match relay.store.auth_request(&q.request) {
        Ok(Some(request)) => {
            let _ = relay.store.remove_auth_request(&q.request);
            redirect_error(
                &relay,
                &request.redirect_uri,
                request.state.as_deref(),
                "access_denied",
                "cancelled",
            )
        }
        Ok(None) => error_page("This sign-in already finished or expired."),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    resource: Option<String>,
}

/// The client a token request comes from, authenticated the way it
/// registered (public clients just name themselves; PKCE protects them).
#[allow(clippy::result_large_err)] // only built on the token endpoint's error path
fn authenticate_client(
    relay: &Relay,
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<OAuthClient, Response> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| B64.decode(b.trim()).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| {
            let (id, secret) = s.split_once(':')?;
            // RFC 6749 section 2.3.1: both parts are form-urlencoded.
            Some((urldecode(id), urldecode(secret)))
        });
    let (client_id, secret) = match (&basic, &form.client_id) {
        (Some((id, secret)), _) => (id.clone(), Some(secret.clone())),
        (None, Some(id)) => (id.clone(), form.client_secret.clone()),
        (None, None) => {
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "no client_id",
            ));
        }
    };
    let client = match relay.store.oauth_client(&client_id) {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client; register again",
            ));
        }
        Err(e) => return Err(internal(e)),
    };
    if let Some(expected) = &client.secret_hash {
        let given = secret.as_deref().map(crate::store::hash);
        if given.as_ref() != Some(expected) {
            return Err(oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "wrong client secret",
            ));
        }
    }
    Ok(client)
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or(())
                {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let valid = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    valid && B64URL.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

/// `POST /oauth/token`: exchange a code, or rotate a refresh token.
async fn token(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let client = match authenticate_client(&relay, &headers, &form) {
        Ok(client) => client,
        Err(response) => return response,
    };
    let now = relay.now();
    if let Some(resource) = form.resource.as_deref()
        && !relay.is_our_resource(resource)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "this relay only issues tokens for its own /mcp",
        );
    }
    let grant = match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) =
                (form.code.as_deref(), form.code_verifier.as_deref())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required",
                );
            };
            let found = match relay.store.take_code(code, now) {
                Ok(found) => found,
                Err(e) => return internal(e),
            };
            let Some(found) = found else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "the code is wrong, used or expired",
                );
            };
            if found.grant.client_id != client.client_id {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "the code belongs to another client",
                );
            }
            if form
                .redirect_uri
                .as_deref()
                .is_some_and(|uri| uri != found.redirect_uri)
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "redirect_uri doesn't match",
                );
            }
            if !pkce_matches(verifier, &found.code_challenge) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "code_verifier doesn't match",
                );
            }
            found.grant
        }
        Some("refresh_token") => {
            let Some(refresh) = form.refresh_token.as_deref() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            let found = match relay.store.take_refresh_token(refresh, now) {
                Ok(found) => found,
                Err(e) => return internal(e),
            };
            match found {
                Some(grant) if grant.client_id == client.client_id => grant,
                _ => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "the refresh token is wrong, used, expired or revoked",
                    );
                }
            }
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "use authorization_code or refresh_token",
            );
        }
    };
    let access = random_secret();
    let refresh = random_secret();
    if let Err(e) = relay
        .store
        .add_oauth_token(&access, "access", &grant, now + ACCESS_TTL_MS)
        .and_then(|()| {
            relay
                .store
                .add_oauth_token(&refresh, "refresh", &grant, now + REFRESH_TTL_MS)
        })
    {
        return internal(e);
    }
    let mut response = Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_MS / 1000,
        "refresh_token": refresh,
        "scope": grant.scope,
    }))
    .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_ignore_case_dashes_and_spaces() {
        assert_eq!(normalize_code("bcdf 2345"), "BCDF-2345");
        assert_eq!(normalize_code("BCDF2345"), "BCDF-2345");
        let code = user_code();
        assert_eq!(normalize_code(&code), code);
        assert_eq!(code.len(), 9);
    }

    #[test]
    fn redirect_uris_are_https_or_loopback_and_loopback_ignores_the_port() {
        assert!(valid_redirect_uri(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(valid_redirect_uri("http://localhost/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:3118/callback"));
        assert!(!valid_redirect_uri("http://evil.example/callback"));
        assert!(!valid_redirect_uri("http://localhost.evil.example/cb"));
        assert!(!valid_redirect_uri("https://claude.ai/cb#frag"));
        assert!(!valid_redirect_uri("javascript:alert(1)"));
        let registered = vec!["http://localhost/callback".to_owned()];
        assert!(redirect_matches(
            &registered,
            "http://localhost:3118/callback"
        ));
        assert!(!redirect_matches(
            &registered,
            "http://localhost:3118/other"
        ));
        assert!(!redirect_matches(
            &registered,
            "http://127.0.0.1:3118/callback"
        ));
        let registered = vec!["https://claude.ai/api/mcp/auth_callback".to_owned()];
        assert!(!redirect_matches(
            &registered,
            "https://claude.ai/api/mcp/auth_callback/x"
        ));
    }

    #[test]
    fn scopes_default_to_the_inbox_and_unknown_ones_are_refused() {
        assert_eq!(granted_scope(None).unwrap(), DEFAULT_SCOPE);
        assert_eq!(
            granted_scope(Some("offline_access")).unwrap(),
            DEFAULT_SCOPE
        );
        assert_eq!(
            granted_scope(Some("inbox:read inbox:read")).unwrap(),
            "inbox:read"
        );
        assert!(granted_scope(Some("admin")).is_err());
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"
        ));
    }

    #[test]
    fn form_values_decode() {
        assert_eq!(urldecode("a%3Ab+c"), "a:b c");
        assert_eq!(urldecode("100%"), "100%");
    }
}
