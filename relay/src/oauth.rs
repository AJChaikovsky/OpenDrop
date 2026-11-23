//! OAuth 2.1 for the hosted MCP server (stage B3), so claude.ai connectors
//! and ChatGPT apps can connect on their own.
//!
//! - Discovery: protected resource metadata (RFC 9728) for `/mcp` and
//!   authorization server metadata (RFC 8414), both at `/.well-known/`.
//! - Clients register themselves (dynamic client registration, RFC 7591) as
//!   public clients; every authorization needs PKCE with S256.
//! - Signing in: the consent page asks for the account's email and sends a
//!   one-time link (the same kind `opendrop relay login` uses). Opening it
//!   shows what the assistant will get, and "Allow" sends the browser back
//!   to the assistant with a code. Opening the link proves the address, so
//!   an assistant can be connected before any device is.
//! - Tokens are opaque and stored hashed. Access tokens last an hour and are
//!   bound to the `/mcp` resource; refresh tokens last 30 days and rotate on
//!   every use, and replaying an old one revokes the whole chain.
//! - Every redirect carries `iss` (RFC 9207).

use crate::Relay;
use crate::store::OAuthToken;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// The one scope: read and delete files in the account's assistant inbox.
pub const SCOPE: &str = "inbox";
pub const ACCESS_TTL_MS: u64 = 60 * 60 * 1000;
pub const REFRESH_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

pub fn router() -> Router<Arc<Relay>> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize_page).post(authorize_send))
        .route("/oauth/approve", get(approve_page).post(approve))
        .route("/oauth/token", post(token))
}

impl Relay {
    fn issuer(&self) -> &str {
        &self.config.public_url
    }

    /// The MCP server's address, which is also the OAuth resource.
    pub(crate) fn mcp_resource(&self) -> String {
        format!("{}/mcp", self.config.public_url)
    }

    fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.config.public_url
        )
    }

    /// The account a bearer token gives access to: an unexpired, unrevoked
    /// OAuth access token for `/mcp`, or a `relay token` one.
    ///
    /// Also who is asking: the OAuth client (claude.ai, ChatGPT...) or the
    /// token, which standing access on devices is given to.
    pub(crate) fn bearer_account(
        &self,
        token: &str,
    ) -> Result<Option<(i64, opendrop::relay::proto::Requester)>, String> {
        use opendrop::relay::proto::{Requester, RequesterKind};
        if let Some(t) = self.store.oauth_token(token)? {
            let ok = t.kind == "access"
                && !t.revoked
                && t.expires_ms > self.now()
                && t.resource == self.mcp_resource();
            if !ok {
                return Ok(None);
            }
            let name = self
                .store
                .oauth_client(&t.client_id)?
                .map(|(name, _)| name)
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "AI assistant".to_owned());
            return Ok(Some((
                t.account_id,
                Requester {
                    kind: RequesterKind::Assistant,
                    id: format!("oauth:{}", t.client_id),
                    name,
                },
            )));
        }
        Ok(self.store.token_info(token)?.map(|(account, label)| {
            let id: String = crate::store::hash(token)[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            (
                account,
                Requester {
                    kind: RequesterKind::Assistant,
                    id: format!("token:{id}"),
                    name: if label.trim().is_empty() {
                        "AI assistant (token)".to_owned()
                    } else {
                        label
                    },
                },
            )
        }))
    }

    /// The `401` that tells a client where to start OAuth.
    pub(crate) fn unauthorized(&self, token_given: bool) -> Response {
        let mut challenge = format!(
            "Bearer resource_metadata=\"{}\", scope=\"{SCOPE}\"",
            self.resource_metadata_url()
        );
        if token_given {
            challenge.push_str(", error=\"invalid_token\"");
        }
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, challenge)],
            "sign in with OAuth, or use a token from `opendrop relay token`",
        )
            .into_response()
    }
}

async fn resource_metadata(State(relay): State<Arc<Relay>>) -> Response {
    axum::Json(json!({
        "resource": relay.mcp_resource(),
        "authorization_servers": [relay.issuer()],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "OpenDrop inbox",
    }))
    .into_response()
}

async fn server_metadata(State(relay): State<Arc<Relay>>) -> Response {
    let base = relay.issuer();
    axum::Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "scopes_supported": [SCOPE],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// Redirect URIs a client may register: HTTPS anywhere, or HTTP only to
/// this machine (native apps such as Claude Code use a loopback port).
fn allowed_redirect(uri: &str) -> bool {
    if uri.contains('#') || uri.len() > 2000 {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    loopback_parts(uri).is_some()
}

/// `(host, path)` of an `http://` loopback URI, ignoring the port.
fn loopback_parts(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once(']')?.0
    } else {
        authority.split(':').next()?
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1").then_some((host, path))
}

/// Does `given` match one the client registered? Exactly, or for loopback
/// URIs, with any port (RFC 8252 section 7.3).
fn redirect_matches(registered: &[String], given: &str) -> bool {
    registered.iter().any(|r| {
        r == given
            || matches!((loopback_parts(r), loopback_parts(given)), (Some(a), Some(b)) if a == b)
    })
}

async fn register(State(relay): State<Arc<Relay>>, body: axum::body::Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "the body must be JSON",
        );
    };
    let uris: Vec<String> = request["redirect_uris"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if uris.is_empty() || uris.len() > 10 || !uris.iter().all(|u| allowed_redirect(u)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must be HTTPS, or HTTP to a loopback address",
        );
    }
    let name: String = request["client_name"]
        .as_str()
        .unwrap_or("An app")
        .chars()
        .take(100)
        .collect();
    let client_id = format!("odc_{}", crate::random_token());
    let now = relay.now();
    if let Err(e) = relay.store.add_oauth_client(&client_id, &name, &uris, now) {
        eprintln!("oauth register: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "try again",
        );
    }
    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({
            "client_id": client_id,
            "client_id_issued_at": now / 1000,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": SCOPE,
        })),
    )
        .into_response()
}

/// What an authorization grants, from the consent page to the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Grant {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    code_challenge: String,
    state: Option<String>,
    scope: String,
    resource: String,
}

#[derive(Debug, Default, Deserialize)]
struct AuthorizeParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    /// Only on the form post.
    email: Option<String>,
}

/// Percent-encode for a query string.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(crate) fn page(title: &str, body: &str) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
        ],
        Html(format!(
            "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>\
             <title>OpenDrop</title><body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5'>\
             <h1>{}</h1>{body}",
            esc(title)
        )),
    )
        .into_response()
}

fn host_of(uri: &str) -> &str {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    rest.split(['/', '?']).next().unwrap_or(rest)
}

/// Send the browser back to the client.
fn back_to_client(
    relay: &Relay,
    redirect_uri: &str,
    state: Option<&str>,
    params: &[(&str, &str)],
) -> Response {
    let mut url = redirect_uri.to_owned();
    url.push(if url.contains('?') { '&' } else { '?' });
    let mut parts: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    if let Some(state) = state {
        parts.push(format!("state={}", enc(state)));
    }
    parts.push(format!("iss={}", enc(relay.issuer())));
    url.push_str(&parts.join("&"));
    Redirect::to(&url).into_response()
}

#[allow(clippy::result_large_err)] // the error is the response to send
/// Check an authorization request. `Err` is the response to give: an error
/// page while the redirect URI can't be trusted, a redirect after that.
fn check_authorize(relay: &Relay, p: &AuthorizeParams) -> Result<Grant, Response> {
    let client = match relay.store.oauth_client(&p.client_id) {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Err(page(
                "This app isn't registered",
                "<p>Remove the connector and add it again.</p>",
            ));
        }
        Err(e) => {
            eprintln!("oauth authorize: {e}");
            return Err(page(
                "Something went wrong",
                "<p>Try again in a moment.</p>",
            ));
        }
    };
    let (client_name, uris) = client;
    if !redirect_matches(&uris, &p.redirect_uri) {
        return Err(page(
            "This request can't be trusted",
            "<p>The app asked to send you to an address it didn't register.</p>",
        ));
    }
    let fail = |error: &str, description: &str| {
        Err(back_to_client(
            relay,
            &p.redirect_uri,
            p.state.as_deref(),
            &[("error", error), ("error_description", description)],
        ))
    };
    if p.response_type != "code" {
        return fail("unsupported_response_type", "only response_type=code");
    }
    if p.code_challenge_method != "S256"
        || p.code_challenge.len() < 43
        || p.code_challenge.len() > 128
    {
        return fail("invalid_request", "PKCE with S256 is required");
    }
    let resource = match p.resource.as_deref().map(|r| r.trim_end_matches('/')) {
        None => relay.mcp_resource(),
        Some(r) if r == relay.mcp_resource() => r.to_owned(),
        Some(_) => return fail("invalid_target", "the only resource is the /mcp server"),
    };
    if let Some(scope) = &p.scope
        && scope
            .split_whitespace()
            .any(|s| s != SCOPE && s != "offline_access")
    {
        return fail("invalid_scope", "the only scope is inbox");
    }
    Ok(Grant {
        client_id: p.client_id.clone(),
        client_name,
        redirect_uri: p.redirect_uri.clone(),
        code_challenge: p.code_challenge.clone(),
        state: p.state.clone(),
        scope: SCOPE.to_owned(),
        resource,
    })
}

fn hidden(name: &str, value: &str) -> String {
    format!("<input type=hidden name={name} value=\"{}\">", esc(value))
}

async fn authorize_page(
    State(relay): State<Arc<Relay>>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    let grant = match check_authorize(&relay, &p) {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let mut fields = String::new();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", &grant.client_id),
        ("redirect_uri", &grant.redirect_uri),
        ("code_challenge", &grant.code_challenge),
        ("code_challenge_method", "S256"),
        ("resource", &grant.resource),
        ("scope", SCOPE),
    ] {
        fields.push_str(&hidden(name, value));
    }
    if let Some(state) = &grant.state {
        fields.push_str(&hidden("state", state));
    }
    page(
        &format!("Connect {} to OpenDrop", grant.client_name),
        &format!(
            "<p><b>{name}</b> wants to read and delete the files you send to your assistant \
             from your devices. It can't see anything else on them.</p>\
             <p>Afterwards you'll go back to <b>{host}</b>.</p>\
             <form method=post action=/oauth/authorize>{fields}\
             <p><label>Your OpenDrop email<br><input name=email type=email required autocomplete=email \
             style='font-size:1rem;padding:.4rem;width:100%;box-sizing:border-box'></label></p>\
             <p><button style='font-size:1rem;padding:.5rem 1rem'>Email me a sign-in link</button></p></form>",
            name = esc(&grant.client_name),
            host = esc(host_of(&grant.redirect_uri)),
        ),
    )
}

async fn authorize_send(
    State(relay): State<Arc<Relay>>,
    Form(p): Form<AuthorizeParams>,
) -> Response {
    let grant = match check_authorize(&relay, &p) {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let email = p.email.unwrap_or_default().trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') || email.contains(char::is_whitespace) {
        return page(
            "That isn't an email address",
            "<p>Go back and try again.</p>",
        );
    }
    if !relay.login_allowed(&email) {
        return page(
            "Too many sign-in links",
            "<p>Wait 15 minutes and try again.</p>",
        );
    }
    let token = crate::random_token();
    let saved = serde_json::to_string(&grant)
        .map_err(|e| e.to_string())
        .and_then(|g| {
            relay
                .store
                .add_oauth_request(&token, &g, &email, relay.now())
        });
    if let Err(e) = saved {
        eprintln!("oauth authorize: {e}");
        return page("Something went wrong", "<p>Try again in a moment.</p>");
    }
    let link = format!("{}/oauth/approve?token={token}", relay.issuer());
    relay.mailer.send_login_link(&email, &link);
    page(
        "Check your email",
        &format!(
            "<p>We sent a sign-in link to <b>{}</b>. Open it in this browser to finish \
             connecting {}. It works for 15 minutes.</p>",
            esc(&email),
            esc(&grant.client_name)
        ),
    )
}

#[derive(Deserialize)]
struct ApproveQuery {
    token: String,
}

/// The emailed link. Showing the page changes nothing (link scanners open
/// links too); only pressing a button does.
async fn approve_page(State(relay): State<Arc<Relay>>, Query(q): Query<ApproveQuery>) -> Response {
    let expired = || {
        page(
            "This link doesn't work",
            "<p>It was already used or has expired. Start connecting again from your assistant.</p>",
        )
    };
    let (grant, email) = match relay.store.oauth_request(&q.token, relay.now()) {
        Ok(Some(found)) => found,
        Ok(None) => return expired(),
        Err(e) => {
            eprintln!("oauth approve: {e}");
            return page(
                "Something went wrong",
                "<p>Try the link again in a moment.</p>",
            );
        }
    };
    let Ok(grant) = serde_json::from_str::<Grant>(&grant) else {
        return expired();
    };
    let token = hidden("token", &q.token);
    page(
        &format!("Allow {}?", grant.client_name),
        &format!(
            "<p>Signed in as <b>{email}</b>.</p>\
             <p><b>{name}</b> will be able to read and delete files you send to your assistant \
             with OpenDrop, until you revoke it with <code>opendrop relay revoke-tokens</code>.</p>\
             <p>You'll go back to <b>{host}</b>.</p>\
             <form method=post action=/oauth/approve style='display:inline'>{token}{allow}\
             <button style='font-size:1rem;padding:.5rem 1rem'>Allow</button></form> \
             <form method=post action=/oauth/approve style='display:inline'>{token}{deny}\
             <button style='font-size:1rem;padding:.5rem 1rem'>Deny</button></form>",
            email = esc(&email),
            name = esc(&grant.client_name),
            host = esc(host_of(&grant.redirect_uri)),
            allow = hidden("decision", "allow"),
            deny = hidden("decision", "deny"),
        ),
    )
}

#[derive(Deserialize)]
struct ApproveForm {
    token: String,
    decision: String,
}

async fn approve(State(relay): State<Arc<Relay>>, Form(f): Form<ApproveForm>) -> Response {
    let now = relay.now();
    let (grant, account_id) = match relay.store.take_oauth_request(&f.token, now) {
        Ok(Some(found)) => found,
        Ok(None) => {
            return page(
                "This link doesn't work",
                "<p>It was already used or has expired. Start connecting again from your assistant.</p>",
            );
        }
        Err(e) => {
            eprintln!("oauth approve: {e}");
            return page("Something went wrong", "<p>Try again in a moment.</p>");
        }
    };
    let Ok(parsed) = serde_json::from_str::<Grant>(&grant) else {
        return page("Something went wrong", "<p>Start connecting again.</p>");
    };
    if f.decision != "allow" {
        return back_to_client(
            &relay,
            &parsed.redirect_uri,
            parsed.state.as_deref(),
            &[
                ("error", "access_denied"),
                ("error_description", "the user said no"),
            ],
        );
    }
    let code = crate::random_token();
    if let Err(e) = relay.store.add_oauth_code(&code, &grant, account_id, now) {
        eprintln!("oauth approve: {e}");
        return page("Something went wrong", "<p>Try again in a moment.</p>");
    }
    back_to_client(
        &relay,
        &parsed.redirect_uri,
        parsed.state.as_deref(),
        &[("code", &code)],
    )
}

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && B64URL.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

/// A client id from HTTP Basic auth, for clients that send it there.
fn basic_client_id(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let decoded = B64.decode(value.strip_prefix("Basic ")?.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let id = text.split(':').next()?;
    Some(id.to_owned())
}

/// Issue an access and a refresh token for one authorization chain.
fn issue(
    relay: &Relay,
    family: &str,
    account_id: i64,
    client_id: &str,
    resource: &str,
) -> Response {
    let now = relay.now();
    let access = format!("oda_{}", crate::random_token());
    let refresh = format!("odr_{}", crate::random_token());
    let make = |kind: &str, ttl: u64| OAuthToken {
        kind: kind.to_owned(),
        family: family.to_owned(),
        account_id,
        client_id: client_id.to_owned(),
        scope: SCOPE.to_owned(),
        resource: resource.to_owned(),
        expires_ms: now + ttl,
        revoked: false,
    };
    let saved = relay
        .store
        .add_oauth_token(&access, &make("access", ACCESS_TTL_MS))
        .and_then(|()| {
            relay
                .store
                .add_oauth_token(&refresh, &make("refresh", REFRESH_TTL_MS))
        });
    if let Err(e) = saved {
        eprintln!("oauth token: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "try again",
        );
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL_MS / 1000,
            "refresh_token": refresh,
            "scope": SCOPE,
        })),
    )
        .into_response()
}

async fn token(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
    let client_id = match form
        .get("client_id")
        .cloned()
        .or_else(|| basic_client_id(&headers))
    {
        Some(id) if !id.is_empty() => id,
        _ => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client_id is required",
            );
        }
    };
    match relay.store.oauth_client(&client_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
        }
        Err(e) => {
            eprintln!("oauth token: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "try again",
            );
        }
    }
    let now = relay.now();
    let bad_grant = |d: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", d);
    match get("grant_type") {
        "authorization_code" => {
            let (grant, account_id) = match relay.store.take_oauth_code(get("code"), now) {
                Ok(Some(found)) => found,
                Ok(None) => return bad_grant("the code is wrong, used or expired"),
                Err(e) => {
                    eprintln!("oauth token: {e}");
                    return oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "try again",
                    );
                }
            };
            let Ok(grant) = serde_json::from_str::<Grant>(&grant) else {
                return bad_grant("the code is wrong");
            };
            if grant.client_id != client_id {
                return bad_grant("the code belongs to another client");
            }
            if grant.redirect_uri != get("redirect_uri") {
                return bad_grant("redirect_uri doesn't match the authorization");
            }
            if !pkce_ok(get("code_verifier"), &grant.code_challenge) {
                return bad_grant("code_verifier doesn't match the code_challenge");
            }
            if let Some(resource) = form.get("resource")
                && resource.trim_end_matches('/') != grant.resource
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    "resource doesn't match the authorization",
                );
            }
            let family = crate::random_token();
            issue(&relay, &family, account_id, &client_id, &grant.resource)
        }
        "refresh_token" => {
            let presented = get("refresh_token");
            let old = match relay.store.oauth_token(presented) {
                Ok(Some(t)) if t.kind == "refresh" => t,
                Ok(_) => return bad_grant("unknown refresh token"),
                Err(e) => {
                    eprintln!("oauth token: {e}");
                    return oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "try again",
                    );
                }
            };
            if old.client_id != client_id {
                return bad_grant("the refresh token belongs to another client");
            }
            if old.revoked {
                // A rotated-out token came back: it leaked. End the chain.
                let _ = relay.store.revoke_oauth_family(&old.family);
                return bad_grant("the refresh token was already used or revoked");
            }
            if old.expires_ms <= now {
                return bad_grant("the refresh token expired");
            }
            if let Err(e) = relay.store.revoke_oauth_token(presented) {
                eprintln!("oauth token: {e}");
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "try again",
                );
            }
            issue(
                &relay,
                &old.family,
                old.account_id,
                &client_id,
                &old.resource,
            )
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris() {
        assert!(allowed_redirect("https://claude.ai/api/mcp/auth_callback"));
        assert!(allowed_redirect("http://localhost:3118/callback"));
        assert!(allowed_redirect("http://127.0.0.1/callback"));
        assert!(!allowed_redirect("http://evil.example/callback"));
        assert!(!allowed_redirect("http://localhost.evil.example/cb"));
        assert!(!allowed_redirect("https://claude.ai/cb#frag"));
        assert!(!allowed_redirect("javascript:alert(1)"));

        let registered = vec![
            "https://claude.ai/api/mcp/auth_callback".to_owned(),
            "http://localhost/callback".to_owned(),
        ];
        assert!(redirect_matches(
            &registered,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(redirect_matches(
            &registered,
            "http://localhost:51234/callback"
        ));
        assert!(!redirect_matches(
            &registered,
            "http://localhost:51234/other"
        ));
        assert!(!redirect_matches(
            &registered,
            "https://claude.ai/api/mcp/auth_callback/x"
        ));
    }

    #[test]
    fn pkce_s256() {
        // RFC 7636 appendix B.
        assert!(pkce_ok(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_ok(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "nope"
        ));
        assert!(!pkce_ok(
            "short",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}
