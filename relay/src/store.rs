//! Accounts, sessions, sign-in links and the device registry, in SQLite.
//!
//! Secrets (sessions, sign-in tokens) are stored only as SHA-256 hashes, so a
//! copy of the database can't be used to sign in.

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, String>;

/// How long a sign-in link works.
pub const LOGIN_TTL_MS: u64 = 15 * 60 * 1000;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

pub struct Store {
    db: Mutex<Connection>,
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub account_id: i64,
    pub name: String,
    pub public_key: [u8; 32],
    pub last_seen_ms: u64,
}

/// What opening a sign-in link did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// The login is now verified; this is its id.
    Ok(String),
    Expired,
    Unknown,
}

fn err(e: rusqlite::Error) -> String {
    format!("database error: {e}")
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path).map_err(err)?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(err)?)
    }

    fn init(db: Connection) -> Result<Self> {
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS accounts (
                 id INTEGER PRIMARY KEY,
                 email TEXT NOT NULL UNIQUE,
                 created_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sessions (
                 token_hash BLOB PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 created_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS logins (
                 login_id TEXT PRIMARY KEY,
                 token_hash BLOB NOT NULL UNIQUE,
                 email TEXT NOT NULL,
                 verified INTEGER NOT NULL DEFAULT 0,
                 created_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS devices (
                 device_id TEXT PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 name TEXT NOT NULL,
                 public_key BLOB NOT NULL,
                 last_seen_ms INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS api_tokens (
                 token_hash BLOB PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 label TEXT NOT NULL,
                 created_ms INTEGER NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS inbox (
                 inbox_id TEXT PRIMARY KEY,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 name TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 mime TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 from_device TEXT NOT NULL,
                 sent_ms INTEGER NOT NULL,
                 expires_ms INTEGER NOT NULL,
                 file_key BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS oauth_clients (
                 client_id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 redirect_uris TEXT NOT NULL,
                 secret_hash BLOB,
                 created_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS oauth_requests (
                 request_hash BLOB PRIMARY KEY,
                 user_code TEXT NOT NULL UNIQUE,
                 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
                 redirect_uri TEXT NOT NULL,
                 state TEXT,
                 code_challenge TEXT NOT NULL,
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 created_ms INTEGER NOT NULL,
                 account_id INTEGER REFERENCES accounts(id),
                 allowed INTEGER
             );
             CREATE TABLE IF NOT EXISTS oauth_codes (
                 code_hash BLOB PRIMARY KEY,
                 client_id TEXT NOT NULL,
                 redirect_uri TEXT NOT NULL,
                 code_challenge TEXT NOT NULL,
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 expires_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS oauth_tokens (
                 token_hash BLOB PRIMARY KEY,
                 kind TEXT NOT NULL,
                 client_id TEXT NOT NULL,
                 account_id INTEGER NOT NULL REFERENCES accounts(id),
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 expires_ms INTEGER NOT NULL
             );",
        )
        .map_err(err)?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Record a pending sign-in for `email`; `token` goes in the emailed link.
    pub fn start_login(&self, login_id: &str, token: &str, email: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        // Old links are useless; drop them as we go.
        db.execute(
            "DELETE FROM logins WHERE created_ms < ?1",
            params![now_ms().saturating_sub(LOGIN_TTL_MS) as i64],
        )
        .map_err(err)?;
        db.execute(
            "INSERT INTO logins (login_id, token_hash, email, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![login_id, hash(token), email, now_ms() as i64],
        )
        .map_err(err)?;
        Ok(())
    }

    /// The link with `token` was opened.
    pub fn verify_login(&self, token: &str) -> Result<Verified> {
        let db = self.db.lock().unwrap();
        let row: Option<(String, i64)> = db
            .query_row(
                "SELECT login_id, created_ms FROM logins WHERE token_hash = ?1",
                params![hash(token)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        let Some((login_id, created)) = row else {
            return Ok(Verified::Unknown);
        };
        if now_ms().saturating_sub(created as u64) > LOGIN_TTL_MS {
            return Ok(Verified::Expired);
        }
        db.execute(
            "UPDATE logins SET verified = 1 WHERE login_id = ?1",
            params![login_id],
        )
        .map_err(err)?;
        Ok(Verified::Ok(login_id))
    }

    /// If the login was verified, use it up: create the account if needed
    /// and a session for it, returning `(email, account id)`.
    pub fn finish_login(&self, login_id: &str, session: &str) -> Result<Option<(String, i64)>> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(err)?;
        let email: Option<String> = tx
            .query_row(
                "SELECT email FROM logins WHERE login_id = ?1 AND verified = 1",
                params![login_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let Some(email) = email else {
            return Ok(None);
        };
        tx.execute("DELETE FROM logins WHERE login_id = ?1", params![login_id])
            .map_err(err)?;
        tx.execute(
            "INSERT OR IGNORE INTO accounts (email, created_ms) VALUES (?1, ?2)",
            params![email, now_ms() as i64],
        )
        .map_err(err)?;
        let account_id: i64 = tx
            .query_row(
                "SELECT id FROM accounts WHERE email = ?1",
                params![email],
                |r| r.get(0),
            )
            .map_err(err)?;
        tx.execute(
            "INSERT INTO sessions (token_hash, account_id, created_ms) VALUES (?1, ?2, ?3)",
            params![hash(session), account_id, now_ms() as i64],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(Some((email, account_id)))
    }

    /// The account a session belongs to: `(id, email)`.
    pub fn session_account(&self, session: &str) -> Result<Option<(i64, String)>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT a.id, a.email FROM sessions s JOIN accounts a ON a.id = s.account_id
                 WHERE s.token_hash = ?1",
                params![hash(session)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)
    }

    pub fn account_email(&self, account_id: i64) -> Result<String> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT email FROM accounts WHERE id = ?1",
                params![account_id],
                |r| r.get(0),
            )
            .map_err(err)
    }

    pub fn device(&self, device_id: &str) -> Result<Option<Device>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT device_id, account_id, name, public_key, last_seen_ms FROM devices
                 WHERE device_id = ?1",
                params![device_id],
                row_to_device,
            )
            .optional()
            .map_err(err)
    }

    /// Add or rename a device. Errors if it belongs to another account.
    pub fn register_device(
        &self,
        account_id: i64,
        device_id: &str,
        name: &str,
        public_key: &[u8; 32],
    ) -> Result<std::result::Result<(), ()>> {
        if let Some(existing) = self.device(device_id)?
            && (existing.account_id != account_id || &existing.public_key != public_key)
        {
            return Ok(Err(()));
        }
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO devices (device_id, account_id, name, public_key) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(device_id) DO UPDATE SET name = excluded.name",
                params![device_id, account_id, name, public_key.as_slice()],
            )
            .map_err(err)?;
        Ok(Ok(()))
    }

    pub fn devices(&self, account_id: i64) -> Result<Vec<Device>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT device_id, account_id, name, public_key, last_seen_ms FROM devices
                 WHERE account_id = ?1 ORDER BY name",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![account_id], row_to_device)
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(rows)
    }

    pub fn touch_device(&self, device_id: &str) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE devices SET last_seen_ms = ?1 WHERE device_id = ?2",
                params![now_ms() as i64, device_id],
            )
            .map_err(err)?;
        Ok(())
    }
}

impl Store {
    /// A token for the hosted MCP server, until OAuth (B3) replaces it.
    pub fn create_token(&self, account_id: i64, token: &str, label: &str) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO api_tokens (token_hash, account_id, label, created_ms) VALUES (?1, ?2, ?3, ?4)",
                params![hash(token), account_id, label, now_ms() as i64],
            )
            .map_err(err)?;
        Ok(())
    }

    /// The account a (not revoked) token belongs to.
    pub fn token_account(&self, token: &str) -> Result<Option<i64>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT account_id FROM api_tokens WHERE token_hash = ?1 AND revoked = 0",
                params![hash(token)],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)
    }

    /// Revoke every token of the account: `opendrop relay token` ones and
    /// every OAuth connection (access and refresh tokens, unused codes).
    /// Returns how many tokens and connections that was.
    pub fn revoke_tokens(&self, account_id: i64) -> Result<usize> {
        let db = self.db.lock().unwrap();
        let api = db
            .execute(
                "UPDATE api_tokens SET revoked = 1 WHERE account_id = ?1 AND revoked = 0",
                params![account_id],
            )
            .map_err(err)?;
        // One refresh token per connected app.
        let connections: usize = db
            .query_row(
                "SELECT COUNT(*) FROM oauth_tokens WHERE account_id = ?1 AND kind = 'refresh'",
                params![account_id],
                |r| r.get::<_, i64>(0),
            )
            .map_err(err)? as usize;
        db.execute(
            "DELETE FROM oauth_tokens WHERE account_id = ?1",
            params![account_id],
        )
        .map_err(err)?;
        db.execute(
            "DELETE FROM oauth_codes WHERE account_id = ?1",
            params![account_id],
        )
        .map_err(err)?;
        Ok(api + connections)
    }

    pub fn add_inbox_item(&self, item: &crate::inbox::Item, file_key: &[u8]) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO inbox (inbox_id, account_id, name, size, mime, sha256, from_device,
                                    sent_ms, expires_ms, file_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    item.inbox_id,
                    item.account_id,
                    item.name,
                    item.size as i64,
                    item.mime,
                    item.sha256,
                    item.from_device,
                    item.sent_ms as i64,
                    item.expires_ms as i64,
                    file_key
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    /// The account's files that haven't expired at `now`, newest first.
    pub fn inbox(&self, account_id: i64, now: u64) -> Result<Vec<crate::inbox::Item>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT inbox_id, account_id, name, size, mime, sha256, from_device, sent_ms, expires_ms
                 FROM inbox WHERE account_id = ?1 AND expires_ms > ?2 ORDER BY sent_ms DESC, rowid DESC",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![account_id, now as i64], row_to_item)
            .map_err(err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(rows)
    }

    /// One of the account's files with its wrapped key, if it hasn't
    /// expired. Another account's id finds nothing.
    pub fn inbox_item(
        &self,
        account_id: i64,
        inbox_id: &str,
        now: u64,
    ) -> Result<Option<(crate::inbox::Item, Vec<u8>)>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT inbox_id, account_id, name, size, mime, sha256, from_device, sent_ms, expires_ms,
                        file_key
                 FROM inbox WHERE account_id = ?1 AND inbox_id = ?2 AND expires_ms > ?3",
                params![account_id, inbox_id, now as i64],
                |r| Ok((row_to_item(r)?, r.get(9)?)),
            )
            .optional()
            .map_err(err)
    }

    /// Remove one file's row; true if it was there.
    pub fn remove_inbox_item(&self, inbox_id: &str) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM inbox WHERE inbox_id = ?1", params![inbox_id])
            .map_err(err)?
            > 0)
    }

    /// Remove expired rows; returns their ids so the blobs go too.
    pub fn expire_inbox(&self, now: u64) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let ids = db
            .prepare("SELECT inbox_id FROM inbox WHERE expires_ms <= ?1")
            .map_err(err)?
            .query_map(params![now as i64], |r| r.get(0))
            .map_err(err)?
            .collect::<std::result::Result<Vec<String>, _>>()
            .map_err(err)?;
        db.execute(
            "DELETE FROM inbox WHERE expires_ms <= ?1",
            params![now as i64],
        )
        .map_err(err)?;
        Ok(ids)
    }

    /// Bytes the account has waiting at `now`.
    pub fn inbox_usage(&self, account_id: i64, now: u64) -> Result<u64> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(size), 0) FROM inbox WHERE account_id = ?1 AND expires_ms > ?2",
                params![account_id, now as i64],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
            .map_err(err)
    }
}

/// An app registered through OAuth dynamic client registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// Set for confidential clients (`client_secret_basic` / `_post`).
    pub secret_hash: Option<Vec<u8>>,
}

/// A browser sign-in waiting for someone to approve its code on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scope: String,
    pub resource: String,
    pub created_ms: u64,
    /// `None` until a device answers; then whether it allowed it.
    pub allowed: Option<bool>,
    pub account_id: Option<i64>,
}

/// What an authorization code or a token stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub client_id: String,
    pub account_id: i64,
    pub scope: String,
    pub resource: String,
}

/// A code waiting to be exchanged at the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGrant {
    pub grant: Grant,
    pub redirect_uri: String,
    pub code_challenge: String,
}

const REQUEST_COLUMNS: &str = "r.client_id, c.name, r.redirect_uri, r.state, r.code_challenge, \
     r.scope, r.resource, r.created_ms, r.allowed, r.account_id";

fn row_to_request(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuthRequest> {
    Ok(AuthRequest {
        client_id: r.get(0)?,
        client_name: r.get(1)?,
        redirect_uri: r.get(2)?,
        state: r.get(3)?,
        code_challenge: r.get(4)?,
        scope: r.get(5)?,
        resource: r.get(6)?,
        created_ms: r.get::<_, i64>(7)? as u64,
        allowed: r.get::<_, Option<i64>>(8)?.map(|a| a != 0),
        account_id: r.get(9)?,
    })
}

/// OAuth (stage B3). Every secret (request ids, codes, tokens, client
/// secrets) is stored as a SHA-256 hash only.
impl Store {
    pub fn add_oauth_client(&self, client: &OAuthClient) -> Result<()> {
        let uris = serde_json::to_string(&client.redirect_uris).map_err(|e| e.to_string())?;
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_clients (client_id, name, redirect_uris, secret_hash, created_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![client.client_id, client.name, uris, client.secret_hash, now_ms() as i64],
            )
            .map_err(err)?;
        Ok(())
    }

    pub fn oauth_client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let row = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT client_id, name, redirect_uris, secret_hash FROM oauth_clients WHERE client_id = ?1",
                params![client_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(err)?;
        Ok(row.map(|(client_id, name, uris, secret_hash)| OAuthClient {
            client_id,
            name,
            redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
            secret_hash,
        }))
    }

    /// Store a browser sign-in under `request_id` (the browser's secret)
    /// and `user_code` (what the person types on a device).
    pub fn add_auth_request(
        &self,
        request_id: &str,
        user_code: &str,
        request: &AuthRequest,
    ) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_requests (request_hash, user_code, client_id, redirect_uri, state, \
                 code_challenge, scope, resource, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    hash(request_id),
                    user_code,
                    request.client_id,
                    request.redirect_uri,
                    request.state,
                    request.code_challenge,
                    request.scope,
                    request.resource,
                    request.created_ms as i64
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    pub fn auth_request(&self, request_id: &str) -> Result<Option<AuthRequest>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                &format!(
                    "SELECT {REQUEST_COLUMNS} FROM oauth_requests r JOIN oauth_clients c \
                     ON c.client_id = r.client_id WHERE r.request_hash = ?1"
                ),
                params![hash(request_id)],
                row_to_request,
            )
            .optional()
            .map_err(err)
    }

    /// The user code of a sign-in (for reloading its page).
    pub fn user_code(&self, request_id: &str) -> Result<Option<String>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT user_code FROM oauth_requests WHERE request_hash = ?1",
                params![hash(request_id)],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)
    }

    /// The undecided sign-in with this code, if it was created after
    /// `not_before`.
    pub fn pending_auth_request(
        &self,
        user_code: &str,
        not_before: u64,
    ) -> Result<Option<AuthRequest>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                &format!(
                    "SELECT {REQUEST_COLUMNS} FROM oauth_requests r JOIN oauth_clients c \
                     ON c.client_id = r.client_id \
                     WHERE r.user_code = ?1 AND r.allowed IS NULL AND r.created_ms > ?2"
                ),
                params![user_code, not_before as i64],
                row_to_request,
            )
            .optional()
            .map_err(err)
    }

    /// Record a device's answer; false if the code isn't pending any more.
    pub fn decide_auth_request(
        &self,
        user_code: &str,
        not_before: u64,
        account_id: i64,
        allow: bool,
    ) -> Result<bool> {
        let changed = self
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE oauth_requests SET allowed = ?1, account_id = ?2 \
                 WHERE user_code = ?3 AND allowed IS NULL AND created_ms > ?4",
                params![allow as i64, account_id, user_code, not_before as i64],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }

    /// Remove a sign-in; false if it was already gone (so only one caller
    /// turns it into a code).
    pub fn remove_auth_request(&self, request_id: &str) -> Result<bool> {
        let changed = self
            .db
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM oauth_requests WHERE request_hash = ?1",
                params![hash(request_id)],
            )
            .map_err(err)?;
        Ok(changed == 1)
    }

    pub fn add_code(&self, code: &str, code_grant: &CodeGrant, expires_ms: u64) -> Result<()> {
        let g = &code_grant.grant;
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, \
                 resource, account_id, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    hash(code),
                    g.client_id,
                    code_grant.redirect_uri,
                    code_grant.code_challenge,
                    g.scope,
                    g.resource,
                    g.account_id,
                    expires_ms as i64
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    /// Use up a code: it works once, and not after it expires.
    pub fn take_code(&self, code: &str, now: u64) -> Result<Option<CodeGrant>> {
        let db = self.db.lock().unwrap();
        let found = db
            .query_row(
                "SELECT client_id, redirect_uri, code_challenge, scope, resource, account_id, expires_ms \
                 FROM oauth_codes WHERE code_hash = ?1",
                params![hash(code)],
                |r| {
                    Ok((
                        CodeGrant {
                            grant: Grant {
                                client_id: r.get(0)?,
                                scope: r.get(3)?,
                                resource: r.get(4)?,
                                account_id: r.get(5)?,
                            },
                            redirect_uri: r.get(1)?,
                            code_challenge: r.get(2)?,
                        },
                        r.get::<_, i64>(6)? as u64,
                    ))
                },
            )
            .optional()
            .map_err(err)?;
        db.execute(
            "DELETE FROM oauth_codes WHERE code_hash = ?1",
            params![hash(code)],
        )
        .map_err(err)?;
        Ok(found.filter(|(_, expires)| *expires > now).map(|(g, _)| g))
    }

    /// `kind` is `access` or `refresh`.
    pub fn add_oauth_token(
        &self,
        token: &str,
        kind: &str,
        grant: &Grant,
        expires_ms: u64,
    ) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO oauth_tokens (token_hash, kind, client_id, account_id, scope, resource, expires_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    hash(token),
                    kind,
                    grant.client_id,
                    grant.account_id,
                    grant.scope,
                    grant.resource,
                    expires_ms as i64
                ],
            )
            .map_err(err)?;
        Ok(())
    }

    fn oauth_token(&self, token: &str, kind: &str, now: u64) -> Result<Option<Grant>> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT client_id, account_id, scope, resource FROM oauth_tokens \
                 WHERE token_hash = ?1 AND kind = ?2 AND expires_ms > ?3",
                params![hash(token), kind, now as i64],
                |r| {
                    Ok(Grant {
                        client_id: r.get(0)?,
                        account_id: r.get(1)?,
                        scope: r.get(2)?,
                        resource: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(err)
    }

    /// What a live (unexpired, unrevoked) access token grants.
    pub fn access_token(&self, token: &str, now: u64) -> Result<Option<Grant>> {
        self.oauth_token(token, "access", now)
    }

    /// Use up a refresh token (they rotate: each works once).
    pub fn take_refresh_token(&self, token: &str, now: u64) -> Result<Option<Grant>> {
        let grant = self.oauth_token(token, "refresh", now)?;
        let removed = self
            .db
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM oauth_tokens WHERE token_hash = ?1 AND kind = 'refresh'",
                params![hash(token)],
            )
            .map_err(err)?;
        // Two requests racing with one token: only the one that deleted it wins.
        Ok(grant.filter(|_| removed == 1))
    }

    /// Drop expired codes and tokens, and sign-ins older than `requests_before`.
    pub fn expire_oauth(&self, now: u64, requests_before: u64) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "DELETE FROM oauth_codes WHERE expires_ms <= ?1",
            params![now as i64],
        )
        .map_err(err)?;
        db.execute(
            "DELETE FROM oauth_tokens WHERE expires_ms <= ?1",
            params![now as i64],
        )
        .map_err(err)?;
        db.execute(
            "DELETE FROM oauth_requests WHERE created_ms <= ?1",
            params![requests_before as i64],
        )
        .map_err(err)?;
        Ok(())
    }
}

fn row_to_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<crate::inbox::Item> {
    Ok(crate::inbox::Item {
        inbox_id: r.get(0)?,
        account_id: r.get(1)?,
        name: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        mime: r.get(4)?,
        sha256: r.get(5)?,
        from_device: r.get(6)?,
        sent_ms: r.get::<_, i64>(7)? as u64,
        expires_ms: r.get::<_, i64>(8)? as u64,
    })
}

fn row_to_device(r: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    let key: Vec<u8> = r.get(3)?;
    let mut public_key = [0u8; 32];
    if key.len() == 32 {
        public_key.copy_from_slice(&key);
    }
    Ok(Device {
        device_id: r.get(0)?,
        account_id: r.get(1)?,
        name: r.get(2)?,
        public_key,
        last_seen_ms: r.get::<_, i64>(4)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_login_link_works_once_and_makes_one_account_per_email() {
        let store = Store::in_memory().unwrap();
        store.start_login("l1", "tok1", "a@example.com").unwrap();
        assert_eq!(
            store.finish_login("l1", "s1").unwrap(),
            None,
            "not opened yet"
        );
        assert_eq!(store.verify_login("nope").unwrap(), Verified::Unknown);
        assert_eq!(
            store.verify_login("tok1").unwrap(),
            Verified::Ok("l1".into())
        );
        let (email, account) = store.finish_login("l1", "s1").unwrap().unwrap();
        assert_eq!(email, "a@example.com");
        assert_eq!(store.finish_login("l1", "s2").unwrap(), None, "used up");
        assert_eq!(store.verify_login("tok1").unwrap(), Verified::Unknown);

        store.start_login("l2", "tok2", "a@example.com").unwrap();
        store.verify_login("tok2").unwrap();
        assert_eq!(store.finish_login("l2", "s2").unwrap().unwrap().1, account);
        assert_eq!(store.session_account("s1").unwrap().unwrap().0, account);
        assert_eq!(store.session_account("s3").unwrap(), None);
    }

    #[test]
    fn a_device_belongs_to_one_account_and_one_key() {
        let store = Store::in_memory().unwrap();
        for (l, t, e, s) in [("l1", "t1", "a@x", "s1"), ("l2", "t2", "b@x", "s2")] {
            store.start_login(l, t, e).unwrap();
            store.verify_login(t).unwrap();
            store.finish_login(l, s).unwrap();
        }
        let a = store.session_account("s1").unwrap().unwrap().0;
        let b = store.session_account("s2").unwrap().unwrap().0;
        assert_eq!(
            store.register_device(a, "d", "Mac", &[1; 32]).unwrap(),
            Ok(())
        );
        assert_eq!(
            store.register_device(a, "d", "Mac 2", &[1; 32]).unwrap(),
            Ok(())
        );
        assert_eq!(
            store.register_device(b, "d", "Mac", &[1; 32]).unwrap(),
            Err(())
        );
        assert_eq!(
            store.register_device(a, "d", "Mac", &[2; 32]).unwrap(),
            Err(())
        );
        assert_eq!(store.devices(a).unwrap()[0].name, "Mac 2");
        assert!(store.devices(b).unwrap().is_empty());
    }
}
