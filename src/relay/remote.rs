//! Requests that reach this device through the relay (stage B4), and the
//! ones it sends to the account's other devices.
//!
//! On the hello connection the relay may ask this device to:
//! - send a file (`fetch_ask`), from anywhere on the device except
//!   OpenDrop's own config folder;
//! - list a folder or find files by name (`list_ask`);
//! - take a file another device sent (`deliver`).
//!
//! Each needs a yes on this device, unless the requester has standing
//! access (see [`access`](super::access)), which the person can give along
//! with that first yes. Asks go through the daemon's usual approval channel,
//! so the app and `opendrop listen` show them like any other request.

use super::access::{self, Access, MAX_RELAY_FILE, PathRefusal};
use super::proto::{self, ClientMsg, RemoteEntry, Requester, RequesterKind, ServerMsg, codes};
use super::{Config, Connection, REPLY_TIMEOUT, unexpected};
use crate::audit::{AuditLog, Entry, Event};
use crate::daemon::{Direction, Status, Transfer, TransferTable};
use crate::identity::DeviceIdentity;
use crate::network::BoxError;
use crate::network::grants::GrantOffer;
use crate::network::server::{FetchInfo, FileRequest};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::SinkExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

/// How long the person has to answer an ask on this device.
pub const APPROVAL_TIMEOUT: Duration = crate::network::APPROVAL_TIMEOUT;

/// At most this many entries come back from one folder listing.
pub const MAX_LIST: usize = 500;
/// At most this many matches come back from one search.
pub const MAX_FOUND: usize = 50;
/// A search looks this many folders deep below where it starts.
const SEARCH_DEPTH: usize = 8;
/// A search gives up after looking at this many entries.
const SEARCH_BUDGET: usize = 200_000;

/// What another device of the account has in a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub device_name: String,
    pub folder: String,
    pub entries: Vec<RemoteEntry>,
    pub truncated: bool,
}

/// A request this device sent and is waiting on.
enum Own {
    /// The file comes in as a `deliver`; this is its transfer row.
    Fetch {
        transfer_id: String,
    },
    List(oneshot::Sender<Result<Listing, BoxError>>),
}

/// The device's side of relayed requests. One per daemon.
pub struct Remote {
    pub identity: DeviceIdentity,
    pub config: Config,
    pub config_dir: PathBuf,
    pub download_dir: PathBuf,
    /// The daemon's approval channel (the app's or the CLI's prompts).
    pub approval: mpsc::Sender<FileRequest>,
    pub access: Arc<Access>,
    pub transfers: Arc<TransferTable>,
    pub audit: Arc<AuditLog>,
    /// Messages for the relay, while the hello connection is up.
    outbox: Mutex<Option<mpsc::UnboundedSender<ClientMsg>>>,
    own: Mutex<HashMap<String, Own>>,
}

impl Remote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: DeviceIdentity,
        config: Config,
        config_dir: PathBuf,
        download_dir: PathBuf,
        approval: mpsc::Sender<FileRequest>,
        transfers: Arc<TransferTable>,
        audit: Arc<AuditLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            access: Arc::new(Access::new(&config_dir)),
            identity,
            config,
            config_dir,
            download_dir,
            approval,
            transfers,
            audit,
            outbox: Mutex::new(None),
            own: Mutex::new(HashMap::new()),
        })
    }

    /// The hello connection is up (`Some`) or down (`None`). Requests still
    /// waiting when it goes down fail: their answers can't arrive.
    pub(super) fn connected(&self, outbox: Option<mpsc::UnboundedSender<ClientMsg>>) {
        let down = outbox.is_none();
        *self.outbox.lock().unwrap() = outbox;
        if down {
            let waiting: Vec<(String, Own)> = self.own.lock().unwrap().drain().collect();
            for (_, own) in waiting {
                self.fail_own(own, "the relay connection dropped; try again".into());
            }
        }
    }

    fn send(&self, msg: ClientMsg) -> Result<(), BoxError> {
        match &*self.outbox.lock().unwrap() {
            Some(outbox) if outbox.send(msg).is_ok() => Ok(()),
            _ => Err(crate::error::coded(
                crate::error::ErrorCode::DeviceOffline,
                "this device isn't connected to the relay right now",
            )),
        }
    }

    fn answer(&self, job_id: &str, refusal: Option<(&str, String)>) {
        let (code, message) = match refusal {
            Some((code, message)) => (Some(code.to_owned()), Some(message)),
            None => (None, None),
        };
        let _ = self.send(ClientMsg::JobAnswer {
            job_id: job_id.to_owned(),
            accepted: code.is_none(),
            code,
            message,
        });
    }

    fn fail_own(&self, own: Own, message: String) {
        match own {
            Own::Fetch { transfer_id } => {
                self.transfers
                    .finish(&transfer_id, Status::Failed, Some(message));
            }
            Own::List(reply) => {
                let _ = reply.send(Err(message.into()));
            }
        }
    }

    /// Ask the account's device `device` (id or name) for the file at
    /// `path`. Returns the transfer id at once; the row follows the file in.
    pub fn fetch(&self, device: &str, path: &str, reason: &str) -> Result<String, BoxError> {
        let name = Path::new(path.trim_end_matches(['/', '\\']))
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_owned());
        let (transfer_id, _cancel) = self.transfers.begin(Transfer::new(
            Direction::Receive,
            None,
            device.to_owned(),
            name,
            0,
        ));
        let request_id = transfer_id.clone();
        self.own.lock().unwrap().insert(
            request_id.clone(),
            Own::Fetch {
                transfer_id: transfer_id.clone(),
            },
        );
        if let Err(e) = self.send(ClientMsg::RemoteFetch {
            request_id: request_id.clone(),
            device: device.to_owned(),
            path: path.to_owned(),
            reason: reason.to_owned(),
        }) {
            self.own.lock().unwrap().remove(&request_id);
            self.transfers
                .finish(&transfer_id, Status::Failed, Some(e.to_string()));
            return Err(e);
        }
        Ok(transfer_id)
    }

    /// List `folder` (home when `None`) on the account's device `device`,
    /// or find files there named like `query`. Waits for the answer, which
    /// may take that device's owner saying yes.
    pub async fn list(
        &self,
        device: &str,
        folder: Option<&str>,
        query: Option<&str>,
    ) -> Result<Listing, BoxError> {
        let request_id = format!(
            "list-{}",
            &crate::transfer::hex(&crate::identity::random_bytes())[..16]
        );
        let (reply, answer) = oneshot::channel();
        self.own
            .lock()
            .unwrap()
            .insert(request_id.clone(), Own::List(reply));
        if let Err(e) = self.send(ClientMsg::RemoteList {
            request_id: request_id.clone(),
            device: device.to_owned(),
            folder: folder.map(str::to_owned),
            query: query.map(str::to_owned),
        }) {
            self.own.lock().unwrap().remove(&request_id);
            return Err(e);
        }
        let waited = tokio::time::timeout(APPROVAL_TIMEOUT + REPLY_TIMEOUT, answer).await;
        self.own.lock().unwrap().remove(&request_id);
        match waited {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("the relay connection dropped; try again".into()),
            Err(_) => Err("no answer from that device in time".into()),
        }
    }

    /// Act on one message from the relay's hello connection.
    pub(super) fn handle(self: &Arc<Self>, msg: ServerMsg) {
        match msg {
            ServerMsg::FetchAsk {
                job_id,
                requester,
                path,
                reason,
                deliver_to,
            } => {
                let me = Arc::clone(self);
                tokio::spawn(async move {
                    me.on_fetch(job_id, requester, path, reason, deliver_to)
                        .await
                });
            }
            ServerMsg::ListAsk {
                job_id,
                requester,
                folder,
                query,
            } => {
                let me = Arc::clone(self);
                tokio::spawn(async move { me.on_list(job_id, requester, folder, query).await });
            }
            ServerMsg::Deliver {
                job_id,
                requester,
                from_device,
                name,
                size,
                sha256,
                request_id,
            } => {
                let me = Arc::clone(self);
                tokio::spawn(async move {
                    me.on_deliver(
                        job_id,
                        requester,
                        from_device,
                        name,
                        size,
                        sha256,
                        request_id,
                    )
                    .await
                });
            }
            ServerMsg::ListResult {
                request_id,
                device_name,
                folder,
                entries,
                truncated,
            } => {
                if let Some(Own::List(reply)) = self.own.lock().unwrap().remove(&request_id) {
                    let _ = reply.send(Ok(Listing {
                        device_name,
                        folder,
                        entries,
                        truncated,
                    }));
                }
            }
            ServerMsg::RequestFailed {
                request_id,
                code,
                message,
            } => {
                let own = self.own.lock().unwrap().remove(&request_id);
                if let Some(own) = own {
                    let message = if code == codes::DECLINED {
                        "the owner declined".to_owned()
                    } else {
                        message
                    };
                    match own {
                        Own::Fetch { transfer_id } => {
                            let status =
                                if matches!(code.as_str(), codes::DECLINED | codes::TIMEOUT) {
                                    Status::Declined
                                } else {
                                    Status::Failed
                                };
                            self.transfers.finish(&transfer_id, status, Some(message));
                        }
                        other => self.fail_own(other, message),
                    }
                }
            }
            _ => {}
        }
    }

    /// Ask the person at this device (unless `requester` has standing
    /// access). `Ok(())` means go ahead.
    async fn approve(
        &self,
        job_id: &str,
        requester: &Requester,
        what: String,
        size: u64,
        reason: String,
    ) -> Result<(), (&'static str, String)> {
        if self.access.allows(&requester.id) {
            return Ok(());
        }
        let (respond, decision) = oneshot::channel();
        let ask = FileRequest {
            transfer_id: job_id.to_owned(),
            peer_name: requester.name.clone(),
            peer_addr: ([0, 0, 0, 0], 0).into(),
            verified: true,
            name: what,
            size,
            respond,
            cancel: None,
            files: None,
            text: None,
            fetch: Some(FetchInfo {
                peer_id: requester.id.clone(),
                reason,
                via_assistant: requester.kind == RequesterKind::Assistant,
                grant: Some(
                    GrantOffer::standing(Arc::clone(&self.access), requester.clone())
                        .audited(Arc::clone(&self.audit), &requester.name),
                ),
            }),
        };
        if self.approval.send(ask).await.is_err() {
            return Err((codes::DECLINED, "nobody can answer on that device".into()));
        }
        match tokio::time::timeout(APPROVAL_TIMEOUT, decision).await {
            Ok(Ok(true)) => Ok(()),
            Ok(_) => Err((codes::DECLINED, "the owner declined".into())),
            Err(_) => Err((codes::TIMEOUT, "the owner didn't answer in time".into())),
        }
    }

    fn entry(&self, event: Event, requester: &Requester) -> Entry {
        Entry::new(event, Some(&requester.id), &requester.name)
            .via_assistant(requester.kind == RequesterKind::Assistant)
    }

    async fn on_fetch(
        self: Arc<Self>,
        job_id: String,
        requester: Requester,
        path: String,
        reason: String,
        deliver_to: String,
    ) {
        self.audit.record(
            self.entry(Event::Request, &requester)
                .file(&path)
                .detail(&reason),
        );
        let refuse = |code: &'static str, message: String| {
            self.audit.record(
                self.entry(Event::Decline, &requester)
                    .file(&path)
                    .detail(&message),
            );
            self.answer(&job_id, Some((code, message)));
        };
        let resolved = match access::resolve(&self.config_dir, &path) {
            Ok(p) => p,
            Err(PathRefusal::NotFound(m)) => return refuse(codes::NOT_FOUND, m),
            Err(PathRefusal::Refused(m)) => return refuse(codes::REFUSED, m),
        };
        let meta = match std::fs::metadata(&resolved) {
            Ok(meta) => meta,
            Err(e) => return refuse(codes::NOT_FOUND, format!("cannot read {path}: {e}")),
        };
        if meta.is_dir() {
            return refuse(
                codes::REFUSED,
                format!("{} is a folder; ask for a file in it", resolved.display()),
            );
        }
        if meta.len() > MAX_RELAY_FILE {
            return refuse(
                codes::TOO_LARGE,
                format!(
                    "{} is {} MB; files over the relay can be at most {} MB",
                    resolved.display(),
                    meta.len() / 1024 / 1024,
                    MAX_RELAY_FILE / 1024 / 1024
                ),
            );
        }
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let shown_reason = match (reason.trim(), deliver_to.as_str()) {
            (r, "the assistant") => r.to_owned(),
            ("", to) => format!("to be saved on {to}"),
            (r, to) => format!("{r} (to be saved on {to})"),
        };
        let granted = self.access.allows(&requester.id);
        if let Err((code, message)) = self
            .approve(
                &job_id,
                &requester,
                resolved.display().to_string(),
                meta.len(),
                shown_reason,
            )
            .await
        {
            return refuse(code, message);
        }
        self.audit.record(
            self.entry(Event::Approve, &requester)
                .file(&name)
                .detail(if granted {
                    "standing access"
                } else {
                    "approved"
                }),
        );
        let row = job_id.clone();
        if self.transfers.get(&row).is_none() {
            self.transfers.begin_with_id(
                row.clone(),
                Transfer::new(
                    Direction::Send,
                    Some(requester.id.clone()),
                    requester.name.clone(),
                    name.clone(),
                    meta.len(),
                ),
            );
        }
        self.transfers
            .update(&row, |t| t.status = Status::Transferring);
        self.answer(&job_id, None);
        let result = upload_job(&self.config, &self.identity, &job_id, &resolved).await;
        let detail = match &result {
            Ok(sha256) => {
                let sha256 = sha256.clone();
                self.transfers.update(&row, |t| {
                    t.bytes = t.size;
                    t.sha256 = Some(sha256);
                    t.status = Status::Done;
                });
                "sent over the relay: done".to_owned()
            }
            Err(e) => {
                self.transfers
                    .finish(&row, Status::Failed, Some(e.to_string()));
                format!("sent over the relay: failed ({e})")
            }
        };
        self.audit.record(
            Entry::new(Event::Send, Some(&requester.id), &requester.name)
                .file(&name)
                .detail(detail)
                .via_assistant(requester.kind == RequesterKind::Assistant),
        );
    }

    async fn on_list(
        self: Arc<Self>,
        job_id: String,
        requester: Requester,
        folder: Option<String>,
        query: Option<String>,
    ) {
        let start = match access::resolve(&self.config_dir, folder.as_deref().unwrap_or("~")) {
            Ok(p) if p.is_dir() => p,
            Ok(p) => {
                return self.answer(
                    &job_id,
                    Some((codes::REFUSED, format!("{} isn't a folder", p.display()))),
                );
            }
            Err(PathRefusal::NotFound(m)) => {
                return self.answer(&job_id, Some((codes::NOT_FOUND, m)));
            }
            Err(PathRefusal::Refused(m)) => {
                return self.answer(&job_id, Some((codes::REFUSED, m)));
            }
        };
        let what = match &query {
            Some(q) => format!("a search for \"{q}\" in {}", start.display()),
            None => format!("the list of files in {}", start.display()),
        };
        self.audit
            .record(self.entry(Event::List, &requester).detail(&what));
        if let Err((code, message)) = self
            .approve(&job_id, &requester, what, 0, String::new())
            .await
        {
            self.audit
                .record(self.entry(Event::Decline, &requester).detail(&message));
            return self.answer(&job_id, Some((code, message)));
        }
        let config_dir = self.config_dir.clone();
        let folder_shown = start.display().to_string();
        let listed = tokio::task::spawn_blocking(move || match query {
            Some(q) => search(&config_dir, &start, &q),
            None => list_folder(&config_dir, &start),
        })
        .await;
        match listed {
            Ok(Ok((entries, truncated))) => {
                let _ = self.send(ClientMsg::ListAnswer {
                    job_id,
                    folder: folder_shown,
                    entries,
                    truncated,
                });
            }
            Ok(Err(e)) => self.answer(&job_id, Some((codes::NOT_FOUND, e.to_string()))),
            Err(e) => self.answer(&job_id, Some((codes::REFUSED, e.to_string()))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn on_deliver(
        self: Arc<Self>,
        job_id: String,
        requester: Requester,
        from_device: String,
        name: String,
        size: u64,
        sha256: String,
        request_id: Option<String>,
    ) {
        let own = request_id.and_then(|id| match self.own.lock().unwrap().remove(&id) {
            Some(Own::Fetch { transfer_id }) => Some(transfer_id),
            Some(other) => {
                self.own.lock().unwrap().insert(id, other);
                None
            }
            None => None,
        });
        let Some(safe_name) = crate::transfer::sanitize_file_name(&name) else {
            return self.answer(&job_id, Some((codes::REFUSED, "unusable file name".into())));
        };
        let row = match own {
            // We asked for it.
            Some(row) => row,
            // Standing access covers files it sends us too.
            None if self.access.allows(&requester.id) => {
                self.transfers
                    .begin_with_id(
                        job_id.clone(),
                        Transfer::new(
                            Direction::Receive,
                            None,
                            format!("{} (from {from_device})", requester.name),
                            safe_name.clone(),
                            size,
                        ),
                    )
                    .0
            }
            None => {
                let (respond, decision) = oneshot::channel();
                let offer = FileRequest {
                    transfer_id: job_id.clone(),
                    peer_name: format!("{} (from {from_device})", requester.name),
                    peer_addr: ([0, 0, 0, 0], 0).into(),
                    verified: true,
                    name: safe_name.clone(),
                    size,
                    respond,
                    cancel: None,
                    files: None,
                    text: None,
                    fetch: None,
                };
                let yes = self.approval.send(offer).await.is_ok()
                    && matches!(
                        tokio::time::timeout(APPROVAL_TIMEOUT, decision).await,
                        Ok(Ok(true))
                    );
                if !yes {
                    return self.answer(
                        &job_id,
                        Some((codes::DECLINED, "the owner declined".into())),
                    );
                }
                job_id.clone()
            }
        };
        self.transfers.update(&row, |t| {
            t.name = safe_name.clone();
            t.size = size;
            t.peer_name = from_device.clone();
            t.status = Status::Transferring;
        });
        self.answer(&job_id, None);
        match download_job(
            &self.config,
            &self.identity,
            &job_id,
            &self.download_dir,
            &safe_name,
            size,
            &sha256,
        )
        .await
        {
            Ok(path) => self.transfers.update(&row, |t| {
                t.bytes = size;
                t.path = Some(path);
                t.sha256 = Some(sha256);
                t.status = Status::Done;
            }),
            Err(e) => self
                .transfers
                .finish(&row, Status::Failed, Some(e.to_string())),
        }
    }
}

fn entry_for(path: &Path, meta: &std::fs::Metadata) -> RemoteEntry {
    RemoteEntry {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: path.display().to_string(),
        is_dir: meta.is_dir(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs()),
    }
}

/// What is in `folder`: folders first, then files, by name. OpenDrop's
/// config folder is left out.
pub fn list_folder(config_dir: &Path, folder: &Path) -> std::io::Result<(Vec<RemoteEntry>, bool)> {
    let mut entries = Vec::new();
    for item in std::fs::read_dir(folder)? {
        let Ok(item) = item else { continue };
        let path = item.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if access::is_private(config_dir, &path.canonicalize().unwrap_or(path.clone())) {
            continue;
        }
        entries.push(entry_for(&path, &meta));
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let truncated = entries.len() > MAX_LIST;
    entries.truncate(MAX_LIST);
    Ok((entries, truncated))
}

/// Files and folders below `start` whose names contain `query` (ignoring
/// case), newest first. Hidden folders and OpenDrop's config are skipped.
pub fn search(
    config_dir: &Path,
    start: &Path,
    query: &str,
) -> std::io::Result<(Vec<RemoteEntry>, bool)> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return list_folder(config_dir, start);
    }
    let private = config_dir
        .canonicalize()
        .unwrap_or_else(|_| config_dir.to_owned());
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([(start.to_owned(), 0usize)]);
    let mut budget = SEARCH_BUDGET;
    let mut truncated = false;
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(items) = std::fs::read_dir(&dir) else {
            continue;
        };
        for item in items.flatten() {
            if budget == 0 {
                truncated = true;
                queue.clear();
                break;
            }
            budget -= 1;
            let path = item.path();
            let name = item.file_name().to_string_lossy().into_owned();
            // Not following links keeps the walk inside `start`.
            let Ok(kind) = item.file_type() else { continue };
            if path.starts_with(&private) {
                continue;
            }
            if name.to_lowercase().contains(&needle)
                && let Ok(meta) = std::fs::metadata(&path)
            {
                found.push(entry_for(&path, &meta));
            }
            if kind.is_dir() && !name.starts_with('.') && depth + 1 < SEARCH_DEPTH {
                queue.push_back((path, depth + 1));
            }
        }
    }
    found.sort_by_key(|e| std::cmp::Reverse(e.modified));
    if found.len() > MAX_FOUND {
        truncated = true;
        found.truncate(MAX_FOUND);
    }
    Ok((found, truncated))
}

/// Bytes per binary frame (the relay takes frames up to 64 KiB).
const CHUNK: usize = 32 * 1024;

/// Send the file of an approved `fetch_ask`. Returns its SHA-256.
async fn upload_job(
    config: &Config,
    identity: &DeviceIdentity,
    job_id: &str,
    path: &Path,
) -> Result<String, BoxError> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or("not a file")?;
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let size = data.len() as u64;
    let sha256 = crate::transfer::sha256_hex(&data);
    let mut connection = Connection::open(&config.url).await?;
    let signature = identity.sign(&proto::job_upload_message(
        &identity.id,
        job_id,
        &name,
        size,
        &sha256,
        &connection.nonce,
    ));
    connection
        .send(&ClientMsg::JobUpload {
            device_id: identity.id.clone(),
            job_id: job_id.to_owned(),
            name,
            size,
            sha256: sha256.clone(),
            signature: B64.encode(signature),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::UploadReady => {}
        other => return Err(unexpected(&other)),
    }
    for chunk in data.chunks(CHUNK) {
        connection
            .socket
            .send(Message::binary(chunk.to_vec()))
            .await?;
    }
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::JobUploaded => Ok(sha256),
        other => Err(unexpected(&other)),
    }
}

/// Collect the file a `deliver` announced into `dir`, checking its size and
/// SHA-256. Returns where it was saved.
async fn download_job(
    config: &Config,
    identity: &DeviceIdentity,
    job_id: &str,
    dir: &Path,
    name: &str,
    size: u64,
    sha256: &str,
) -> Result<PathBuf, BoxError> {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;
    let mut connection = Connection::open(&config.url).await?;
    let signature = identity.sign(&proto::job_download_message(
        &identity.id,
        job_id,
        &connection.nonce,
    ));
    connection
        .send(&ClientMsg::JobDownload {
            device_id: identity.id.clone(),
            job_id: job_id.to_owned(),
            signature: B64.encode(signature),
        })
        .await?;
    match connection.receive(REPLY_TIMEOUT).await? {
        ServerMsg::DownloadReady {
            size: s, sha256: h, ..
        } if s == size && h.eq_ignore_ascii_case(sha256) => {}
        ServerMsg::DownloadReady { .. } => {
            return Err("the relay announced a different file".into());
        }
        other => return Err(unexpected(&other)),
    }
    let mut part = crate::transfer::PartFile::create(dir).await?;
    let mut hasher = Sha256::new();
    let mut got = 0u64;
    while got < size {
        let frame = tokio::time::timeout(REPLY_TIMEOUT, connection.socket.next())
            .await
            .map_err(|_| "the download stalled")?;
        match frame {
            Some(Ok(Message::Binary(chunk))) => {
                got += chunk.len() as u64;
                if got > size {
                    return Err("the relay sent more than announced".into());
                }
                hasher.update(&chunk);
                part.file().write_all(&chunk).await?;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            _ => return Err("the download ended early".into()),
        }
    }
    let digest = crate::transfer::hex(&hasher.finalize());
    if !digest.eq_ignore_ascii_case(sha256) {
        part.discard().await;
        return Err("the file's SHA-256 doesn't match; it was thrown away".into());
    }
    Ok(part.persist(dir, name).await?)
}
