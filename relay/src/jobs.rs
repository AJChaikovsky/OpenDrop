//! Requests routed through the relay to a device (stage B4).
//!
//! A job is one request to one of an account's devices: fetch a file, or
//! list a folder (or search). It is asked on the device's hello connection,
//! answered there by the person at the device (or by standing access they
//! gave), and its file then travels over separate connections: up from the
//! device that has it, and either into the assistant inbox or on to another
//! of the account's devices.
//!
//! Jobs live in memory only; one that isn't finished in
//! [`JOB_TTL`] is dropped, with its file.

use crate::Relay;
use crate::inbox;
use crate::store::Device;
use opendrop::relay::proto::{RemoteEntry, Requester, RequesterKind, ServerMsg, codes};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long a job may take from ask to delivery.
pub const JOB_TTL: Duration = Duration::from_secs(15 * 60);

/// Where a fetched file goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The account's assistant inbox.
    Inbox,
    /// Another of the account's devices, saved in its download folder.
    Device { device_id: String, name: String },
}

/// A listing a device sent back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub device_name: String,
    pub folder: String,
    pub entries: Vec<RemoteEntry>,
    pub truncated: bool,
}

/// Where a job stands, as whoever asked sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    /// Waiting for the person at the device to answer.
    Asking,
    /// Approved: the file is on its way.
    Moving,
    Listed(Listing),
    /// The file is in the assistant inbox under this id.
    InInbox(String),
    /// The file was saved on the named device.
    Delivered(String),
    Failed {
        code: String,
        message: String,
    },
}

impl JobState {
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Asking | Self::Moving)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Asked the source device; waiting for its answer.
    Asking,
    /// The source said yes; waiting for its upload.
    Uploading,
    /// The file is here; the target was asked to take it.
    Offering,
    /// The target said yes; waiting for it to collect the file.
    Collecting,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fetch,
    List,
}

/// A file held for a device, sealed like inbox files.
#[derive(Debug, Clone)]
pub(crate) struct Held {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub wrapped: Vec<u8>,
}

pub(crate) struct Job {
    pub account_id: i64,
    pub requester: Requester,
    pub source: Device,
    kind: Kind,
    pub delivery: Delivery,
    /// A device that asked: its id and its own id for the request.
    pub reply_to: Option<(String, String)>,
    stage: Stage,
    state: watch::Sender<JobState>,
    created: Instant,
    pub held: Option<Held>,
}

impl Job {
    fn set(&self, state: JobState) {
        let _ = self.state.send(state);
    }
}

fn job_id() -> String {
    format!("job_{}", &crate::random_token()[..22])
}

/// A refusal: an error code from `codes` and a message for whoever asked.
pub type Refusal = (&'static str, String);

impl Relay {
    /// The account's device `query` names (id or name), preferring online
    /// ones. It must be online.
    pub(crate) fn find_device(&self, account_id: i64, query: &str) -> Result<Device, Refusal> {
        let devices = self
            .store
            .devices(account_id)
            .map_err(|e| (codes::BAD_REQUEST, e))?;
        let named: Vec<&Device> = devices
            .iter()
            .filter(|d| d.device_id == query || opendrop::discovery::same_name(&d.name, query))
            .collect();
        let online: Vec<&Device> = named
            .iter()
            .copied()
            .filter(|d| self.is_online(&d.device_id))
            .collect();
        match (online.as_slice(), named.as_slice()) {
            ([device], _) => Ok((*device).clone()),
            ([], []) => {
                let names: Vec<String> = devices
                    .iter()
                    .map(|d| {
                        let state = if self.is_online(&d.device_id) {
                            "online"
                        } else {
                            "offline"
                        };
                        format!("\"{}\" ({state})", d.name)
                    })
                    .collect();
                Err((
                    codes::NOT_FOUND,
                    format!(
                        "no device named \"{query}\" on this account; its devices: {}",
                        if names.is_empty() {
                            "none".to_owned()
                        } else {
                            names.join(", ")
                        }
                    ),
                ))
            }
            ([], [device, ..]) => Err((
                codes::OFFLINE,
                format!(
                    "\"{}\" isn't connected to the relay right now (is OpenDrop running there?)",
                    device.name
                ),
            )),
            (several, _) => Err((
                codes::BAD_REQUEST,
                format!(
                    "several online devices are called \"{query}\"; use a device id: {}",
                    several
                        .iter()
                        .map(|d| d.device_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }

    /// Ask `device` (id or name) for the file at `path`, for `requester`.
    /// It goes to the inbox, or with `deliver_to` to that device.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_fetch(
        &self,
        account_id: i64,
        requester: Requester,
        device: &str,
        path: &str,
        reason: &str,
        deliver_to: Option<&str>,
        reply_to: Option<(String, String)>,
    ) -> Result<(String, watch::Receiver<JobState>), Refusal> {
        let source = self.find_device(account_id, device)?;
        let delivery = match deliver_to {
            None => Delivery::Inbox,
            Some(target) => {
                let target = self.find_device(account_id, target)?;
                if target.device_id == source.device_id {
                    return Err((
                        codes::BAD_REQUEST,
                        "the file is already on that device".into(),
                    ));
                }
                Delivery::Device {
                    device_id: target.device_id,
                    name: target.name,
                }
            }
        };
        if requester.id == format!("device:{}", source.device_id) {
            return Err((codes::BAD_REQUEST, "that's this device".into()));
        }
        let path: String = path.chars().take(4096).collect();
        let reason: String = reason.chars().take(500).collect();
        let deliver_name = match &delivery {
            Delivery::Inbox => "the assistant".to_owned(),
            Delivery::Device { name, .. } => name.clone(),
        };
        let id = job_id();
        let ask = ServerMsg::FetchAsk {
            job_id: id.clone(),
            requester: requester.clone(),
            path,
            reason,
            deliver_to: deliver_name,
        };
        self.start(
            account_id,
            requester,
            source,
            Kind::Fetch,
            delivery,
            reply_to,
            id,
            ask,
        )
    }

    /// Ask `device` for a folder listing (or a search), for `requester`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_list(
        &self,
        account_id: i64,
        requester: Requester,
        device: &str,
        folder: Option<&str>,
        query: Option<&str>,
        reply_to: Option<(String, String)>,
    ) -> Result<(String, watch::Receiver<JobState>), Refusal> {
        let source = self.find_device(account_id, device)?;
        if requester.id == format!("device:{}", source.device_id) {
            return Err((codes::BAD_REQUEST, "that's this device".into()));
        }
        let id = job_id();
        let ask = ServerMsg::ListAsk {
            job_id: id.clone(),
            requester: requester.clone(),
            folder: folder.map(|f| f.chars().take(4096).collect()),
            query: query.map(|q| q.chars().take(200).collect()),
        };
        self.start(
            account_id,
            requester,
            source,
            Kind::List,
            Delivery::Inbox,
            reply_to,
            id,
            ask,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        &self,
        account_id: i64,
        requester: Requester,
        source: Device,
        kind: Kind,
        delivery: Delivery,
        reply_to: Option<(String, String)>,
        id: String,
        ask: ServerMsg,
    ) -> Result<(String, watch::Receiver<JobState>), Refusal> {
        let (state, watch) = watch::channel(JobState::Asking);
        let source_id = source.device_id.clone();
        self.jobs.lock().unwrap().insert(
            id.clone(),
            Job {
                account_id,
                requester,
                source,
                kind,
                delivery,
                reply_to,
                stage: Stage::Asking,
                state,
                created: Instant::now(),
                held: None,
            },
        );
        if !self.push(&source_id, ask) {
            self.jobs.lock().unwrap().remove(&id);
            return Err((codes::OFFLINE, "that device just went offline".into()));
        }
        Ok((id, watch))
    }

    /// Where job `job_id` of `account_id` stands, if it exists.
    pub(crate) fn job_state(
        &self,
        account_id: i64,
        job_id: &str,
    ) -> Option<watch::Receiver<JobState>> {
        let jobs = self.jobs.lock().unwrap();
        jobs.get(job_id)
            .filter(|j| j.account_id == account_id)
            .map(|j| j.state.subscribe())
    }

    /// End `job_id` with `state`, telling a device that asked. Drops it
    /// (and any held file) once final.
    fn finish(&self, job_id: &str, state: JobState) {
        // Finished jobs stay (without their file) until they expire, so
        // whoever asked can still look the outcome up.
        let reply_to = {
            let mut jobs = self.jobs.lock().unwrap();
            let Some(job) = jobs.get_mut(job_id) else {
                return;
            };
            if job.state.borrow().is_final() {
                return;
            }
            job.stage = Stage::Done;
            if job.held.take().is_some() {
                self.blobs.delete(job_id);
            }
            job.set(state.clone());
            job.reply_to.clone()
        };
        if let Some((device_id, request_id)) = &reply_to {
            match &state {
                JobState::Failed { code, message } => {
                    self.push(
                        device_id,
                        ServerMsg::RequestFailed {
                            request_id: request_id.clone(),
                            code: code.clone(),
                            message: message.clone(),
                        },
                    );
                }
                JobState::Listed(listing) => {
                    self.push(
                        device_id,
                        ServerMsg::ListResult {
                            request_id: request_id.clone(),
                            device_name: listing.device_name.clone(),
                            folder: listing.folder.clone(),
                            entries: listing.entries.clone(),
                            truncated: listing.truncated,
                        },
                    );
                }
                _ => {}
            }
        }
    }

    fn fail(&self, job_id: &str, code: &str, message: impl Into<String>) {
        self.finish(
            job_id,
            JobState::Failed {
                code: code.to_owned(),
                message: message.into(),
            },
        );
    }

    /// A `job_answer` from `device_id`'s hello connection.
    pub(crate) fn job_answer(
        &self,
        device_id: &str,
        job_id: &str,
        accepted: bool,
        code: Option<String>,
        message: Option<String>,
    ) {
        let mut jobs = self.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(job_id) else {
            return;
        };
        let target = match &job.delivery {
            Delivery::Device { device_id, .. } => Some(device_id.as_str()),
            Delivery::Inbox => None,
        };
        let from_source = job.source.device_id == device_id && job.stage == Stage::Asking;
        let from_target = target == Some(device_id) && job.stage == Stage::Offering;
        if !(from_source || from_target) {
            return;
        }
        if accepted {
            match (from_source, job.kind) {
                (true, Kind::Fetch) => job.stage = Stage::Uploading,
                (true, Kind::List) => return, // a list is answered with list_answer
                (false, _) => job.stage = Stage::Collecting,
            }
            job.set(JobState::Moving);
            return;
        }
        drop(jobs);
        let code = code.unwrap_or_else(|| codes::DECLINED.to_owned());
        let message = message.unwrap_or_else(|| "the owner declined".to_owned());
        let message = if from_target {
            format!("the receiving device refused it: {message}")
        } else {
            message
        };
        self.fail(job_id, &code, message);
    }

    /// A `list_answer` from `device_id`'s hello connection.
    pub(crate) fn list_answer(
        &self,
        device_id: &str,
        job_id: &str,
        folder: String,
        mut entries: Vec<RemoteEntry>,
        truncated: bool,
    ) {
        let device_name = {
            let jobs = self.jobs.lock().unwrap();
            match jobs.get(job_id) {
                Some(job)
                    if job.source.device_id == device_id
                        && job.kind == Kind::List
                        && job.stage == Stage::Asking =>
                {
                    job.source.name.clone()
                }
                _ => return,
            }
        };
        entries.truncate(1000);
        self.finish(
            job_id,
            JobState::Listed(Listing {
                device_name,
                folder,
                entries,
                truncated,
            }),
        );
    }

    /// Fail the jobs waiting on `device_id`, which just went offline.
    pub(crate) fn device_gone(&self, device_id: &str) {
        let stuck: Vec<String> = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, j)| {
                (j.source.device_id == device_id
                    && matches!(j.stage, Stage::Asking | Stage::Uploading))
                    || matches!(&j.delivery, Delivery::Device { device_id: t, .. }
                        if t == device_id && matches!(j.stage, Stage::Offering | Stage::Collecting))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stuck {
            self.fail(
                &id,
                codes::OFFLINE,
                "the device went offline before it finished",
            );
        }
    }

    /// Drop jobs older than [`JOB_TTL`] (failing unfinished ones first).
    /// Returns how many.
    pub fn expire_jobs(&self) -> usize {
        let old: Vec<String> = self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, j)| j.created.elapsed() > JOB_TTL)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &old {
            self.fail(id, codes::TIMEOUT, "it took too long");
            self.jobs.lock().unwrap().remove(id);
        }
        old.len()
    }

    /// Whether `device_id` may upload the file of `job_id` now; the job's
    /// account and where the file goes.
    pub(crate) fn upload_slot(
        &self,
        device_id: &str,
        job_id: &str,
    ) -> Option<(i64, Device, Delivery)> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(job_id)?;
        (job.source.device_id == device_id && job.stage == Stage::Uploading)
            .then(|| (job.account_id, job.source.clone(), job.delivery.clone()))
    }

    /// The uploaded file of `job_id` went to the inbox as `inbox_id`.
    pub(crate) fn uploaded_to_inbox(&self, job_id: &str, inbox_id: String) {
        self.finish(job_id, JobState::InInbox(inbox_id));
    }

    /// The uploaded file of `job_id` is held for its target device: offer it.
    pub(crate) fn uploaded_for_device(&self, job_id: &str, held: Held) {
        let mut jobs = self.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(job_id) else {
            self.blobs.delete(job_id);
            return;
        };
        let Delivery::Device { device_id, .. } = job.delivery.clone() else {
            return;
        };
        let offer = ServerMsg::Deliver {
            job_id: job_id.to_owned(),
            requester: job.requester.clone(),
            from_device: job.source.name.clone(),
            name: held.name.clone(),
            size: held.size,
            sha256: held.sha256.clone(),
            request_id: job
                .reply_to
                .as_ref()
                .filter(|(asker, _)| *asker == device_id)
                .map(|(_, request_id)| request_id.clone()),
        };
        job.held = Some(held);
        job.stage = Stage::Offering;
        drop(jobs);
        if !self.push(&device_id, offer) {
            self.fail(job_id, codes::OFFLINE, "the receiving device went offline");
        }
    }

    /// The file `device_id` may collect for `job_id` now.
    pub(crate) fn collect(&self, device_id: &str, job_id: &str) -> Option<Held> {
        let mut jobs = self.jobs.lock().unwrap();
        let job = jobs.get_mut(job_id)?;
        match &job.delivery {
            Delivery::Device { device_id: t, .. }
                if t == device_id && job.stage == Stage::Collecting =>
            {
                job.stage = Stage::Done;
                job.held.clone()
            }
            _ => None,
        }
    }

    /// `device_id` collected the file of `job_id`.
    pub(crate) fn collected(&self, job_id: &str, ok: bool) {
        let name = self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .and_then(|j| match &j.delivery {
                Delivery::Device { name, .. } => Some(name.clone()),
                Delivery::Inbox => None,
            })
            .unwrap_or_default();
        if ok {
            self.finish(job_id, JobState::Delivered(name));
        } else {
            self.fail(
                job_id,
                codes::BAD_UPLOAD,
                "the file didn't reach the device",
            );
        }
    }

    /// Handle a request a device sent on its hello connection.
    pub(crate) fn device_request(&self, device: &Device, msg: opendrop::relay::proto::ClientMsg) {
        use opendrop::relay::proto::ClientMsg;
        let requester = Requester {
            kind: RequesterKind::Device,
            id: format!("device:{}", device.device_id),
            name: device.name.clone(),
        };
        let (request_id, started) = match msg {
            ClientMsg::JobAnswer {
                job_id,
                accepted,
                code,
                message,
            } => return self.job_answer(&device.device_id, &job_id, accepted, code, message),
            ClientMsg::ListAnswer {
                job_id,
                folder,
                entries,
                truncated,
            } => return self.list_answer(&device.device_id, &job_id, folder, entries, truncated),
            ClientMsg::RemoteFetch {
                request_id,
                device: target,
                path,
                reason,
            } => {
                let reply = Some((device.device_id.clone(), request_id.clone()));
                // The file comes back to the device that asked.
                let started = self.start_fetch(
                    device.account_id,
                    requester,
                    &target,
                    &path,
                    &reason,
                    Some(&device.device_id),
                    reply,
                );
                (request_id, started)
            }
            ClientMsg::RemoteList {
                request_id,
                device: target,
                folder,
                query,
            } => {
                let reply = Some((device.device_id.clone(), request_id.clone()));
                let started = self.start_list(
                    device.account_id,
                    requester,
                    &target,
                    folder.as_deref(),
                    query.as_deref(),
                    reply,
                );
                (request_id, started)
            }
            _ => return,
        };
        if let Err((code, message)) = started {
            self.push(
                &device.device_id,
                ServerMsg::RequestFailed {
                    request_id,
                    code: code.to_owned(),
                    message,
                },
            );
        }
    }

    /// Check an inbox upload fits: size and the account's quota.
    pub(crate) fn inbox_room(&self, account_id: i64, size: u64) -> Result<(), Refusal> {
        if size > inbox::MAX_FILE {
            return Err((
                codes::TOO_LARGE,
                format!(
                    "files over the relay can be at most {} MB",
                    inbox::MAX_FILE / 1024 / 1024
                ),
            ));
        }
        let used = self
            .store
            .inbox_usage(account_id, self.now())
            .map_err(|e| (codes::BAD_REQUEST, e))?;
        if used + size > inbox::ACCOUNT_QUOTA {
            return Err((
                codes::QUOTA,
                format!(
                    "the assistant inbox is full ({} MB); files leave it when read or after 24 hours",
                    inbox::ACCOUNT_QUOTA / 1024 / 1024
                ),
            ));
        }
        Ok(())
    }

    /// The upload of `job_id` was refused or broke off.
    pub(crate) fn upload_failed(&self, job_id: &str, message: &str) {
        self.fail(job_id, codes::BAD_UPLOAD, message);
    }
}

/// Wait until `state` is final, or `limit` passes. Returns the latest.
pub async fn wait(state: &mut watch::Receiver<JobState>, limit: Duration) -> JobState {
    let _ = tokio::time::timeout(limit, state.wait_for(JobState::is_final)).await;
    state.borrow().clone()
}
