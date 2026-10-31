//! Every transfer a daemon has seen, in either direction, with its progress
//! and a way to cancel it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Waiting for a user (ours for incoming files, theirs for outgoing).
    AwaitingApproval,
    Transferring,
    Done,
    Declined,
    Failed,
    Cancelled,
}

impl Status {
    /// Nothing more will happen to a transfer in this state.
    pub fn is_final(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Declined | Self::Failed | Self::Cancelled
        )
    }
}

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub transfer_id: String,
    pub direction: Direction,
    /// Known for outgoing transfers (from the handshake).
    pub peer_id: Option<String>,
    pub peer_name: String,
    /// File name as offered.
    pub name: String,
    pub size: u64,
    pub bytes: u64,
    pub status: Status,
    /// Where an incoming file was saved.
    pub path: Option<PathBuf>,
    pub sha256: Option<String>,
    pub error: Option<String>,
    /// Unix time in milliseconds when the row was created.
    pub started_ms: u64,
}

impl Transfer {
    pub fn new(
        direction: Direction,
        peer_id: Option<String>,
        peer_name: String,
        name: String,
        size: u64,
    ) -> Self {
        Self {
            transfer_id: String::new(),
            direction,
            peer_id,
            peer_name,
            name,
            size,
            bytes: 0,
            status: Status::AwaitingApproval,
            path: None,
            sha256: None,
            error: None,
            started_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CancelError {
    NotFound,
    /// Already done, declined, failed or cancelled.
    AlreadyFinished(Status),
    /// Running, but nothing holds a way to stop it (an incoming file that is
    /// already streaming).
    NotCancellable,
}

impl std::fmt::Display for CancelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no such transfer"),
            Self::AlreadyFinished(status) => write!(f, "transfer already ended ({status:?})"),
            Self::NotCancellable => write!(f, "this transfer can't be cancelled once it started"),
        }
    }
}

impl std::error::Error for CancelError {}

#[derive(Debug, Default)]
pub struct TransferTable {
    rows: Mutex<BTreeMap<String, Transfer>>,
    cancels: Mutex<HashMap<String, oneshot::Sender<()>>>,
    next_id: AtomicU64,
}

impl TransferTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row under a fresh id. The receiver fires if someone cancels it.
    pub fn begin(&self, transfer: Transfer) -> (String, oneshot::Receiver<()>) {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let prefix = match transfer.direction {
            Direction::Send => "out",
            Direction::Receive => "in",
        };
        self.begin_with_id(format!("{prefix}-{n}"), transfer)
    }

    /// Add (or replace) a row under `id`.
    pub fn begin_with_id(
        &self,
        id: String,
        mut transfer: Transfer,
    ) -> (String, oneshot::Receiver<()>) {
        transfer.transfer_id = id.clone();
        let (cancel, cancelled) = oneshot::channel();
        self.rows.lock().unwrap().insert(id.clone(), transfer);
        self.cancels.lock().unwrap().insert(id.clone(), cancel);
        (id, cancelled)
    }

    pub fn get(&self, id: &str) -> Option<Transfer> {
        self.rows.lock().unwrap().get(id).cloned()
    }

    /// Every row, oldest first.
    pub fn list(&self) -> Vec<Transfer> {
        let mut rows: Vec<Transfer> = self.rows.lock().unwrap().values().cloned().collect();
        rows.sort_by(|a, b| {
            a.started_ms
                .cmp(&b.started_ms)
                .then_with(|| a.transfer_id.cmp(&b.transfer_id))
        });
        rows
    }

    /// Change a row in place. Final rows stay final, and a row that ends
    /// gives up its cancel handle.
    pub fn update(&self, id: &str, change: impl FnOnce(&mut Transfer)) {
        let mut rows = self.rows.lock().unwrap();
        let Some(row) = rows.get_mut(id) else {
            return;
        };
        if row.status.is_final() {
            return;
        }
        change(row);
        if row.status.is_final() {
            self.cancels.lock().unwrap().remove(id);
        }
    }

    /// End a row with `status` (and an error to show, if any).
    pub fn finish(&self, id: &str, status: Status, error: Option<String>) {
        self.update(id, |t| {
            t.status = status;
            t.error = error;
        });
    }

    /// Ask whoever runs the transfer to stop. The row turns `cancelled` once
    /// they have.
    pub fn cancel(&self, id: &str) -> Result<(), CancelError> {
        let status = self.get(id).ok_or(CancelError::NotFound)?.status;
        if status.is_final() {
            return Err(CancelError::AlreadyFinished(status));
        }
        let cancel = self.cancels.lock().unwrap().remove(id);
        match cancel.map(|cancel| cancel.send(())) {
            Some(Ok(())) => Ok(()),
            _ => Err(CancelError::NotCancellable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(direction: Direction) -> Transfer {
        Transfer::new(direction, None, "Mac".into(), "a.txt".into(), 10)
    }

    #[test]
    fn rows_get_ids_and_keep_final_states() {
        let table = TransferTable::new();
        let (a, _ca) = table.begin(row(Direction::Send));
        let (b, _cb) = table.begin(row(Direction::Receive));
        assert_eq!((a.as_str(), b.as_str()), ("out-1", "in-2"));
        table.update(&a, |t| t.bytes = 4);
        table.finish(&a, Status::Done, None);
        table.update(&a, |t| t.status = Status::Failed);
        assert_eq!(table.get(&a).unwrap().status, Status::Done);
        assert_eq!(table.get(&a).unwrap().bytes, 4);
        assert_eq!(table.list().len(), 2);
    }

    #[test]
    fn cancel_reaches_the_runner_once() {
        let table = TransferTable::new();
        let (id, mut cancelled) = table.begin(row(Direction::Send));
        assert_eq!(table.cancel("nope"), Err(CancelError::NotFound));
        table.cancel(&id).unwrap();
        assert!(cancelled.try_recv().is_ok());
        assert_eq!(table.cancel(&id), Err(CancelError::NotCancellable));
        table.finish(&id, Status::Cancelled, None);
        assert_eq!(
            table.cancel(&id),
            Err(CancelError::AlreadyFinished(Status::Cancelled))
        );
    }
}
