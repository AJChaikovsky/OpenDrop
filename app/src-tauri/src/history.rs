//! Transfer history (issue #35): every send and receive that finished, one
//! JSON object per line in `history.jsonl` in the config folder, so it
//! survives a restart. Filled by watching the node's own events, plus the
//! user's "no" to an incoming file (which has no event of its own).

use crate::node::AppEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE_NAME: &str = "history.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    Declined,
    Failed,
    Cancelled,
}

/// One finished transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// When it finished, in milliseconds since the Unix epoch.
    pub at_ms: u64,
    pub direction: Direction,
    /// The other device's name.
    pub peer: String,
    pub name: String,
    pub size: u64,
    /// Set for a folder: how many files it held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    pub result: Outcome,
    /// Where a received file or folder was saved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Why it failed, was declined or cancelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What we know about a transfer before it ends.
#[derive(Debug, Clone)]
struct Open {
    direction: Direction,
    peer: String,
    name: String,
    size: u64,
    files: Option<u64>,
}

#[derive(Debug)]
pub struct History {
    path: Option<PathBuf>,
    memory: Mutex<Vec<Entry>>,
    open: Mutex<HashMap<String, Open>>,
}

impl History {
    /// The history in `config_dir`, or (without one) in memory only.
    pub fn new(config_dir: Option<&Path>) -> Self {
        Self {
            path: config_dir.map(|c| c.join(FILE_NAME)),
            memory: Mutex::new(Vec::new()),
            open: Mutex::new(HashMap::new()),
        }
    }

    /// Note what `event` says about a transfer; if it ended one, record it
    /// and return the new entry.
    pub fn observe(&self, event: &AppEvent) -> Option<Entry> {
        let mut open = self.open.lock().unwrap();
        let (id, result, path, detail) = match event {
            AppEvent::IncomingRequest {
                transfer_id,
                peer_name,
                name,
                size,
                fetch,
                files,
                ..
            } => {
                // A fetch of one of our files is in Activity, not here.
                if fetch.is_none() {
                    open.insert(
                        transfer_id.clone(),
                        Open {
                            direction: Direction::Received,
                            peer: peer_name.clone(),
                            name: name.clone(),
                            size: *size,
                            files: *files,
                        },
                    );
                }
                return None;
            }
            AppEvent::SendWaiting {
                transfer_id,
                device_name,
                name,
                size,
                files,
            } => {
                open.insert(
                    transfer_id.clone(),
                    Open {
                        direction: Direction::Sent,
                        peer: device_name.clone(),
                        name: name.clone(),
                        size: *size,
                        files: *files,
                    },
                );
                return None;
            }
            AppEvent::IncomingExpired { transfer_id } => (
                transfer_id,
                Outcome::Declined,
                None,
                Some("not answered in time".to_owned()),
            ),
            AppEvent::ReceiveDone {
                transfer_id, path, ..
            } => (transfer_id, Outcome::Done, Some(path.clone()), None),
            AppEvent::TextReceived { transfer_id, .. } => (
                transfer_id,
                Outcome::Done,
                None,
                Some("copied to the clipboard".to_owned()),
            ),
            AppEvent::ReceiveFailed { transfer_id, error } => {
                (transfer_id, Outcome::Failed, None, Some(error.clone()))
            }
            AppEvent::ReceiveCancelled {
                transfer_id,
                by_peer,
            } => (
                transfer_id,
                Outcome::Cancelled,
                None,
                by_peer.then(|| "the sender cancelled it".to_owned()),
            ),
            AppEvent::SendDone { transfer_id, .. } => (transfer_id, Outcome::Done, None, None),
            AppEvent::SendDeclined { transfer_id } => (transfer_id, Outcome::Declined, None, None),
            AppEvent::SendFailed { transfer_id, error } => {
                (transfer_id, Outcome::Failed, None, Some(error.clone()))
            }
            AppEvent::SendCancelled {
                transfer_id,
                by_peer,
            } => (
                transfer_id,
                Outcome::Cancelled,
                None,
                by_peer.then(|| "the receiver cancelled it".to_owned()),
            ),
            _ => return None,
        };
        let started = open.remove(id)?;
        drop(open);
        Some(self.finish(started, result, path, detail))
    }

    /// Our user said no to an incoming file. Returns the new entry.
    pub fn declined(&self, transfer_id: &str) -> Option<Entry> {
        let started = self.open.lock().unwrap().remove(transfer_id)?;
        Some(self.finish(
            started,
            Outcome::Declined,
            None,
            Some("you declined it".into()),
        ))
    }

    fn finish(
        &self,
        started: Open,
        result: Outcome,
        path: Option<String>,
        detail: Option<String>,
    ) -> Entry {
        let entry = Entry {
            at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default(),
            direction: started.direction,
            peer: started.peer,
            name: started.name,
            size: started.size,
            files: started.files,
            result,
            path,
            detail,
        };
        match &self.path {
            None => self.memory.lock().unwrap().push(entry.clone()),
            Some(path) => {
                if let Err(e) = append(path, &entry) {
                    eprintln!("cannot write the history {}: {e}", path.display());
                }
            }
        }
        entry
    }

    /// Every entry, newest first, at most `limit`.
    pub fn entries(&self, limit: usize) -> Vec<Entry> {
        let mut entries = match &self.path {
            None => self.memory.lock().unwrap().clone(),
            Some(path) => read(path).unwrap_or_default(),
        };
        entries.reverse();
        entries.truncate(limit);
        entries
    }

    /// Whether `path` is where a recorded transfer was saved: "Show in
    /// folder" only opens those.
    pub fn has_path(&self, path: &str) -> bool {
        self.entries(usize::MAX)
            .iter()
            .any(|e| e.path.as_deref() == Some(path))
    }
}

fn append(path: &Path, entry: &Entry) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_string(entry).map_err(io::Error::other)?;
    line.push('\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())
}

/// Lines that don't parse (a crash mid-write, a newer version) are skipped.
fn read(path: &Path) -> io::Result<Vec<Entry>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect())
}

/// Open the system file browser with `path` selected.
pub fn reveal(path: &Path) -> io::Result<()> {
    let mut command;
    #[cfg(target_os = "macos")]
    {
        command = std::process::Command::new("open");
        command.arg("-R").arg(path);
    }
    #[cfg(windows)]
    {
        command = std::process::Command::new("explorer");
        let mut arg = std::ffi::OsString::from("/select,");
        arg.push(path);
        command.arg(arg);
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        command = std::process::Command::new("xdg-open");
        command.arg(path.parent().unwrap_or(path));
    }
    command.spawn().map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(Some(dir.path()));
        history.observe(&AppEvent::SendWaiting {
            transfer_id: "s1".into(),
            device_name: "Windows".into(),
            name: "a.txt".into(),
            size: 3,
            files: None,
        });
        history.observe(&AppEvent::SendDone {
            transfer_id: "s1".into(),
            sha256: "x".into(),
        });
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join(FILE_NAME))
            .unwrap();
        file.write_all(b"{half a line\n").unwrap();
        let entries = History::new(Some(dir.path())).entries(10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].result, Outcome::Done);
    }

    #[test]
    fn events_for_unknown_transfers_are_ignored() {
        let history = History::new(None);
        assert!(
            history
                .observe(&AppEvent::SendDone {
                    transfer_id: "nope".into(),
                    sha256: "x".into(),
                })
                .is_none()
        );
        assert!(history.declined("nope").is_none());
        assert!(history.entries(10).is_empty());
    }
}
