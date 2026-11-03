//! The audit log: what other devices (and assistants) asked this one for,
//! and what was decided. One JSON object per line, appended to
//! `audit.log` in the config folder; nothing is ever rewritten. It records
//! names, ids and decisions, never file contents.

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE_NAME: &str = "audit.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// A device listed our shared files.
    List,
    /// A device asked for one of our shared files.
    Request,
    /// Our user (or a folder grant) said yes to a request or incoming file.
    Approve,
    /// A request or incoming file was declined: by our user, by timing out,
    /// or because it wasn't allowed.
    Decline,
    /// Our user let a device fetch from a folder for a while.
    Grant,
    /// We sent a file to a device (the result is in `detail`).
    Send,
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Milliseconds since the Unix epoch.
    pub at_ms: u64,
    pub event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    pub peer_name: String,
    /// The file's name (never its contents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// More about it: the reason given, why it was declined, the folder
    /// granted, how a send ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// An AI assistant asked, according to the other device.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub via_assistant: bool,
}

impl Entry {
    pub fn new(event: Event, peer_id: Option<&str>, peer_name: &str) -> Self {
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default();
        Self {
            at_ms,
            event,
            peer_id: peer_id.map(str::to_owned),
            peer_name: peer_name.to_owned(),
            file: None,
            detail: None,
            via_assistant: false,
        }
    }

    pub fn file(mut self, name: &str) -> Self {
        self.file = Some(name.to_owned());
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.is_empty() {
            self.detail = Some(detail);
        }
        self
    }

    pub fn via_assistant(mut self, yes: bool) -> Self {
        self.via_assistant = yes;
        self
    }
}

/// Where entries go: a file, or (in tests, or without a config folder)
/// memory.
#[derive(Debug)]
pub struct AuditLog {
    path: Option<PathBuf>,
    memory: Mutex<Vec<Entry>>,
}

impl AuditLog {
    /// The log in `config_dir`.
    pub fn open(config_dir: &Path) -> Self {
        Self {
            path: Some(config_dir.join(FILE_NAME)),
            memory: Mutex::new(Vec::new()),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            path: None,
            memory: Mutex::new(Vec::new()),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Append `entry`. A log that can't be written doesn't stop the
    /// transfer; the error goes to stderr.
    pub fn record(&self, entry: Entry) {
        let mut memory = self.memory.lock().unwrap();
        match &self.path {
            None => memory.push(entry),
            Some(path) => {
                if let Err(e) = append(path, &entry) {
                    eprintln!("cannot write the audit log {}: {e}", path.display());
                }
            }
        }
    }

    /// Every entry so far, oldest first.
    pub fn entries(&self) -> io::Result<Vec<Entry>> {
        match &self.path {
            None => Ok(self.memory.lock().unwrap().clone()),
            Some(path) => read(path),
        }
    }
}

fn append(path: &Path, entry: &Entry) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(&line)
}

/// The entries in the log at `path` (none if it doesn't exist yet). Lines
/// that don't parse are skipped.
pub fn read(path: &Path) -> io::Result<Vec<Entry>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_lines_and_reads_them_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path());
        log.record(Entry::new(Event::List, Some("device-1"), "PC").detail("2 files"));
        log.record(
            Entry::new(Event::Request, Some("device-1"), "PC")
                .file("q3.pdf")
                .detail("for the deck")
                .via_assistant(true),
        );
        // A second handle on the same file appends, it doesn't overwrite.
        AuditLog::open(dir.path()).record(Entry::new(Event::Decline, None, "PC"));
        let entries = log.entries().unwrap();
        assert_eq!(
            entries.iter().map(|e| e.event).collect::<Vec<_>>(),
            [Event::List, Event::Request, Event::Decline]
        );
        assert_eq!(entries[1].file.as_deref(), Some("q3.pdf"));
        assert!(entries[1].via_assistant);
        let text = std::fs::read_to_string(dir.path().join(FILE_NAME)).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert!(text.lines().next().unwrap().contains(r#""event":"list""#));
    }

    #[test]
    fn a_missing_log_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&dir.path().join(FILE_NAME)).unwrap().is_empty());
    }
}
