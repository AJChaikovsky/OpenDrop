//! Time-limited folder grants: "let this device fetch from this folder for
//! 10 minutes", offered on a fetch approval. While a grant lasts, fetches
//! by that device of files in that folder (or below it) go through without
//! asking. Per-file approval stays the default; grants live only in memory.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a grant lasts.
pub const GRANT_DURATION: Duration = Duration::from_secs(10 * 60);

type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// The grants this device has given.
pub struct Grants {
    clock: Clock,
    entries: Mutex<Vec<Grant>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub peer_id: String,
    pub folder: PathBuf,
    pub until: Instant,
}

impl std::fmt::Debug for Grants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grants")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl Default for Grants {
    fn default() -> Self {
        Self::new()
    }
}

impl Grants {
    pub fn new() -> Self {
        Self::with_clock(Box::new(Instant::now))
    }

    /// Grants that read the time from `clock` (tests use a fake one).
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            clock,
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Let `peer_id` fetch from `folder` for `duration` from now.
    pub fn allow(&self, peer_id: &str, folder: &Path, duration: Duration) -> Grant {
        let grant = Grant {
            peer_id: peer_id.to_owned(),
            folder: folder.to_owned(),
            until: (self.clock)() + duration,
        };
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|g| !(g.peer_id == grant.peer_id && g.folder == grant.folder));
        entries.push(grant.clone());
        grant
    }

    /// Whether a grant still running lets `peer_id` fetch the file at `path`
    /// (a canonical path).
    pub fn covers(&self, peer_id: &str, path: &Path) -> bool {
        let now = (self.clock)();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|g| g.until > now);
        entries
            .iter()
            .any(|g| g.peer_id == peer_id && path.starts_with(&g.folder) && path != g.folder)
    }

    /// Grants still running.
    pub fn active(&self) -> Vec<Grant> {
        let now = (self.clock)();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|g| g.until > now);
        entries.clone()
    }
}

/// The grant a fetch approval can include: the requesting device and the
/// requested file's folder. Accepting it starts the 10 minutes.
#[derive(Clone)]
pub struct GrantOffer {
    grants: Arc<Grants>,
    pub peer_id: String,
    pub folder: PathBuf,
}

impl GrantOffer {
    pub fn new(grants: Arc<Grants>, peer_id: String, folder: PathBuf) -> Self {
        Self {
            grants,
            peer_id,
            folder,
        }
    }

    /// Give the grant.
    pub fn accept(&self) -> Grant {
        self.grants
            .allow(&self.peer_id, &self.folder, GRANT_DURATION)
    }
}

impl std::fmt::Debug for GrantOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantOffer")
            .field("peer_id", &self.peer_id)
            .field("folder", &self.folder)
            .finish()
    }
}

impl PartialEq for GrantOffer {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id && self.folder == other.folder
    }
}

impl Eq for GrantOffer {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Grants on a clock that only moves when told to.
    fn fake() -> (Arc<Grants>, Arc<AtomicU64>) {
        let start = Instant::now();
        let minutes = Arc::new(AtomicU64::new(0));
        let now = Arc::clone(&minutes);
        let grants = Grants::with_clock(Box::new(move || {
            start + Duration::from_secs(60 * now.load(Ordering::SeqCst))
        }));
        (Arc::new(grants), minutes)
    }

    #[test]
    fn a_grant_covers_its_folder_until_it_runs_out() {
        let (grants, minutes) = fake();
        let a = Path::new("/share/A");
        GrantOffer::new(Arc::clone(&grants), "pc".into(), a.into()).accept();
        minutes.store(9, Ordering::SeqCst);
        assert!(grants.covers("pc", &a.join("report.pdf")));
        assert!(grants.covers("pc", &a.join("2026/q3.pdf")));
        minutes.store(11, Ordering::SeqCst);
        assert!(!grants.covers("pc", &a.join("report.pdf")));
        assert!(grants.active().is_empty());
    }

    #[test]
    fn a_grant_covers_only_its_folder_and_device() {
        let (grants, _) = fake();
        grants.allow("pc", Path::new("/share/A"), GRANT_DURATION);
        assert!(!grants.covers("pc", Path::new("/share/B/report.pdf")));
        assert!(!grants.covers("pc", Path::new("/share/AB/report.pdf")));
        assert!(!grants.covers("pc", Path::new("/share/report.pdf")));
        assert!(!grants.covers("pc", Path::new("/share/A")));
        assert!(!grants.covers("laptop", Path::new("/share/A/report.pdf")));
    }

    #[test]
    fn granting_again_restarts_the_clock() {
        let (grants, minutes) = fake();
        let a = Path::new("/share/A");
        grants.allow("pc", a, GRANT_DURATION);
        minutes.store(8, Ordering::SeqCst);
        grants.allow("pc", a, GRANT_DURATION);
        minutes.store(15, Ordering::SeqCst);
        assert!(grants.covers("pc", &a.join("x")));
        assert_eq!(grants.active().len(), 1);
    }
}
