//! Standing access over the relay: "always let this assistant (or this
//! device) fetch from this device without asking".
//!
//! The first request from a requester is approved on this device; the
//! person can then give it standing access, kept in `relay-access.json` in
//! the config folder until they revoke it (`opendrop relay revoke`). Every
//! call reads the file afresh, so a revoke takes effect in a running daemon
//! at once. OpenDrop's own config folder is never served, granted or not.

use super::proto::{Requester, RequesterKind};
use crate::network::BoxError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const ACCESS_FILE: &str = "relay-access.json";

/// One requester with standing access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
    /// The requester's id (`device:…`, `oauth:…`, `token:…`).
    pub id: String,
    pub kind: RequesterKind,
    pub name: String,
    /// When it was given, in milliseconds since the Unix epoch.
    pub granted_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AccessFile {
    version: u32,
    grants: Vec<Standing>,
}

/// The standing access this device has given, stored in a config folder.
#[derive(Debug)]
pub struct Access {
    path: PathBuf,
    /// Serializes read-modify-write within this process.
    write: Mutex<()>,
}

impl Access {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            path: config_dir.join(ACCESS_FILE),
            write: Mutex::new(()),
        }
    }

    fn load(&self) -> Result<AccessFile, BoxError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let file: AccessFile = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{} is damaged: {e}", self.path.display()))?;
                Ok(file)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AccessFile {
                version: 1,
                grants: Vec::new(),
            }),
            Err(e) => Err(format!("cannot read {}: {e}", self.path.display()).into()),
        }
    }

    fn save(&self, file: &AccessFile) -> Result<(), BoxError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Who has standing access.
    pub fn list(&self) -> Result<Vec<Standing>, BoxError> {
        Ok(self.load()?.grants)
    }

    /// Whether `requester_id` has standing access. A damaged file grants
    /// nothing.
    pub fn allows(&self, requester_id: &str) -> bool {
        self.load()
            .map(|f| f.grants.iter().any(|g| g.id == requester_id))
            .unwrap_or(false)
    }

    /// Give `requester` standing access (again, if it had it).
    pub fn grant(&self, requester: &Requester) -> Result<Standing, BoxError> {
        let _guard = self.write.lock().unwrap();
        let mut file = self.load()?;
        file.version = 1;
        file.grants.retain(|g| g.id != requester.id);
        let standing = Standing {
            id: requester.id.clone(),
            kind: requester.kind,
            name: requester.name.clone(),
            granted_ms: now_ms(),
        };
        file.grants.push(standing.clone());
        self.save(&file)?;
        Ok(standing)
    }

    /// Take standing access away from whoever `query` names (an id, or a
    /// name ignoring case); `all` takes it from everyone. Returns who lost it.
    pub fn revoke(&self, query: &str) -> Result<Vec<Standing>, BoxError> {
        let _guard = self.write.lock().unwrap();
        let mut file = self.load()?;
        let matches = |g: &Standing| {
            query == "all" || g.id == query || crate::discovery::same_name(&g.name, query)
        };
        let (gone, kept): (Vec<_>, Vec<_>) = file.grants.into_iter().partition(matches);
        file.grants = kept;
        if !gone.is_empty() {
            self.save(&file)?;
        }
        Ok(gone)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Largest file sent over the relay (the relay's own limit).
pub const MAX_RELAY_FILE: u64 = 25 * 1024 * 1024;

/// Why a path can't be served over the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRefusal {
    NotFound(String),
    Refused(String),
}

impl std::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(m) | Self::Refused(m) => write!(f, "{m}"),
        }
    }
}

/// The user's home folder, where relative paths and `~` start.
pub fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

/// `path` as typed by a requester (absolute, `~/…`, or relative to home),
/// resolved to a canonical path on this device, unless it is inside
/// OpenDrop's config folder.
pub fn resolve(config_dir: &Path, path: &str) -> Result<PathBuf, PathRefusal> {
    let trimmed = path.trim();
    let raw = if trimmed.is_empty() || trimmed == "~" {
        home()
    } else if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        home().join(rest)
    } else if Path::new(trimmed).is_absolute() {
        PathBuf::from(trimmed)
    } else {
        home().join(trimmed)
    };
    let canonical = raw
        .canonicalize()
        .map_err(|_| PathRefusal::NotFound(format!("nothing at {}", raw.display())))?;
    if is_private(config_dir, &canonical) {
        return Err(PathRefusal::Refused(
            "OpenDrop's own settings and keys can't be fetched".into(),
        ));
    }
    Ok(canonical)
}

/// Whether `canonical` is inside OpenDrop's config folder (its keys,
/// sign-ins and settings), which is never served.
pub fn is_private(config_dir: &Path, canonical: &Path) -> bool {
    let config = config_dir
        .canonicalize()
        .unwrap_or_else(|_| config_dir.to_owned());
    canonical.starts_with(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requester(id: &str, name: &str) -> Requester {
        Requester {
            kind: RequesterKind::Assistant,
            id: id.into(),
            name: name.into(),
        }
    }

    #[test]
    fn standing_access_is_kept_until_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let access = Access::new(dir.path());
        assert!(!access.allows("oauth:a"));
        access.grant(&requester("oauth:a", "Claude")).unwrap();
        access.grant(&requester("oauth:b", "ChatGPT")).unwrap();
        access.grant(&requester("oauth:a", "Claude")).unwrap();
        assert_eq!(access.list().unwrap().len(), 2);
        // Another handle on the same folder (a running daemon) sees it.
        assert!(Access::new(dir.path()).allows("oauth:a"));
        let gone = access.revoke("claude").unwrap();
        assert_eq!(gone.len(), 1);
        assert!(!access.allows("oauth:a"));
        assert!(access.allows("oauth:b"));
        assert_eq!(access.revoke("all").unwrap().len(), 1);
        assert!(access.list().unwrap().is_empty());
    }

    #[test]
    fn a_damaged_file_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ACCESS_FILE), b"{not json").unwrap();
        assert!(!Access::new(dir.path()).allows("oauth:a"));
    }

    #[test]
    fn the_config_folder_is_never_served() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("OpenDrop");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("identity.json"), b"secret").unwrap();
        std::fs::write(root.path().join("notes.txt"), b"hi").unwrap();
        let ok = resolve(
            &config,
            &root.path().join("notes.txt").display().to_string(),
        );
        assert!(ok.is_ok());
        for sneaky in [
            config.join("identity.json").display().to_string(),
            root.path()
                .join("OpenDrop/../OpenDrop/identity.json")
                .display()
                .to_string(),
            config.display().to_string(),
        ] {
            assert!(
                matches!(resolve(&config, &sneaky), Err(PathRefusal::Refused(_))),
                "{sneaky} was served"
            );
        }
        assert!(matches!(
            resolve(&config, "/definitely/not/here.txt"),
            Err(PathRefusal::NotFound(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_into_the_config_folder_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("OpenDrop");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("relay.json"), b"session").unwrap();
        let link = root.path().join("innocent.txt");
        std::os::unix::fs::symlink(config.join("relay.json"), &link).unwrap();
        assert!(matches!(
            resolve(&config, &link.display().to_string()),
            Err(PathRefusal::Refused(_))
        ));
    }
}
