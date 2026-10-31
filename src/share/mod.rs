//! What this device shares with paired devices: an allowlist of folders and
//! files, nothing by default.
//!
//! Shared roots live in `shares.json` in the config dir, next to a random
//! key. Each shared file gets an opaque id, an HMAC of its canonical path
//! under that key, so peers never see or send paths. A request names an id;
//! the id is honoured only if listing the shares right now produces it,
//! which rules out everything else in one place: paths (relative or
//! absolute), files outside a root (including through symlinks), hidden
//! files, the download folder, and files whose root was unshared.

use crate::identity::random_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub const SHARES_FILE: &str = "shares.json";

/// Folders deeper than this under a root are not listed.
pub const MAX_DEPTH: usize = 32;

/// At most this many files are listed across all roots.
pub const MAX_FILES: usize = 100_000;

/// A file a peer may ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFile {
    pub file_id: String,
    /// Bare file name.
    pub name: String,
    /// Where it sits in the share, e.g. `Reports/2026/q3.pdf` (the root's
    /// own name first), with `/` separators on every OS.
    pub path: String,
    pub size: u64,
    /// Last modified, Unix seconds.
    pub modified: u64,
}

/// A shared file resolved from its id, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub file: SharedFile,
    /// Canonical path on disk.
    pub disk_path: PathBuf,
}

#[derive(Debug)]
pub enum ShareError {
    Io(io::Error),
    /// The id doesn't name a currently shared file.
    NotShared,
    /// `shares.json` is damaged.
    Damaged(String),
    /// The path can't be shared (e.g. it is inside the download folder).
    Refused(String),
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::NotShared => write!(f, "that file is not shared"),
            Self::Damaged(reason) => write!(f, "{SHARES_FILE} is damaged: {reason}"),
            Self::Refused(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ShareError {}

impl From<io::Error> for ShareError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SharesFile {
    version: u32,
    /// Hex; created with the first share.
    key: String,
    roots: Vec<PathBuf>,
}

/// The share allowlist for one config dir. Every call reads `shares.json`
/// afresh, so `opendrop share add/remove` take effect in a running daemon
/// right away.
#[derive(Debug, Clone)]
pub struct Shares {
    config_dir: PathBuf,
    download_dir: Option<PathBuf>,
}

impl Shares {
    /// `download_dir` (where received files land) is never listed, even
    /// inside a shared folder.
    pub fn new(config_dir: &Path, download_dir: Option<&Path>) -> Self {
        Self {
            config_dir: config_dir.to_owned(),
            download_dir: download_dir.map(Path::to_owned),
        }
    }

    fn file_path(&self) -> PathBuf {
        self.config_dir.join(SHARES_FILE)
    }

    fn load(&self) -> Result<SharesFile, ShareError> {
        match std::fs::read(self.file_path()) {
            Ok(bytes) => {
                let file: SharesFile = serde_json::from_slice(&bytes)
                    .map_err(|e| ShareError::Damaged(e.to_string()))?;
                if file.version != 1 {
                    return Err(ShareError::Damaged(format!(
                        "unknown version {}",
                        file.version
                    )));
                }
                if decode_key(&file.key).is_none() {
                    return Err(ShareError::Damaged("bad key".into()));
                }
                Ok(file)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(SharesFile {
                version: 1,
                key: crate::transfer::hex(&random_bytes()),
                roots: Vec::new(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, file: &SharesFile) -> Result<(), ShareError> {
        std::fs::create_dir_all(&self.config_dir)?;
        let json = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
        let tmp = self.config_dir.join(format!("{SHARES_FILE}.tmp"));
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, self.file_path())?;
        Ok(())
    }

    /// Shared roots, as canonical paths.
    pub fn roots(&self) -> Result<Vec<PathBuf>, ShareError> {
        Ok(self.load()?.roots)
    }

    /// Share a folder or file. Returns its canonical path.
    pub fn add(&self, path: &Path) -> Result<PathBuf, ShareError> {
        let root = path
            .canonicalize()
            .map_err(|e| ShareError::Refused(format!("cannot share {}: {e}", path.display())))?;
        if let Some(downloads) = self.canonical_download_dir()
            && root.starts_with(&downloads)
        {
            return Err(ShareError::Refused(format!(
                "{} is in the download folder, which is never shared",
                path.display()
            )));
        }
        let mut file = self.load()?;
        if !file.roots.contains(&root) {
            file.roots.push(root.clone());
            self.save(&file)?;
        }
        Ok(root)
    }

    /// Stop sharing a root, named as it was added. Returns whether it was
    /// shared. Ids of its files stop working at once.
    pub fn remove(&self, path: &Path) -> Result<bool, ShareError> {
        let mut file = self.load()?;
        let canonical = path.canonicalize().ok();
        let before = file.roots.len();
        file.roots
            .retain(|r| r != path && Some(r) != canonical.as_ref());
        if file.roots.len() == before {
            return Ok(false);
        }
        self.save(&file)?;
        Ok(true)
    }

    /// Every shared file whose path contains `query` (ignoring case), sorted
    /// by path.
    pub fn list(&self, query: Option<&str>) -> Result<Vec<SharedFile>, ShareError> {
        Ok(self
            .walk()?
            .into_iter()
            .map(|r| r.file)
            .filter(|f| query.is_none_or(|q| f.path.to_lowercase().contains(&q.to_lowercase())))
            .collect())
    }

    /// The shared file with this id, or `NotShared`.
    pub fn resolve(&self, file_id: &str) -> Result<Resolved, ShareError> {
        // Ids are fixed-length hex; anything else (a path, say) can't match.
        if !is_file_id(file_id) {
            return Err(ShareError::NotShared);
        }
        self.walk()?
            .into_iter()
            .find(|r| r.file.file_id == file_id)
            .ok_or(ShareError::NotShared)
    }

    /// The id this device gives the file at canonical path `path`, whether
    /// or not it is shared. For tests and diagnostics.
    pub fn file_id_for(&self, path: &Path) -> Result<String, ShareError> {
        let key = decode_key(&self.load()?.key).expect("checked on load");
        Ok(file_id(&key, path))
    }

    fn canonical_download_dir(&self) -> Option<PathBuf> {
        self.download_dir.as_ref()?.canonicalize().ok()
    }

    fn walk(&self) -> Result<Vec<Resolved>, ShareError> {
        let file = self.load()?;
        let key = decode_key(&file.key).expect("checked on load");
        let downloads = self.canonical_download_dir();
        let mut out = Vec::new();
        for root in &file.roots {
            // A root that has since been deleted or moved shares nothing.
            let Ok(meta) = std::fs::metadata(root) else {
                continue;
            };
            let label = root.file_name().map_or_else(
                || root.display().to_string(),
                |n| n.to_string_lossy().into(),
            );
            let mut walker = Walker {
                key: &key,
                root,
                downloads: downloads.as_deref(),
                out: &mut out,
            };
            if meta.is_file() {
                walker.file(root, &label);
            } else {
                walker.dir(root, &label, 0);
            }
        }
        // A file reachable twice (a symlink to it, or overlapping roots) is
        // listed once, under its own name where possible.
        let via_link = |r: &Resolved| {
            r.disk_path.file_name().map(|n| n.to_string_lossy())
                != Some(r.file.name.as_str().into())
        };
        out.sort_by(|a, b| {
            (&a.file.file_id, via_link(a), &a.file.path).cmp(&(
                &b.file.file_id,
                via_link(b),
                &b.file.path,
            ))
        });
        out.dedup_by(|a, b| a.file.file_id == b.file.file_id);
        out.sort_by(|a, b| a.file.path.cmp(&b.file.path));
        Ok(out)
    }
}

struct Walker<'a> {
    key: &'a [u8; 32],
    root: &'a Path,
    downloads: Option<&'a Path>,
    out: &'a mut Vec<Resolved>,
}

impl Walker<'_> {
    fn dir(&mut self, dir: &Path, label: &str, depth: usize) {
        if depth > MAX_DEPTH || self.downloads.is_some_and(|d| dir.starts_with(d)) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if self.out.len() >= MAX_FILES {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if is_hidden(&name, &path) {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let child = format!("{label}/{name}");
            if kind.is_dir() {
                self.dir(&path, &child, depth + 1);
            } else if kind.is_file() || kind.is_symlink() {
                // Symlinks count only if they point at a regular file inside
                // the root; links to folders are skipped (no cycles).
                self.file(&path, &child);
            }
        }
    }

    fn file(&mut self, path: &Path, label: &str) {
        let Ok(canonical) = path.canonicalize() else {
            return;
        };
        if !canonical.starts_with(self.root)
            || self.downloads.is_some_and(|d| canonical.starts_with(d))
        {
            return;
        }
        let Ok(meta) = std::fs::metadata(&canonical) else {
            return;
        };
        let name = label.rsplit('/').next().unwrap_or(label).to_owned();
        if !meta.is_file() || is_hidden(&name, &canonical) {
            return;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        self.out.push(Resolved {
            file: SharedFile {
                file_id: file_id(self.key, &canonical),
                name,
                path: label.to_owned(),
                size: meta.len(),
                modified,
            },
            disk_path: canonical,
        });
    }
}

/// Dot files, and on Windows files with the hidden attribute.
fn is_hidden(name: &str, path: &Path) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            return meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0;
        }
    }
    let _ = path;
    false
}

fn decode_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

const ID_PREFIX: &str = "f_";
const ID_HEX_LEN: usize = 32;

fn is_file_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX).is_some_and(|hex| {
        hex.len() == ID_HEX_LEN && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// `f_` + the first 128 bits of HMAC-SHA256(key, canonical path), in hex.
fn file_id(key: &[u8; 32], path: &Path) -> String {
    let mac = hmac_sha256(key, path.as_os_str().as_encoded_bytes());
    format!("{ID_PREFIX}{}", &crate::transfer::hex(&mac)[..ID_HEX_LEN])
}

/// HMAC-SHA256 (RFC 2104) for a key shorter than the block size.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(key);
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests;
