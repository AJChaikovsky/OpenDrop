//! The assistant inbox (stage B2): files a device sent to "My assistant",
//! waiting for the assistant to fetch them through the hosted MCP server.
//!
//! Each file is encrypted at rest with its own random key (ChaCha20-Poly1305);
//! that key is stored in the database wrapped with the relay's master key,
//! which lives in a separate file. A file is deleted the first time it's read,
//! or when it expires (24 hours), whichever comes first.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use std::path::{Path, PathBuf};

/// Largest file the inbox takes.
pub const MAX_FILE: u64 = 25 * 1024 * 1024;
/// Most an account may have waiting at once.
pub const ACCOUNT_QUOTA: u64 = 100 * 1024 * 1024;
/// How long a file waits before it's deleted unread.
pub const TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// One waiting file, as the assistant sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub inbox_id: String,
    pub account_id: i64,
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub sha256: String,
    pub from_device: String,
    pub sent_ms: u64,
    pub expires_ms: u64,
}

/// Seals and opens file contents, and keeps the sealed blobs on disk.
pub struct Blobs {
    dir: Option<PathBuf>,
    memory: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    master: ChaCha20Poly1305,
}

/// A sealed blob: nonce (12) + tag (16) + ciphertext.
fn seal(cipher: &ChaCha20Poly1305, aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce_bytes: [u8; 12] = opendrop::identity::random_bytes()[..12].try_into().unwrap();
    let nonce = Nonce::from(nonce_bytes);
    let mut body = plain.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, body.as_mut_slice().into())
        .expect("encryption can't fail for in-memory buffers");
    let mut out = Vec::with_capacity(28 + body.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(tag.as_slice());
    out.extend_from_slice(&body);
    out
}

fn open(cipher: &ChaCha20Poly1305, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 28 {
        return Err("sealed data is too short".into());
    }
    let nonce = Nonce::from(<[u8; 12]>::try_from(&sealed[..12]).unwrap());
    let tag = Tag::try_from(&sealed[12..28]).map_err(|_| "bad tag")?;
    let mut body = sealed[28..].to_vec();
    cipher
        .decrypt_inout_detached(&nonce, aad, body.as_mut_slice().into(), &tag)
        .map_err(|_| "sealed data failed authentication".to_owned())?;
    Ok(body)
}

impl Blobs {
    /// Blobs under `dir`, with the master key in `key_file` (created on
    /// first use, readable only by this user).
    pub fn open(dir: &Path, key_file: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let key = match std::fs::read(key_file) {
            Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| format!("{} is damaged", key_file.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = opendrop::identity::random_bytes();
                write_private(key_file, &key)
                    .map_err(|e| format!("cannot create {}: {e}", key_file.display()))?;
                key
            }
            Err(e) => return Err(format!("cannot read {}: {e}", key_file.display())),
        };
        Ok(Self {
            dir: Some(dir.to_owned()),
            memory: Default::default(),
            master: ChaCha20Poly1305::new(&key.into()),
        })
    }

    /// Blobs kept in memory (tests).
    pub fn in_memory() -> Self {
        Self {
            dir: None,
            memory: Default::default(),
            master: ChaCha20Poly1305::new(&opendrop::identity::random_bytes().into()),
        }
    }

    /// Encrypt `plain` with a fresh key and store it under `inbox_id`.
    /// Returns the file key, wrapped with the master key, for the database.
    pub fn put(&self, inbox_id: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
        let file_key = opendrop::identity::random_bytes();
        let sealed = seal(
            &ChaCha20Poly1305::new(&file_key.into()),
            inbox_id.as_bytes(),
            plain,
        );
        match &self.dir {
            Some(dir) => std::fs::write(dir.join(inbox_id), sealed)
                .map_err(|e| format!("cannot store the file: {e}"))?,
            None => {
                self.memory
                    .lock()
                    .unwrap()
                    .insert(inbox_id.to_owned(), sealed);
            }
        }
        Ok(seal(&self.master, inbox_id.as_bytes(), &file_key))
    }

    pub fn get(&self, inbox_id: &str, wrapped_key: &[u8]) -> Result<Vec<u8>, String> {
        let file_key: [u8; 32] = open(&self.master, inbox_id.as_bytes(), wrapped_key)?
            .try_into()
            .map_err(|_| "bad file key")?;
        let sealed = match &self.dir {
            Some(dir) => std::fs::read(dir.join(inbox_id))
                .map_err(|e| format!("cannot read the file: {e}"))?,
            None => self
                .memory
                .lock()
                .unwrap()
                .get(inbox_id)
                .cloned()
                .ok_or("the file is gone")?,
        };
        open(
            &ChaCha20Poly1305::new(&file_key.into()),
            inbox_id.as_bytes(),
            &sealed,
        )
    }

    pub fn delete(&self, inbox_id: &str) {
        match &self.dir {
            Some(dir) => {
                let _ = std::fs::remove_file(dir.join(inbox_id));
            }
            None => {
                self.memory.lock().unwrap().remove(inbox_id);
            }
        }
    }

    /// The raw sealed bytes (tests check that they aren't the plaintext).
    pub fn sealed(&self, inbox_id: &str) -> Option<Vec<u8>> {
        match &self.dir {
            Some(dir) => std::fs::read(dir.join(inbox_id)).ok(),
            None => self.memory.lock().unwrap().get(inbox_id).cloned(),
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// A MIME type from the file name, for how the assistant shows it.
pub fn mime_for(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "rs" | "py" | "js" | "ts" | "tsx" | "c" | "h" | "cpp" | "java" | "go" | "sh" | "toml"
        | "yaml" | "yml" | "css" | "sql" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_are_sealed_and_open_only_with_their_wrapped_key() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = Blobs::open(&dir.path().join("inbox"), &dir.path().join("relay.key")).unwrap();
        let plain = b"the secret plans".repeat(100);
        let wrapped = blobs.put("i1", &plain).unwrap();
        let sealed = blobs.sealed("i1").unwrap();
        assert!(
            !sealed.windows(16).any(|w| w == b"the secret plans"),
            "stored encrypted"
        );
        assert_eq!(blobs.get("i1", &wrapped).unwrap(), plain);
        // A key wrapped for another file doesn't open this one.
        let other = blobs.put("i2", b"x").unwrap();
        assert!(blobs.get("i1", &other).is_err());
        // The master key survives a restart.
        let again = Blobs::open(&dir.path().join("inbox"), &dir.path().join("relay.key")).unwrap();
        assert_eq!(again.get("i1", &wrapped).unwrap(), plain);
        blobs.delete("i1");
        assert!(blobs.get("i1", &wrapped).is_err());
    }

    #[test]
    fn mime_types_follow_the_extension() {
        assert_eq!(mime_for("notes.TXT"), "text/plain");
        assert_eq!(mime_for("photo.jpeg"), "image/jpeg");
        assert_eq!(mime_for("noext"), "application/octet-stream");
    }
}
