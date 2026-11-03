//! File transfer engine: chunked streaming, temp files, verification.
//!
//! The sender streams a file in [`CHUNK_SIZE`] pieces, hashing as it goes.
//! The receiver writes the bytes to a hidden temp file in the destination
//! folder, hashing them too, and only moves the file into place once both
//! hashes match. An interrupted or corrupted transfer leaves nothing behind.

use crate::network::IO_TIMEOUT;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// Bytes read and written per step.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Longest file name we accept, in bytes (the common filesystem limit).
pub const MAX_NAME_LEN: usize = 255;

/// Turn a peer-supplied name into a safe bare file name, or `None` if
/// nothing usable is left.
///
/// Directory parts are dropped, so a name can never escape the destination
/// folder, and characters Windows forbids become `_`.
pub fn sanitize_file_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = base
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Windows also drops trailing dots and spaces, which would turn "..."
    // into an empty name there.
    let cleaned = cleaned.trim().trim_end_matches('.').trim_end();
    if cleaned.is_empty() || cleaned.len() > MAX_NAME_LEN {
        return None;
    }
    Some(cleaned.to_owned())
}

/// Copy exactly `size` bytes from `reader` to `writer` and return their
/// SHA-256 in lowercase hex. `progress` gets the running byte count.
///
/// Each read and write must make progress within [`IO_TIMEOUT`], so a
/// stalled peer can't hang the transfer.
pub async fn copy_hashed<R, W>(
    reader: &mut R,
    writer: &mut W,
    size: u64,
    progress: &mut (dyn FnMut(u64) + Send),
) -> io::Result<String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut hasher = Sha256::new();
    let mut done = 0u64;
    while done < size {
        let want = (size - done).min(CHUNK_SIZE as u64) as usize;
        let n = timeout(IO_TIMEOUT, reader.read(&mut buf[..want]))
            .await
            .map_err(|_| timed_out("reading"))??;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("stream ended after {done} of {size} bytes"),
            ));
        }
        hasher.update(&buf[..n]);
        timeout(IO_TIMEOUT, writer.write_all(&buf[..n]))
            .await
            .map_err(|_| timed_out("writing"))??;
        done += n as u64;
        progress(done);
    }
    timeout(IO_TIMEOUT, writer.flush())
        .await
        .map_err(|_| timed_out("flushing"))??;
    Ok(hex(&hasher.finalize()))
}

/// SHA-256 of `bytes` in lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A file being received: a hidden temp file in the destination folder
/// that is deleted on drop unless [`PartFile::persist`] moves it into place.
pub struct PartFile {
    path: PathBuf,
    file: Option<File>,
    kept: bool,
}

impl PartFile {
    /// Create a new temp file in `dir`, creating `dir` if needed.
    pub async fn create(dir: &Path) -> io::Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        for attempt in 0..100 {
            let path = dir.join(format!(".opendrop-{stamp:x}-{attempt}.part"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await
            {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        kept: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a temp file",
        ))
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file is open until persisted")
    }

    /// Give up on the file: finish any pending write, close it and delete
    /// it.
    pub async fn discard(mut self) {
        if let Some(mut file) = self.file.take() {
            use tokio::io::AsyncWriteExt;
            let _ = file.flush().await;
        }
    }

    /// Flush to disk and move into `dir` as `name`, or `name (1)`,
    /// `name (2)`, ... if that's taken. Returns where the file ended up.
    pub async fn persist(mut self, dir: &Path, name: &str) -> io::Result<PathBuf> {
        if let Some(file) = self.file.take() {
            file.sync_all().await?;
        }
        let dest = free_path(dir, name).await?;
        tokio::fs::rename(&self.path, &dest).await?;
        self.kept = true;
        Ok(dest)
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.kept {
            // Close first: Windows won't delete a file that is still open.
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The first of `name`, `stem (1).ext`, `stem (2).ext`, ... not taken in `dir`.
async fn free_path(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let candidate = dir.join(name);
    if !tokio::fs::try_exists(&candidate).await? {
        return Ok(candidate);
    }
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    for n in 1..10_000 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !tokio::fs::try_exists(&candidate).await? {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("too many files named {name}"),
    ))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("peer stalled while {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_ordinary_names() {
        assert_eq!(
            sanitize_file_name("photo.jpg").as_deref(),
            Some("photo.jpg")
        );
        assert_eq!(
            sanitize_file_name("Résumé 2026.pdf").as_deref(),
            Some("Résumé 2026.pdf")
        );
        assert_eq!(sanitize_file_name(".bashrc").as_deref(), Some(".bashrc"));
    }

    #[test]
    fn sanitize_strips_paths_and_bad_characters() {
        assert_eq!(
            sanitize_file_name("../../etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            sanitize_file_name("C:\\Users\\x\\a.txt").as_deref(),
            Some("a.txt")
        );
        assert_eq!(
            sanitize_file_name("what?.txt").as_deref(),
            Some("what_.txt")
        );
        assert_eq!(sanitize_file_name("tab\there").as_deref(), Some("tab_here"));
        assert_eq!(sanitize_file_name("notes. ").as_deref(), Some("notes"));
    }

    #[test]
    fn sanitize_rejects_unusable_names() {
        for bad in ["", " ", ".", "..", "...", "dir/", "a/..", &"x".repeat(256)] {
            assert_eq!(sanitize_file_name(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn copy_hashed_copies_and_hashes() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 3 + 17).map(|i| i as u8).collect();
        let mut out = Vec::new();
        let mut seen = Vec::new();
        let hash = copy_hashed(&mut &data[..], &mut out, data.len() as u64, &mut |n| {
            seen.push(n)
        })
        .await
        .unwrap();
        assert_eq!(out, data);
        assert_eq!(hash, sha256_hex(&data));
        assert_eq!(seen.last(), Some(&(data.len() as u64)));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn copy_hashed_stops_at_size_and_fails_when_short() {
        let mut out = Vec::new();
        copy_hashed(&mut &b"hello world"[..], &mut out, 5, &mut |_| {})
            .await
            .unwrap();
        assert_eq!(out, b"hello");

        let err = copy_hashed(&mut &b"hi"[..], &mut Vec::new(), 5, &mut |_| {})
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn part_file_is_removed_unless_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let mut part = PartFile::create(dir.path()).await.unwrap();
        part.file().write_all(b"partial").await.unwrap();
        drop(part);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn persist_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let mut saved = Vec::new();
        for body in ["one", "two", "three"] {
            let mut part = PartFile::create(dir.path()).await.unwrap();
            part.file().write_all(body.as_bytes()).await.unwrap();
            saved.push(part.persist(dir.path(), "notes.txt").await.unwrap());
        }
        let names: Vec<_> = saved
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["notes.txt", "notes (1).txt", "notes (2).txt"]);
        assert_eq!(std::fs::read_to_string(&saved[2]).unwrap(), "three");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }
}
