//! Folders as one transfer (issue #34): listing a folder to send, checking
//! the relative paths a peer offers, and the staging folder that becomes
//! the received folder only once every file has arrived intact.

use super::{MAX_NAME_LEN, free_path, hex, sanitize_file_name};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Most files one folder transfer may hold.
pub const MAX_FOLDER_FILES: usize = 100_000;
/// Deepest nesting accepted, in path components.
pub const MAX_DEPTH: usize = 64;
/// Longest relative path accepted, in bytes.
pub const MAX_PATH_LEN: usize = 1024;

/// One file in a folder transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderEntry {
    /// Relative to the folder, components separated by `/`.
    pub path: String,
    pub size: u64,
}

/// Turn a peer-supplied relative path into one that stays inside the
/// destination, or `None`. Rejected: absolute paths, drive letters and UNC
/// prefixes, `..` and `.`, empty components, backslashes, and components
/// that aren't already safe file names (see [`sanitize_file_name`]).
pub fn safe_relative_path(path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains(['\\', ':', '\0']) {
        return None;
    }
    let mut out = PathBuf::new();
    let mut depth = 0;
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        if sanitize_file_name(component).as_deref() != Some(component) {
            return None;
        }
        if is_reserved_on_windows(component) {
            return None;
        }
        depth += 1;
        if depth > MAX_DEPTH {
            return None;
        }
        out.push(component);
    }
    Some(out)
}

/// `CON`, `NUL`, `COM1`… (with or without an extension) can't be created as
/// files on Windows.
fn is_reserved_on_windows(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Check a whole offered listing: every path safe, no two the same (ignoring
/// case, since the receiver's disk may not care), no file that is also
/// another's folder, and within the limits. Returns the paths in order.
pub fn check_listing(entries: &[FolderEntry]) -> Result<Vec<PathBuf>, String> {
    if entries.is_empty() {
        return Err("the folder is empty".into());
    }
    if entries.len() > MAX_FOLDER_FILES {
        return Err(format!("more than {MAX_FOLDER_FILES} files"));
    }
    let mut files = HashSet::new();
    let mut paths = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = safe_relative_path(&entry.path)
            .ok_or_else(|| format!("unsafe path {:?} in the folder", entry.path))?;
        if !files.insert(entry.path.to_lowercase()) {
            return Err(format!("{:?} appears twice", entry.path));
        }
        paths.push(path);
    }
    // "a/b" as a file and "a/b/c" as another file can't both exist.
    for entry in entries {
        let lower = entry.path.to_lowercase();
        let mut prefix = String::new();
        for component in lower
            .split('/')
            .collect::<Vec<_>>()
            .split_last()
            .map_or(&[][..], |(_, dirs)| dirs)
        {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if files.contains(&prefix) {
                return Err(format!("{prefix:?} is both a file and a folder"));
            }
        }
    }
    Ok(paths)
}

/// Every regular file under `root`, sorted, with paths relative to it.
/// Symbolic links are skipped (they could point anywhere).
pub fn list_folder(root: &Path) -> io::Result<Vec<(PathBuf, FolderEntry)>> {
    let mut out = Vec::new();
    walk(root, "", &mut out)?;
    out.sort_by(|a, b| a.1.path.cmp(&b.1.path));
    if out.len() > MAX_FOLDER_FILES {
        return Err(io::Error::other(format!(
            "{} has more than {MAX_FOLDER_FILES} files",
            root.display()
        )));
    }
    Ok(out)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<(PathBuf, FolderEntry)>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            io::Error::other(format!(
                "{} has a name that isn't UTF-8",
                entry.path().display()
            ))
        })?;
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if kind.is_dir() {
            walk(&entry.path(), &relative, out)?;
        } else if kind.is_file() {
            let size = entry.metadata()?.len();
            out.push((
                entry.path(),
                FolderEntry {
                    path: relative,
                    size,
                },
            ));
        }
        if out.len() > MAX_FOLDER_FILES {
            return Ok(());
        }
    }
    Ok(())
}

/// One SHA-256 for a whole folder: over each file's hash and path, in the
/// listing's order. Both sides compute it, so it's the folder's checksum.
pub fn tree_hash<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut hasher = Sha256::new();
    for (path, sha256) in files {
        hasher.update(sha256.as_bytes());
        hasher.update(b"  ");
        hasher.update(path.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

/// A folder being received: a hidden folder next to where it will end up,
/// deleted (with everything in it) unless [`Staging::persist`] moves it
/// into place.
pub struct Staging {
    path: PathBuf,
    kept: bool,
}

impl Staging {
    pub async fn create(dir: &Path) -> io::Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        for attempt in 0..100 {
            let path = dir.join(format!(".opendrop-{stamp:x}-{attempt}.partdir"));
            match tokio::fs::create_dir(&path).await {
                Ok(()) => return Ok(Self { path, kept: false }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a temp folder",
        ))
    }

    /// Create the file at `relative` (already checked) for writing.
    pub async fn create_file(&self, relative: &Path) -> io::Result<tokio::fs::File> {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
    }

    /// Move into `dir` as `name`, or `name (1)`… if taken.
    pub async fn persist(mut self, dir: &Path, name: &str) -> io::Result<PathBuf> {
        let dest = free_path(dir, name).await?;
        tokio::fs::rename(&self.path, &dest).await?;
        self.kept = true;
        Ok(dest)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// A folder name to save under: the offered one if it's a safe name.
pub fn folder_name(offered: &str) -> Option<String> {
    sanitize_file_name(offered).filter(|n| n.len() <= MAX_NAME_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance (#34): relative paths with `..`, absolute paths or drive
    /// letters are rejected.
    #[test]
    fn unsafe_relative_paths_are_rejected() {
        for bad in [
            "",
            "..",
            "../evil.txt",
            "a/../../evil.txt",
            "a/./b.txt",
            "/etc/passwd",
            "//server/share/x",
            "C:/Windows/evil.dll",
            "C:evil.txt",
            "c:\\evil.txt",
            "\\\\server\\share\\x",
            "a\\..\\b",
            "a//b",
            "a/b/",
            "dir/CON",
            "nul.txt",
            "COM1.log",
            "a/b?.txt",
            "a/\0b",
            "a/ trailing-space ",
            "a/trailing-dot.",
        ] {
            assert_eq!(safe_relative_path(bad), None, "{bad:?}");
        }
        let deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert_eq!(safe_relative_path(&deep), None);
        for good in [
            "a.txt",
            "Photos/2026/IMG_0001.jpg",
            ".hidden/config",
            "a b/c-d_e (1).txt",
            "Ünïcødé/文件.txt",
            "COM10.txt",
            "console.log",
        ] {
            let path = safe_relative_path(good).unwrap_or_else(|| panic!("{good:?}"));
            assert_eq!(
                path.components().count(),
                good.split('/').count(),
                "{good:?}"
            );
            assert!(path.is_relative());
        }
    }

    #[test]
    fn listings_with_duplicates_or_clashes_are_rejected() {
        let entry = |path: &str| FolderEntry {
            path: path.into(),
            size: 1,
        };
        assert!(check_listing(&[entry("a.txt"), entry("b/c.txt")]).is_ok());
        assert!(check_listing(&[]).is_err());
        assert!(check_listing(&[entry("a.txt"), entry("A.TXT")]).is_err());
        assert!(check_listing(&[entry("a"), entry("a/b.txt")]).is_err());
        assert!(check_listing(&[entry("ok.txt"), entry("../x")]).is_err());
    }

    #[test]
    fn listing_skips_links_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("b/c")).unwrap();
        std::fs::write(dir.path().join("z.txt"), "z").unwrap();
        std::fs::write(dir.path().join("b/c/d.txt"), "dd").unwrap();
        std::fs::write(dir.path().join("b/a.txt"), "").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("b/link")).unwrap();
        let listed: Vec<(String, u64)> = list_folder(dir.path())
            .unwrap()
            .into_iter()
            .map(|(_, e)| (e.path, e.size))
            .collect();
        assert_eq!(
            listed,
            [
                ("b/a.txt".into(), 0),
                ("b/c/d.txt".into(), 2),
                ("z.txt".into(), 1)
            ]
        );
    }
}
