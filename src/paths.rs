//! Where things go on disk by default.

use std::path::{Path, PathBuf};

/// Where received files go when nothing else is configured: the platform's
/// Downloads folder if it has one, else `Downloads` in the home folder,
/// plus `OpenDrop`.
///
/// Linux machines without XDG user dirs (WSL, minimal installs) report no
/// Downloads folder, so the home folder is the fallback. Only with no home
/// folder at all is the path relative (`./OpenDrop`).
pub fn default_download_dir(platform_downloads: Option<PathBuf>, home: Option<&Path>) -> PathBuf {
    platform_downloads
        .or_else(|| home.map(|home| home.join("Downloads")))
        .unwrap_or_default()
        .join("OpenDrop")
}

/// The home folder from the environment: `HOME`, or `USERPROFILE` on Windows.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_the_platform_downloads_folder() {
        let dir = default_download_dir(Some("/x/Dl".into()), Some(Path::new("/home/a")));
        assert_eq!(dir, PathBuf::from("/x/Dl/OpenDrop"));
    }

    /// Issue found in the #40 Linux test: with no XDG Downloads folder the
    /// app saved into `./OpenDrop`, relative to wherever it was launched.
    #[test]
    fn falls_back_to_home_downloads_not_the_working_directory() {
        // An absolute home on every OS (`/home/a` isn't absolute on Windows).
        let home = std::env::temp_dir();
        let dir = default_download_dir(None, Some(&home));
        assert_eq!(dir, home.join("Downloads").join("OpenDrop"));
        assert!(dir.is_absolute());
    }

    #[test]
    fn relative_only_without_any_home() {
        assert_eq!(default_download_dir(None, None), PathBuf::from("OpenDrop"));
    }
}
