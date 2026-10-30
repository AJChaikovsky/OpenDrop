//! Devices this one has paired with, kept in `paired-devices.json` in the
//! config folder.
//!
//! Every connection checks the peer's key against this store: a device id we
//! paired with must come with the same public key, or it is an impostor.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// File in the config folder listing paired devices.
pub const STORE_FILE: &str = "paired-devices.json";

/// A device we paired with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDevice {
    pub id: String,
    pub name: String,
    #[serde(with = "crate::protocol::hex_array")]
    pub public_key: [u8; 32],
    /// Seconds since the Unix epoch.
    pub paired_at: u64,
}

impl PairedDevice {
    pub fn new(id: String, name: String, public_key: [u8; 32]) -> Self {
        let paired_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        Self {
            id,
            name,
            public_key,
            paired_at,
        }
    }
}

/// What the store says about a device that introduced itself with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Paired, and it presented the key we paired with.
    Paired,
    /// Not paired.
    Unknown,
    /// We paired with this id under a different key.
    Mismatch,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    devices: Vec<PairedDevice>,
}

/// The store could not be read.
#[derive(Debug)]
pub struct StoreError {
    pub path: PathBuf,
    pub reason: String,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "paired devices file {} is unreadable ({}); fix or delete it to pair again",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for StoreError {}

/// Paired devices, shared by the server, the client and the UI. Changes are
/// written to disk right away (unless the store is in-memory) and announced
/// to subscribers.
#[derive(Debug)]
pub struct PairedDevices {
    path: Option<PathBuf>,
    devices: Mutex<BTreeMap<String, PairedDevice>>,
    changes: broadcast::Sender<()>,
}

impl Default for PairedDevices {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl PairedDevices {
    /// An empty store that is never saved.
    pub fn in_memory() -> Self {
        Self::with(None, BTreeMap::new())
    }

    /// Load `paired-devices.json` from `config_dir`. A missing file is an
    /// empty store; a damaged one is an error (and is left untouched).
    pub fn load(config_dir: &Path) -> Result<Self, StoreError> {
        let path = config_dir.join(STORE_FILE);
        let error = |reason: String| StoreError {
            path: path.clone(),
            reason,
        };
        let devices = match std::fs::read(&path) {
            Ok(bytes) => {
                let file: StoreFile =
                    serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
                if file.version != 1 {
                    return Err(error(format!("unknown version {}", file.version)));
                }
                file.devices
                    .into_iter()
                    .map(|d| (d.id.clone(), d))
                    .collect()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(error(e.to_string())),
        };
        Ok(Self::with(Some(path), devices))
    }

    fn with(path: Option<PathBuf>, devices: BTreeMap<String, PairedDevice>) -> Self {
        Self {
            path,
            devices: Mutex::new(devices),
            changes: broadcast::channel(16).0,
        }
    }

    pub fn get(&self, id: &str) -> Option<PairedDevice> {
        self.devices.lock().unwrap().get(id).cloned()
    }

    /// Paired devices, sorted by id.
    pub fn list(&self) -> Vec<PairedDevice> {
        self.devices.lock().unwrap().values().cloned().collect()
    }

    pub fn check(&self, id: &str, public_key: &[u8; 32]) -> Trust {
        match self.devices.lock().unwrap().get(id) {
            None => Trust::Unknown,
            Some(d) if d.public_key == *public_key => Trust::Paired,
            Some(_) => Trust::Mismatch,
        }
    }

    /// Add or replace a paired device.
    pub fn insert(&self, device: PairedDevice) -> io::Result<()> {
        let mut devices = self.devices.lock().unwrap();
        devices.insert(device.id.clone(), device);
        self.save(&devices)?;
        drop(devices);
        let _ = self.changes.send(());
        Ok(())
    }

    /// Forget a device. Returns whether it was paired.
    pub fn remove(&self, id: &str) -> io::Result<bool> {
        let mut devices = self.devices.lock().unwrap();
        if devices.remove(id).is_none() {
            return Ok(false);
        }
        self.save(&devices)?;
        drop(devices);
        let _ = self.changes.send(());
        Ok(true)
    }

    /// Hear about every insert and remove from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.changes.subscribe()
    }

    /// Write the whole store to a temp file, then rename it over the old
    /// one, so a crash mid-write never leaves a half-written file.
    fn save(&self, devices: &BTreeMap<String, PairedDevice>) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = StoreFile {
            version: 1,
            devices: devices.values().cloned().collect(),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, key: u8) -> PairedDevice {
        PairedDevice::new(id.into(), format!("Device {id}"), [key; 32])
    }

    #[test]
    fn check_compares_the_full_key() {
        let store = PairedDevices::in_memory();
        store.insert(device("device-a", 1)).unwrap();
        assert_eq!(store.check("device-a", &[1; 32]), Trust::Paired);
        assert_eq!(store.check("device-a", &[2; 32]), Trust::Mismatch);
        assert_eq!(store.check("device-b", &[1; 32]), Trust::Unknown);
    }

    #[test]
    fn changes_are_saved_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let store = PairedDevices::load(dir.path()).unwrap();
        assert!(store.list().is_empty());
        store.insert(device("device-a", 1)).unwrap();
        store.insert(device("device-b", 2)).unwrap();
        let reloaded = PairedDevices::load(dir.path()).unwrap();
        assert_eq!(reloaded.list(), store.list());
        assert!(reloaded.remove("device-a").unwrap());
        assert!(!reloaded.remove("device-a").unwrap());
        let ids: Vec<String> = PairedDevices::load(dir.path())
            .unwrap()
            .list()
            .into_iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(ids, ["device-b"]);
    }

    #[test]
    fn a_damaged_file_is_reported_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STORE_FILE);
        for garbage in [&b"\x00\x01not json"[..], br#"{"version":9,"devices":[]}"#] {
            std::fs::write(&path, garbage).unwrap();
            let err = PairedDevices::load(dir.path()).unwrap_err();
            let shown = err.to_string();
            assert!(shown.contains(STORE_FILE), "{shown}");
            assert!(shown.contains("fix or delete"), "{shown}");
            assert_eq!(std::fs::read(&path).unwrap(), garbage);
        }
    }

    #[test]
    fn subscribers_hear_about_changes() {
        let store = PairedDevices::in_memory();
        let mut changes = store.subscribe();
        store.insert(device("device-a", 1)).unwrap();
        assert!(changes.try_recv().is_ok());
        assert!(!store.remove("device-x").unwrap());
        assert!(changes.try_recv().is_err());
        store.remove("device-a").unwrap();
        assert!(changes.try_recv().is_ok());
    }
}
