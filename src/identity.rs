//! Who this device is: an Ed25519 key pair kept in the config folder, and the
//! device id derived from its public key.
//!
//! The key is created on first start and reused from then on, so a device
//! keeps its id across restarts. Deleting the key file is the only thing
//! that gives a device a new id.

use crate::network::BoxError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// File in the config folder holding this device's private key.
pub const KEY_FILE: &str = "identity.key";

/// Hex digits of the public key's SHA-256 used in the device id: 64 bits,
/// enough that ids don't collide by accident. Trust decisions never rest on
/// the id alone; they compare the full public key.
const ID_HEX_LEN: usize = 16;

/// Who this device is, as announced to peers, plus the private key that
/// proves it.
#[derive(Clone)]
pub struct DeviceIdentity {
    /// `device-` followed by the start of the public key's fingerprint.
    pub id: String,
    pub name: String,
    key: SigningKey,
}

impl DeviceIdentity {
    /// An identity with a fresh, unsaved key: for tests and one-off tools.
    /// Real devices use [`DeviceIdentity::load_or_create`].
    pub fn new(name: impl Into<String>) -> Self {
        Self::from_key(SigningKey::from_bytes(&random_bytes()), name)
    }

    /// Load the key from `config_dir`, creating it (and the folder) on first
    /// use. A key file that exists but can't be read is an error, never
    /// silently replaced, since that would change the device's id.
    pub fn load_or_create(config_dir: &Path, name: impl Into<String>) -> Result<Self, BoxError> {
        let path = config_dir.join(KEY_FILE);
        let key = match std::fs::read(&path) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "{} is not an OpenDrop key ({} bytes, expected 32); \
                         delete it to create a new device identity",
                        path.display(),
                        bytes.len()
                    )
                })?;
                SigningKey::from_bytes(&seed)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir_all(config_dir)
                    .map_err(|e| format!("could not create {}: {e}", config_dir.display()))?;
                let seed = random_bytes();
                write_private(&path, &seed)
                    .map_err(|e| format!("could not save {}: {e}", path.display()))?;
                SigningKey::from_bytes(&seed)
            }
            Err(e) => return Err(format!("could not read {}: {e}", path.display()).into()),
        };
        Ok(Self::from_key(key, name))
    }

    fn from_key(key: SigningKey, name: impl Into<String>) -> Self {
        Self {
            id: device_id_for(&key.verifying_key().to_bytes()),
            name: name.into(),
            key,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

impl fmt::Debug for DeviceIdentity {
    // Never print the private key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The device id that belongs to `public_key`.
pub fn device_id_for(public_key: &[u8; 32]) -> String {
    let fingerprint = crate::transfer::hex(&Sha256::digest(public_key));
    format!("device-{}", &fingerprint[..ID_HEX_LEN])
}

/// Check that `signature` over `message` was made with `public_key`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key)
        .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
        .is_ok()
}

/// Where OpenDrop keeps its key and paired devices: `OPENDROP_CONFIG_DIR` if
/// set, otherwise the OS config folder (`~/Library/Application Support`,
/// `%APPDATA%`, `~/.config`) plus `OpenDrop`.
pub fn default_config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("OPENDROP_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OpenDrop")
}

/// 32 bytes from the OS random number generator.
pub fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    bytes
}

/// Create `path` holding `bytes`, readable only by this user. Fails if the
/// file already exists, so two processes starting at once can't both write
/// a key.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    // On Windows the file inherits the ACL of the user's profile folder,
    // which only that user (and administrators) can read.
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_survives_restarts_until_the_key_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let first = DeviceIdentity::load_or_create(dir.path(), "Mac").unwrap();
        for _ in 0..3 {
            let again = DeviceIdentity::load_or_create(dir.path(), "Mac").unwrap();
            assert_eq!(again.id, first.id);
            assert_eq!(again.public_key(), first.public_key());
        }
        std::fs::remove_file(dir.path().join(KEY_FILE)).unwrap();
        let fresh = DeviceIdentity::load_or_create(dir.path(), "Mac").unwrap();
        assert_ne!(fresh.id, first.id);
        assert_eq!(
            DeviceIdentity::load_or_create(dir.path(), "Mac")
                .unwrap()
                .id,
            fresh.id
        );
    }

    #[test]
    fn id_is_the_public_key_fingerprint() {
        let me = DeviceIdentity::new("Mac");
        assert_eq!(me.id, device_id_for(&me.public_key()));
        assert!(me.id.starts_with("device-"));
        assert_eq!(me.id.len(), "device-".len() + ID_HEX_LEN);
        assert_ne!(me.id, DeviceIdentity::new("Mac").id);
    }

    #[test]
    fn creates_missing_config_folders() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("OpenDrop");
        DeviceIdentity::load_or_create(&nested, "Mac").unwrap();
        assert!(nested.join(KEY_FILE).is_file());
    }

    #[test]
    fn a_damaged_key_file_is_an_error_not_a_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KEY_FILE), b"garbage").unwrap();
        let err = DeviceIdentity::load_or_create(dir.path(), "Mac").unwrap_err();
        assert!(err.to_string().contains("not an OpenDrop key"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join(KEY_FILE)).unwrap(),
            b"garbage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        DeviceIdentity::load_or_create(dir.path(), "Mac").unwrap();
        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn default_key_location_is_under_the_user_profile() {
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
        let config = dirs::config_dir().unwrap();
        assert!(
            config.starts_with(&profile),
            "{config:?} not under {profile:?}"
        );
    }

    #[test]
    fn signatures_verify_only_with_the_right_key_and_message() {
        let me = DeviceIdentity::new("Mac");
        let other = DeviceIdentity::new("PC");
        let sig = me.sign(b"hello");
        assert!(verify(&me.public_key(), b"hello", &sig));
        assert!(!verify(&me.public_key(), b"hellO", &sig));
        assert!(!verify(&other.public_key(), b"hello", &sig));
    }

    #[test]
    fn debug_output_hides_the_private_key() {
        let me = DeviceIdentity::new("Mac");
        let shown = format!("{me:?}");
        let secret = crate::transfer::hex(&me.key.to_bytes());
        assert!(!shown.contains(&secret));
    }
}
