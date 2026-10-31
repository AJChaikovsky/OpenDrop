//! Unix socket transport for the control API.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

pub type ClientStream = UnixStream;

/// Where the daemon for one config dir listens, and who may connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub path: PathBuf,
    /// Only clients running as this uid are served. `None` means the owner
    /// of the socket file, i.e. whoever started the daemon.
    pub allowed_uid: Option<u32>,
}

impl Endpoint {
    /// `<config dir>/run/control.sock`.
    pub fn for_config_dir(config_dir: &Path) -> Self {
        Self {
            path: config_dir.join("run").join("control.sock"),
            allowed_uid: None,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

/// Bind the socket (replacing a stale one left by a crashed daemon) and hand
/// every accepted, authorised client to `on_client`.
pub async fn serve(
    endpoint: Endpoint,
    ready: oneshot::Sender<Result<(), String>>,
    mut on_client: impl FnMut(UnixStream) + Send,
) -> io::Result<()> {
    let bound = async {
        let listener = bind(&endpoint).await?;
        let allowed = match endpoint.allowed_uid {
            Some(uid) => uid,
            None => std::fs::metadata(&endpoint.path)?.uid(),
        };
        io::Result::Ok((listener, allowed))
    };
    let (listener, allowed) = match bound.await {
        Ok(bound) => {
            let _ = ready.send(Ok(()));
            bound
        }
        Err(e) => {
            let _ = ready.send(Err(format!("{endpoint}: {e}")));
            return Err(e);
        }
    };
    let _cleanup = RemoveOnDrop(endpoint.path.clone());
    loop {
        let (stream, _) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed => on_client(stream),
            // Another user: drop the connection without a word.
            _ => drop(stream),
        }
    }
}

async fn bind(endpoint: &Endpoint) -> io::Result<UnixListener> {
    let path = &endpoint.path;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    // The folder keeps other users from even reaching the socket.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("another daemon is already serving {}", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<UnixStream> {
    UnixStream::connect(&endpoint.path).await
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
