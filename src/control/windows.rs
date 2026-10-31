//! Named pipe transport for the control API.
//!
//! The pipe is created with an explicit DACL that grants access to the user
//! running the daemon and to SYSTEM, nobody else (the default DACL would
//! also give Everyone read access), and remote clients are refused.

use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::io;
use std::path::Path;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub type ClientStream = NamedPipeClient;

/// Where the daemon for one config dir listens, and who may connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `\\.\pipe\opendrop-<hash>`.
    pub name: String,
    /// The pipe's security descriptor in SDDL. `None` means this user and
    /// SYSTEM only (see [`own_user_sddl`]).
    pub sddl: Option<String>,
}

impl Endpoint {
    /// One pipe per config dir, so several daemons (different `--config`)
    /// can run side by side.
    pub fn for_config_dir(config_dir: &Path) -> Self {
        let dir = std::path::absolute(config_dir).unwrap_or_else(|_| config_dir.to_owned());
        let digest = Sha256::digest(dir.to_string_lossy().to_lowercase().as_bytes());
        let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Self {
            name: format!(r"\\.\pipe\opendrop-{hash}"),
            sddl: None,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Create pipe instances one after another, handing each connected client to
/// `on_client`.
pub async fn serve(
    endpoint: Endpoint,
    ready: oneshot::Sender<Result<(), String>>,
    mut on_client: impl FnMut(NamedPipeServer) + Send,
) -> io::Result<()> {
    let bound = (|| {
        let sddl = match &endpoint.sddl {
            Some(sddl) => sddl.clone(),
            None => own_user_sddl()?,
        };
        let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
        let server = descriptor.create(&endpoint.name, true)?;
        io::Result::Ok((descriptor, server))
    })();
    let (descriptor, mut server) = match bound {
        Ok(bound) => {
            let _ = ready.send(Ok(()));
            bound
        }
        Err(e) => {
            let _ = ready.send(Err(format!("{endpoint}: {e}")));
            return Err(e);
        }
    };
    loop {
        server.connect().await?;
        let next = descriptor.create(&endpoint.name, false)?;
        on_client(std::mem::replace(&mut server, next));
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<NamedPipeClient> {
    // All instances can be busy for a moment between clients.
    for _ in 0..50 {
        match ClientOptions::new().open(&endpoint.name) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            other => return other,
        }
    }
    ClientOptions::new().open(&endpoint.name)
}

/// SDDL granting full access to this process's user and SYSTEM only, with
/// no inherited entries.
pub fn own_user_sddl() -> io::Result<String> {
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", current_user_sid()?))
}

/// The current user's SID as a string, e.g. `S-1-5-21-...`.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: plain Win32 calls with buffers we own; every handle and
    // allocation is released before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut wide: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut wide) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        while *wide.add(n) != 0 {
            n += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
        LocalFree(wide as HLOCAL);
        Ok(sid)
    }
}

/// A security descriptor parsed from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable after creation and only read by
// CreateNamedPipe.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; the descriptor is freed on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    fn create(&self, name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        };
        // SAFETY: `attributes` points at a valid descriptor for the call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name,
                    &mut attributes as *mut SECURITY_ATTRIBUTES as *mut c_void,
                )
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}
