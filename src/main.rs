//! OpenDrop command-line prototype.
//!
//!   opendrop listen [--port PORT] [--name NAME] [--dir DIR] [--auto-accept]
//!   opendrop peers [--wait SECONDS]
//!   opendrop send <DEVICE|IP[:PORT]> <MESSAGE> [--name NAME]
//!   opendrop send-file <DEVICE|IP[:PORT]> <FILE>... [--name NAME]

use opendrop::DEFAULT_PORT;
use opendrop::discovery::{Discovery, Peer, PeerEvent};
use opendrop::network::client::{Connection, FileResult};
use opendrop::network::server::{Approval, FileRequest};
use opendrop::network::{APPROVAL_TIMEOUT, DeviceIdentity, server};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// How long `peers` and `send <DEVICE>` browse before giving up.
const DEFAULT_WAIT: Duration = Duration::from_secs(3);

const USAGE: &str = "\
OpenDrop networking prototype

USAGE:
    opendrop listen [--port PORT] [--name NAME] [--dir DIR] [--auto-accept]
                                    advertise, receive messages and files
    opendrop peers [--wait SECONDS] list devices on this network
    opendrop send <DEVICE|IP[:PORT]> <MESSAGE> [--name NAME]
    opendrop send-file <DEVICE|IP[:PORT]> <FILE>... [--name NAME]

`listen` asks before accepting each file; --auto-accept takes every file without asking.
Received files go to --dir (default: Downloads/OpenDrop in your home folder).

EXAMPLES:
    opendrop listen
    opendrop peers
    opendrop send \"AJ's MacBook\" \"hello from my PC\"
    opendrop send-file \"AJ's MacBook\" photo.jpg notes.pdf
    opendrop send 192.168.1.20 \"hello from my Mac\"";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let name = take_flag(&mut args, "--name").unwrap_or_else(default_device_name);
    let port = match take_flag(&mut args, "--port").map(|p| p.parse::<u16>()) {
        None => DEFAULT_PORT,
        Some(Ok(p)) => p,
        Some(Err(_)) => return fail("--port must be a number between 0 and 65535"),
    };
    let wait = match take_flag(&mut args, "--wait").map(|w| w.parse::<f64>()) {
        None => DEFAULT_WAIT,
        Some(Ok(w)) if w.is_finite() && w >= 0.0 => Duration::from_secs_f64(w),
        Some(_) => return fail("--wait must be a number of seconds"),
    };
    let download_dir = take_flag(&mut args, "--dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_download_dir);
    let auto_accept = take_switch(&mut args, "--auto-accept");
    let identity = DeviceIdentity::new(name);

    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["listen"] => listen(identity, port, download_dir, auto_accept).await,
        ["peers"] => peers(identity, wait).await,
        ["send", target, message] => send(identity, target, message, wait).await,
        ["send-file", target, files @ ..] if !files.is_empty() => {
            send_files(identity, target, files, wait).await
        }
        ["help"] | ["--help"] | ["-h"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

async fn listen(
    identity: DeviceIdentity,
    port: u16,
    download_dir: PathBuf,
    auto_accept: bool,
) -> ExitCode {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => return fail(&format!("could not listen on port {port}: {e}")),
    };
    // With --port 0 the OS picks one; advertise what we actually got.
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    println!(
        "\"{}\" ({}) listening on port {port}",
        identity.name, identity.id
    );
    match local_ip() {
        Some(ip) => println!("Other devices can reach this one at {ip}:{port}"),
        None => println!("Could not detect this device's LAN IP; check your network settings"),
    }
    println!("Received files are saved to {}", download_dir.display());
    let approval = if auto_accept {
        println!("Accepting every incoming file without asking (--auto-accept).");
        Approval::AcceptAll
    } else {
        println!("You'll be asked before any incoming file is saved.");
        Approval::Ask(spawn_prompt())
    };
    let discovery = match Discovery::start(&identity, Some(port)) {
        Ok(d) => {
            println!("Advertising on the local network; nearby devices will appear below.");
            Some(d)
        }
        Err(e) => {
            eprintln!("warning: mDNS discovery unavailable ({e}); peers must use the IP above");
            None
        }
    };
    println!("Press Ctrl+C to stop.\n");
    if let Some(discovery) = &discovery {
        let mut events = discovery.subscribe();
        tokio::spawn(async move {
            // Address each peer was last shown with. Updates mostly add
            // addresses as more interfaces answer; only mention the ones that
            // change where we'd connect.
            let mut shown = HashMap::new();
            while let Ok(event) = events.recv().await {
                match event {
                    PeerEvent::Found(p) => {
                        println!("+ found {}", describe(&p));
                        shown.insert(p.id.clone(), p.socket_addr());
                    }
                    PeerEvent::Updated(p) => {
                        if shown.insert(p.id.clone(), p.socket_addr()) != Some(p.socket_addr()) {
                            println!("~ updated {}", describe(&p));
                        }
                    }
                    PeerEvent::Lost(p) => {
                        println!("- lost \"{}\" ({})", p.name, p.id);
                        shown.remove(&p.id);
                    }
                }
            }
        });
    }

    tokio::select! {
        result = server::run(listener, identity, download_dir, approval) => match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&format!("server stopped: {e}")),
        },
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down.");
            ExitCode::SUCCESS
        }
    }
}

async fn peers(identity: DeviceIdentity, wait: Duration) -> ExitCode {
    let discovery = match Discovery::start(&identity, None) {
        Ok(d) => d,
        Err(e) => return fail(&format!("could not start mDNS discovery: {e}")),
    };
    println!(
        "Looking for OpenDrop devices for {:.1}s...",
        wait.as_secs_f64()
    );
    tokio::time::sleep(wait).await;
    let found = discovery.peers();
    if found.is_empty() {
        println!("No devices found. Is `opendrop listen` running on the same network?");
    }
    for peer in found {
        println!("{}", describe(&peer));
    }
    ExitCode::SUCCESS
}

async fn send(identity: DeviceIdentity, target: &str, message: &str, wait: Duration) -> ExitCode {
    let (mut connection, addr) = match connect(&identity, target, wait).await {
        Ok(c) => c,
        Err(code) => return code,
    };
    match connection.send_text(message).await {
        Ok(received_bytes) => {
            println!(
                "Delivered to \"{}\" ({}) at {addr}: they received {received_bytes} bytes.",
                connection.peer.name, connection.peer.id
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

async fn send_files(
    identity: DeviceIdentity,
    target: &str,
    files: &[&str],
    wait: Duration,
) -> ExitCode {
    // Catch typos before connecting rather than halfway through a batch.
    for file in files {
        match std::fs::metadata(file) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                return fail(&format!(
                    "{file} is not a file (folders aren't supported yet)"
                ));
            }
            Err(e) => return fail(&format!("cannot read {file}: {e}")),
        }
    }
    let (mut connection, addr) = match connect(&identity, target, wait).await {
        Ok(c) => c,
        Err(code) => return code,
    };
    println!(
        "Sending {} file(s) to \"{}\" ({}) at {addr}",
        files.len(),
        connection.peer.name,
        connection.peer.id
    );
    println!("Waiting for them to accept each file...");
    let mut declined = 0;
    for file in files {
        let path = Path::new(file);
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut bar = Progress::new(path, size);
        match connection
            .send_file(path, &mut |sent| bar.update(sent))
            .await
        {
            Ok(FileResult::Delivered(outcome)) => bar.finish(&format!(
                "done, verified (SHA-256 {}...)",
                &outcome.sha256[..12]
            )),
            Ok(FileResult::Declined) => {
                bar.finish("declined by the receiver");
                declined += 1;
            }
            Err(e) => {
                bar.finish("failed");
                return fail(&e.to_string());
            }
        }
    }
    if declined > 0 {
        return fail(&format!("{declined} of {} file(s) declined", files.len()));
    }
    ExitCode::SUCCESS
}

/// Connect to `target`: a bare IP (default port), IP:PORT, or a discovered
/// device's name or id. A discovered device may advertise several
/// addresses; the first that answers wins.
async fn connect(
    identity: &DeviceIdentity,
    target: &str,
    wait: Duration,
) -> Result<(Connection, String), ExitCode> {
    let addrs = match target.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, DEFAULT_PORT).to_string()],
        Err(_) if target.parse::<SocketAddr>().is_ok() => vec![target.to_owned()],
        Err(_) => find_peer(identity, target, wait)
            .await?
            .iter()
            .map(SocketAddr::to_string)
            .collect(),
    };
    let mut last_error = String::new();
    for addr in addrs {
        match Connection::open(&addr, identity).await {
            Ok(connection) => return Ok((connection, addr)),
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(fail(&last_error))
}

/// One-line transfer progress on stderr, redrawn at most ten times a second.
struct Progress {
    name: String,
    size: u64,
    started: Instant,
    drawn: Option<Instant>,
    sent: u64,
}

impl Progress {
    fn new(path: &Path, size: u64) -> Self {
        Self {
            name: path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().into(),
            ),
            size,
            started: Instant::now(),
            drawn: None,
            sent: 0,
        }
    }

    fn update(&mut self, sent: u64) {
        if self.drawn.is_none() {
            // Bytes only flow once the receiver accepts; don't count the wait.
            self.started = Instant::now();
        }
        self.sent = sent;
        if self
            .drawn
            .is_some_and(|t| t.elapsed() < Duration::from_millis(100))
        {
            return;
        }
        self.drawn = Some(Instant::now());
        self.draw("");
    }

    fn finish(&mut self, status: &str) {
        self.draw(status);
        eprintln!();
    }

    fn draw(&self, status: &str) {
        let percent = (self.sent * 100).checked_div(self.size).unwrap_or(100);
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = self.sent as f64 / secs / 1_000_000.0;
        eprint!(
            "\r  {}  {percent:>3}%  {} / {}  {rate:.1} MB/s  {status}",
            self.name,
            human_size(self.sent),
            human_size(self.size)
        );
        let _ = std::io::stderr().flush();
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

async fn find_peer(
    identity: &DeviceIdentity,
    query: &str,
    wait: Duration,
) -> Result<Vec<SocketAddr>, ExitCode> {
    let discovery = Discovery::start(identity, None)
        .map_err(|e| fail(&format!("could not start mDNS discovery: {e}")))?;
    let peer = discovery.find(query, wait).await.ok_or_else(|| {
        fail(&format!(
            "no device named \"{query}\" found on this network (run `opendrop peers` to list them)"
        ))
    })?;
    let addrs = peer.socket_addrs();
    if addrs.is_empty() {
        return Err(fail(&format!(
            "\"{}\" advertised no usable address",
            peer.name
        )));
    }
    Ok(addrs)
}

fn describe(peer: &Peer) -> String {
    let addr = peer
        .socket_addr()
        .map_or_else(|| format!("?:{}", peer.port), |a| a.to_string());
    let mut line = format!("\"{}\" ({}) at {addr}", peer.name, peer.id);
    if peer.protocol_version != opendrop::protocol::PROTOCOL_VERSION {
        line.push_str(&format!(
            " [protocol v{}, incompatible]",
            peer.protocol_version
        ));
    }
    line
}

/// Ask on the terminal about each offered file, one at a time. Offers that
/// arrive while one is pending wait their turn.
fn spawn_prompt() -> mpsc::Sender<FileRequest> {
    let (requests, mut pending) = mpsc::channel::<FileRequest>(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(FileRequest {
            peer_name,
            peer_addr,
            name,
            size,
            mut respond,
        }) = pending.recv().await
        {
            if respond.is_closed() {
                continue; // Timed out or the sender hung up while queued.
            }
            print!(
                "\n? \"{peer_name}\" ({}) wants to send you \"{name}\" ({}).\n  Accept? [y/N] (within {}s): ",
                peer_addr.ip(),
                human_size(size),
                APPROVAL_TIMEOUT.as_secs()
            );
            let _ = std::io::stdout().flush();
            let answer = tokio::select! {
                line = lines.next_line() => line.ok().flatten(),
                _ = respond.closed() => {
                    println!("\n  No answer in time; declined.");
                    continue;
                }
            };
            let accept =
                answer.is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "y" | "yes"));
            let _ = respond.send(accept);
        }
    });
    requests
}

/// Remove `--flag` from `args`, returning whether it was there.
fn take_switch(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|a| a != flag);
    args.len() != before
}

/// Remove `--flag VALUE` from `args` and return VALUE.
fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.remove(i);
    (i < args.len()).then(|| args.remove(i))
}

/// `~/Downloads/OpenDrop`, or `./OpenDrop` if there's no home folder.
fn default_download_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE")) // Windows
        .map(|home| PathBuf::from(home).join("Downloads"))
        .unwrap_or_default()
        .join("OpenDrop")
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME") // Windows
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .map(|s| s.trim().trim_end_matches(".local").to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "OpenDrop device".to_owned())
}

/// The LAN address the OS would use for outbound traffic. Connecting a UDP
/// socket only picks a route; no packets are sent.
fn local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.168.0.1:9").ok()?;
    socket
        .local_addr()
        .ok()
        .map(|a| a.ip())
        .filter(|ip| !ip.is_unspecified())
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}
