//! OpenDrop command-line prototype.
//!
//!   opendrop listen [--port PORT] [--name NAME] [--dir DIR] [--auto-accept]
//!   opendrop peers [--wait SECONDS]
//!   opendrop send <DEVICE|IP[:PORT]> <MESSAGE> [--name NAME]
//!   opendrop send-file <DEVICE|IP[:PORT]> <FILE>... [--name NAME]
//!   opendrop pair <DEVICE|IP[:PORT]>
//!   opendrop devices [--wait SECONDS]
//!   opendrop unpair <DEVICE>

use opendrop::DEFAULT_PORT;
use opendrop::daemon::{self, Daemon};
use opendrop::discovery::{Discovery, Peer, PeerEvent};
use opendrop::identity::default_config_dir;
use opendrop::network::client::{Connection, FileResult};
use opendrop::network::server::{Approval, FileRequest};
use opendrop::network::{APPROVAL_TIMEOUT, DeviceIdentity};
use opendrop::pairing::store::PairedDevices;
use opendrop::pairing::{PAIRING_TIMEOUT, PairOutcome, PairPrompt, PairPrompts};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
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
    opendrop pair <DEVICE|IP[:PORT]>  pair with a device (both screens show a code)
    opendrop devices [--wait SECONDS] list nearby and paired devices
    opendrop unpair <DEVICE>          forget a paired device

Every command also takes --config DIR.

`listen` asks before accepting each file; --auto-accept takes every file without asking.
Received files go to --dir (default: Downloads/OpenDrop in your home folder).
This device's key lives in --config (default: OPENDROP_CONFIG_DIR, or the OS
config folder plus OpenDrop); its device id is derived from that key.

EXAMPLES:
    opendrop listen
    opendrop peers
    opendrop send \"AJ's MacBook\" \"hello from my PC\"
    opendrop send-file \"AJ's MacBook\" photo.jpg notes.pdf
    opendrop send 192.168.1.20 \"hello from my Mac\"
    opendrop pair \"AJ's MacBook\"";

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
    let config_dir = take_flag(&mut args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(default_config_dir);
    let identity = match DeviceIdentity::load_or_create(&config_dir, name) {
        Ok(identity) => identity,
        Err(e) => return fail(&e.to_string()),
    };
    // A damaged store must not stop the device from receiving files: carry
    // on with nothing paired (and leave the file alone for the user to fix).
    // Commands that manage pairing refuse to run on it instead.
    let (paired, store_error) = match PairedDevices::load(&config_dir) {
        Ok(paired) => (Arc::new(paired), None),
        Err(e) => (Arc::new(PairedDevices::in_memory()), Some(e.to_string())),
    };
    let needs_store = matches!(
        args.first().map(String::as_str),
        Some("pair" | "unpair" | "devices")
    );
    if let Some(error) = &store_error {
        if needs_store {
            return fail(error);
        }
        eprintln!("warning: {error}");
        eprintln!("warning: carrying on with no paired devices; changes won't be saved");
    }
    let me = Me { identity, paired };

    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["listen"] => listen(me, port, download_dir, auto_accept).await,
        ["peers"] => peers(&me, wait).await,
        ["send", target, message] => send(&me, target, message, wait).await,
        ["send-file", target, files @ ..] if !files.is_empty() => {
            send_files(&me, target, files, wait).await
        }
        ["pair", target] => pair(&me, target, wait).await,
        ["devices"] => devices(&me, wait).await,
        ["unpair", target] => unpair(&me, target),
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

/// This device: who it is and whom it has paired with.
struct Me {
    identity: DeviceIdentity,
    paired: Arc<PairedDevices>,
}

async fn listen(me: Me, port: u16, download_dir: PathBuf, auto_accept: bool) -> ExitCode {
    let Me { identity, paired } = me;
    let (file_prompts, pair_prompts) = spawn_prompt();
    let approval = if auto_accept {
        Approval::AcceptAll
    } else {
        Approval::Ask(file_prompts)
    };
    let daemon = match Daemon::start(daemon::Options {
        port,
        paired: Arc::clone(&paired),
        pair_prompts: Some(pair_prompts),
        ..daemon::Options::new(identity, download_dir, approval)
    })
    .await
    {
        Ok(d) => d,
        Err(e) => return fail(&e.to_string()),
    };
    // With --port 0 the OS picks one; advertise what we actually got.
    let port = daemon.port;
    println!(
        "\"{}\" ({}) listening on port {port}",
        daemon.identity.name, daemon.identity.id
    );
    match local_ip() {
        Some(ip) => println!("Other devices can reach this one at {ip}:{port}"),
        None => println!("Could not detect this device's LAN IP; check your network settings"),
    }
    println!(
        "Received files are saved to {}",
        daemon.download_dir.display()
    );
    if auto_accept {
        println!("Accepting every incoming file without asking (--auto-accept).");
    } else {
        println!("You'll be asked before any incoming file is saved.");
    }
    match paired.list().len() {
        0 => println!("No paired devices yet; others can pair with `opendrop pair`."),
        n => println!("{n} paired device(s); see `opendrop devices`."),
    }
    match (daemon.discovery(), daemon.discovery_error()) {
        (Some(_), _) => {
            println!("Advertising on the local network; nearby devices will appear below.")
        }
        (None, error) => eprintln!(
            "warning: mDNS discovery unavailable ({}); peers must use the IP above",
            error.unwrap_or("turned off")
        ),
    }
    println!("Press Ctrl+C to stop.\n");
    if let Some(discovery) = daemon.discovery() {
        let mut events = discovery.subscribe();
        let paired = Arc::clone(&paired);
        tokio::spawn(async move {
            // Address each peer was last shown with. Updates mostly add
            // addresses as more interfaces answer; only mention the ones that
            // change where we'd connect.
            let mut shown = HashMap::new();
            while let Ok(event) = events.recv().await {
                match event {
                    PeerEvent::Found(p) => {
                        println!("+ found {}", describe(&p, &paired));
                        shown.insert(p.id.clone(), p.socket_addr());
                    }
                    PeerEvent::Updated(p) => {
                        if shown.insert(p.id.clone(), p.socket_addr()) != Some(p.socket_addr()) {
                            println!("~ updated {}", describe(&p, &paired));
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
        result = daemon.wait() => match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&format!("server stopped: {e}")),
        },
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down.");
            ExitCode::SUCCESS
        }
    }
}

async fn peers(me: &Me, wait: Duration) -> ExitCode {
    let discovery = match Discovery::start(&me.identity, None) {
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
        println!("{}", describe(&peer, &me.paired));
    }
    ExitCode::SUCCESS
}

async fn send(me: &Me, target: &str, message: &str, wait: Duration) -> ExitCode {
    let (mut connection, addr) = match connect(me, target, wait).await {
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

async fn send_files(me: &Me, target: &str, files: &[&str], wait: Duration) -> ExitCode {
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
    let (mut connection, addr) = match connect(me, target, wait).await {
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

async fn pair(me: &Me, target: &str, wait: Duration) -> ExitCode {
    let (mut connection, addr) = match connect(me, target, wait).await {
        Ok(c) => c,
        Err(code) => return code,
    };
    let peer = connection.peer.clone();
    if connection.paired {
        println!("Already paired with \"{}\" ({}).", peer.name, peer.id);
        return ExitCode::SUCCESS;
    }
    println!(
        "Asking \"{}\" ({}) at {addr} to pair. Both screens will show a 6-digit code.",
        peer.name, peer.id
    );
    let (_files, prompts) = spawn_prompt();
    match connection.pair(&me.identity, &prompts, &me.paired).await {
        Ok(PairOutcome::Paired) => {
            println!("Paired with \"{}\" ({}).", peer.name, peer.id);
            ExitCode::SUCCESS
        }
        Ok(PairOutcome::Declined { by_peer: true }) => {
            fail(&format!("\"{}\" declined; not paired", peer.name))
        }
        Ok(PairOutcome::Declined { by_peer: false }) => fail("you declined; not paired"),
        Ok(PairOutcome::TimedOut) => fail(&format!(
            "no answer within {}s; not paired",
            PAIRING_TIMEOUT.as_secs()
        )),
        Err(e) => fail(&format!("pairing failed: {e}")),
    }
}

/// Nearby devices with their pairing status, then paired devices that
/// aren't around right now.
async fn devices(me: &Me, wait: Duration) -> ExitCode {
    let found = match Discovery::start(&me.identity, None) {
        Ok(discovery) => {
            tokio::time::sleep(wait).await;
            discovery.peers()
        }
        Err(e) => {
            eprintln!("warning: could not look for nearby devices ({e})");
            Vec::new()
        }
    };
    let paired = me.paired.list();
    if found.is_empty() && paired.is_empty() {
        println!("No devices nearby and none paired.");
        return ExitCode::SUCCESS;
    }
    for peer in &found {
        let status = if peer.protocol_version != opendrop::protocol::PROTOCOL_VERSION {
            "Incompatible"
        } else if me.paired.get(&peer.id).is_some() {
            "Paired"
        } else {
            "Unpaired"
        };
        println!("{status:<13}{}", describe(peer, &me.paired));
    }
    for device in paired.iter().filter(|d| found.iter().all(|p| p.id != d.id)) {
        println!(
            "{:<13}\"{}\" ({}) not on the network right now",
            "Paired", device.name, device.id
        );
    }
    ExitCode::SUCCESS
}

/// Forget a paired device, named by id or (unambiguous) name.
fn unpair(me: &Me, target: &str) -> ExitCode {
    let matches: Vec<_> = me
        .paired
        .list()
        .into_iter()
        .filter(|d| d.id == target || d.name.eq_ignore_ascii_case(target))
        .collect();
    let device = match matches.as_slice() {
        [device] => device,
        [] => {
            return fail(&format!(
                "no paired device named \"{target}\" (see `opendrop devices`)"
            ));
        }
        several => {
            let ids: Vec<&str> = several.iter().map(|d| d.id.as_str()).collect();
            return fail(&format!(
                "several paired devices are named \"{target}\"; use an id: {}",
                ids.join(", ")
            ));
        }
    };
    match me.paired.remove(&device.id) {
        Ok(_) => {
            println!(
                "Unpaired \"{}\" ({}). It will see this the next time you connect.",
                device.name, device.id
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("could not save the change: {e}")),
    }
}

/// Connect to `target`: a bare IP (default port), IP:PORT, or a discovered
/// device's name or id. A discovered device may advertise several
/// addresses; the first that answers wins.
async fn connect(me: &Me, target: &str, wait: Duration) -> Result<(Connection, String), ExitCode> {
    let addrs = match target.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, DEFAULT_PORT).to_string()],
        Err(_) if target.parse::<SocketAddr>().is_ok() => vec![target.to_owned()],
        Err(_) => find_peer(&me.identity, target, wait)
            .await?
            .iter()
            .map(SocketAddr::to_string)
            .collect(),
    };
    let mut last_error = String::new();
    for addr in addrs {
        match Connection::open_with(&addr, &me.identity, &me.paired).await {
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

fn describe(peer: &Peer, paired: &PairedDevices) -> String {
    let addr = peer
        .socket_addr()
        .map_or_else(|| format!("?:{}", peer.port), |a| a.to_string());
    let mut line = format!("\"{}\" ({}) at {addr}", peer.name, peer.id);
    if peer.protocol_version != opendrop::protocol::PROTOCOL_VERSION {
        line.push_str(&format!(
            " [protocol v{}, incompatible]",
            peer.protocol_version
        ));
    } else if paired.get(&peer.id).is_some() {
        line.push_str(" [paired]");
    }
    line
}

/// Ask on the terminal about each offered file and each pairing request,
/// one at a time. Requests that arrive while one is pending wait their turn.
fn spawn_prompt() -> (mpsc::Sender<FileRequest>, PairPrompts) {
    let (file_requests, mut files) = mpsc::channel::<FileRequest>(16);
    let (pair_requests, mut pairs) = mpsc::channel::<PairPrompt>(4);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        loop {
            let (question, limit, mut respond) = tokio::select! {
                Some(FileRequest { peer_name, peer_addr, name, size, respond, .. }) = files.recv() => (
                    format!(
                        "\"{peer_name}\" ({}) wants to send you \"{name}\" ({}).\n  Accept?",
                        peer_addr.ip(),
                        human_size(size),
                    ),
                    APPROVAL_TIMEOUT,
                    respond,
                ),
                Some(PairPrompt { peer, code, incoming, respond }) = pairs.recv() => (
                    format!(
                        "{} Pairing code: {code}\n  Does \"{}\" show the same code?",
                        if incoming {
                            format!("\"{}\" ({}) wants to pair.", peer.name, peer.id)
                        } else {
                            format!("Pairing with \"{}\" ({}).", peer.name, peer.id)
                        },
                        peer.name
                    ),
                    PAIRING_TIMEOUT,
                    respond,
                ),
                else => break,
            };
            if respond.is_closed() {
                continue; // Timed out or the sender hung up while queued.
            }
            print!("\n? {question} [y/N] (within {}s): ", limit.as_secs());
            let _ = std::io::stdout().flush();
            let answer = tokio::select! {
                line = lines.next_line() => line.ok().flatten(),
                _ = respond.closed() => {
                    println!("\n  No answer in time, or the other side cancelled; declined.");
                    continue;
                }
            };
            let _ = respond.send(is_yes(answer));
        }
    });
    (file_requests, pair_requests)
}

fn is_yes(answer: Option<String>) -> bool {
    answer.is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "y" | "yes"))
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
