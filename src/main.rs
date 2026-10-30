//! OpenDrop command-line prototype.
//!
//!   opendrop listen [--port PORT] [--name NAME]
//!   opendrop peers [--wait SECONDS]
//!   opendrop send <DEVICE|IP[:PORT]> <MESSAGE> [--name NAME]

use opendrop::DEFAULT_PORT;
use opendrop::discovery::{Discovery, Peer, PeerEvent};
use opendrop::network::{DeviceIdentity, client, server};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;
use tokio::net::TcpListener;

/// How long `peers` and `send <DEVICE>` browse before giving up.
const DEFAULT_WAIT: Duration = Duration::from_secs(3);

const USAGE: &str = "\
OpenDrop networking prototype

USAGE:
    opendrop listen [--port PORT] [--name NAME]   advertise and receive messages
    opendrop peers [--wait SECONDS]               list devices on this network
    opendrop send <DEVICE|IP[:PORT]> <MESSAGE> [--name NAME]

EXAMPLES:
    opendrop listen
    opendrop peers
    opendrop send \"AJ's MacBook\" \"hello from my PC\"
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
    let identity = DeviceIdentity::new(name);

    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["listen"] => listen(identity, port).await,
        ["peers"] => peers(identity, wait).await,
        ["send", target, message] => send(identity, target, message, wait).await,
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

async fn listen(identity: DeviceIdentity, port: u16) -> ExitCode {
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
        result = server::run(listener, identity) => match result {
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
    // Accept a bare IP (default port), IP:PORT, or a discovered device's name or id.
    let addrs = match target.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, DEFAULT_PORT).to_string()],
        Err(_) if target.parse::<SocketAddr>().is_ok() => vec![target.to_owned()],
        Err(_) => match find_peer(&identity, target, wait).await {
            Ok(addrs) => addrs.iter().map(SocketAddr::to_string).collect(),
            Err(code) => return code,
        },
    };
    // A discovered device may advertise several addresses; use the first
    // that answers.
    let mut last_error = String::new();
    for addr in addrs {
        match client::send_text(&addr, &identity, message).await {
            Ok(outcome) => {
                println!(
                    "Delivered to \"{}\" ({}) at {addr}: they received {} bytes.",
                    outcome.peer.name, outcome.peer.id, outcome.received_bytes
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => last_error = e.to_string(),
        }
    }
    fail(&last_error)
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

/// Remove `--flag VALUE` from `args` and return VALUE.
fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.remove(i);
    (i < args.len()).then(|| args.remove(i))
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
