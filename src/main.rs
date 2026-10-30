//! OpenDrop command-line prototype.
//!
//!   opendrop listen [--port PORT] [--name NAME]
//!   opendrop send <IP[:PORT]> <MESSAGE> [--name NAME]

use opendrop::DEFAULT_PORT;
use opendrop::network::{DeviceIdentity, client, server};
use std::net::{IpAddr, UdpSocket};
use std::process::ExitCode;
use tokio::net::TcpListener;

const USAGE: &str = "\
OpenDrop networking prototype

USAGE:
    opendrop listen [--port PORT] [--name NAME]
    opendrop send <IP[:PORT]> <MESSAGE> [--name NAME]

EXAMPLES:
    opendrop listen
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
    let identity = DeviceIdentity::new(name);

    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["listen"] => listen(identity, port).await,
        ["send", target, message] => send(identity, target, message).await,
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
    println!(
        "\"{}\" ({}) listening on port {port}",
        identity.name, identity.id
    );
    match local_ip() {
        Some(ip) => println!("Other devices can reach this one at {ip}:{port}"),
        None => println!("Could not detect this device's LAN IP; check your network settings"),
    }
    println!("Press Ctrl+C to stop.\n");

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

async fn send(identity: DeviceIdentity, target: &str, message: &str) -> ExitCode {
    // Accept a bare IP and fill in the default port.
    let addr = match target.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]:{DEFAULT_PORT}"),
        Ok(ip) => format!("{ip}:{DEFAULT_PORT}"),
        Err(_) => target.to_owned(),
    };
    match client::send_text(&addr, &identity, message).await {
        Ok(outcome) => {
            println!(
                "Delivered to \"{}\" ({}) at {addr}: they received {} bytes.",
                outcome.peer.name, outcome.peer.id, outcome.received_bytes
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
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
