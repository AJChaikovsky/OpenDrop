//! `opendrop-relay`: run the OpenDrop relay server.

use opendrop_relay::{Config, LogMailer, Relay, inbox::Blobs, serve, store::Store};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
OpenDrop relay server (opt-in; see docs/design/ai-file-requests.md, \"Option B\")

USAGE:
    opendrop-relay [--bind ADDR] [--data DIR] [--public-url URL]

    --bind ADDR        where to listen (default 0.0.0.0:8787)
    --data DIR         where accounts, devices and the encrypted inbox are kept
                       (default relay-data)
    --public-url URL   how devices and browsers reach this relay, used in sign-in
                       links (default http://<bind address>)

Sign-in links are printed here rather than emailed. The hosted MCP server for
assistants is at <public URL>/mcp (needs a token from `opendrop relay token`).";

#[tokio::main]
async fn main() -> ExitCode {
    let mut bind = "0.0.0.0:8787".to_owned();
    let mut data = PathBuf::from("relay-data");
    let mut public_url = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        let result = match arg.as_str() {
            "--bind" => value("--bind").map(|v| bind = v),
            "--data" => value("--data").map(|v| data = v.into()),
            "--public-url" => value("--public-url").map(|v| public_url = Some(v)),
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => Err(format!("unknown argument {other}")),
        };
        if let Err(e) = result {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&data) {
        eprintln!("error: cannot create {}: {e}", data.display());
        return ExitCode::FAILURE;
    }
    let store = match Store::open(&data.join("relay.db")) {
        Ok(store) => store,
        Err(e) => {
            eprintln!(
                "error: cannot open {}: {e}",
                data.join("relay.db").display()
            );
            return ExitCode::FAILURE;
        }
    };
    let blobs = match Blobs::open(&data.join("inbox"), &data.join("relay.key")) {
        Ok(blobs) => blobs,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot listen on {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let public_url = public_url.unwrap_or_else(|| format!("http://{bind}"));
    println!("OpenDrop relay listening on {bind}, reachable as {public_url}");
    let relay = Relay::new(store, blobs, Box::new(LogMailer), Config::new(public_url));
    match serve(listener, relay).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
