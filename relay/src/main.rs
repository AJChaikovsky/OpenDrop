//! `opendrop-relay`: run the OpenDrop relay server.

use opendrop_relay::{Config, LogMailer, Relay, serve, store::Store};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
OpenDrop relay server (opt-in; see docs/design/ai-file-requests.md, \"Option B\")

USAGE:
    opendrop-relay [--bind ADDR] [--db FILE] [--public-url URL]

    --bind ADDR        where to listen (default 0.0.0.0:8787)
    --db FILE          SQLite database (default relay.db)
    --public-url URL   how devices and browsers reach this relay, used in sign-in
                       links (default http://<bind address>)

Sign-in links are printed here rather than emailed.";

#[tokio::main]
async fn main() -> ExitCode {
    let mut bind = "0.0.0.0:8787".to_owned();
    let mut db = PathBuf::from("relay.db");
    let mut public_url = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        let result = match arg.as_str() {
            "--bind" => value("--bind").map(|v| bind = v),
            "--db" => value("--db").map(|v| db = v.into()),
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
    let store = match Store::open(&db) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: cannot open {}: {e}", db.display());
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
    let relay = Relay::new(store, Box::new(LogMailer), Config::new(public_url));
    match serve(listener, relay).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
