//! Tauri shell around [`node::Node`]: commands in, events out.

mod node;

use node::{AppEvent, Device, EventSink, Node};
use opendrop::DEFAULT_PORT;
use opendrop::network::DeviceIdentity;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{Emitter, Manager, State};

/// The window listens for every [`AppEvent`] on this event name.
const EVENT: &str = "opendrop://event";

/// This device, as shown in the window's header.
#[derive(Serialize)]
struct Me {
    id: String,
    name: String,
    port: u16,
    download_dir: String,
}

#[tauri::command]
fn me(node: State<'_, Arc<Node>>) -> Me {
    Me {
        id: node.identity.id.clone(),
        name: node.identity.name.clone(),
        port: node.port,
        download_dir: node.download_dir.display().to_string(),
    }
}

#[tauri::command]
fn devices(node: State<'_, Arc<Node>>) -> Vec<Device> {
    node.devices()
}

/// Send files to a discovered device, or to `address` (`IP` or `IP:PORT`)
/// when it isn't discovered. Returns the transfer ids, in order.
#[tauri::command]
async fn send_files(
    node: State<'_, Arc<Node>>,
    device_id: Option<String>,
    address: Option<String>,
    paths: Vec<PathBuf>,
) -> Result<Vec<String>, String> {
    let result = match (device_id, address) {
        (Some(id), _) => node.send_to_device(&id, &paths).await,
        (None, Some(address)) => {
            let addr = parse_address(&address)?;
            node.send_to_addrs(&[addr], &paths).await
        }
        (None, None) => return Err("no device given".into()),
    };
    result.map_err(|e| e.to_string())
}

#[tauri::command]
fn respond(node: State<'_, Arc<Node>>, transfer_id: String, accept: bool) -> bool {
    node.respond(&transfer_id, accept)
}

fn parse_address(address: &str) -> Result<SocketAddr, String> {
    let address = address.trim();
    address
        .parse::<SocketAddr>()
        .or_else(|_| {
            address
                .parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
        })
        .map_err(|_| format!("\"{address}\" is not an IP address"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let sink: EventSink = Arc::new(move |event: AppEvent| {
                let _ = handle.emit(EVENT, event);
            });
            // OPENDROP_NAME and OPENDROP_DIR let two copies run side by side
            // on one machine for testing.
            let download_dir = std::env::var_os("OPENDROP_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    app.path()
                        .download_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("OpenDrop")
                });
            let name = std::env::var("OPENDROP_NAME").unwrap_or_else(|_| device_name());
            let identity = DeviceIdentity::new(name);
            let node = tauri::async_runtime::block_on(async move {
                // Prefer the standard port so CLI peers can reach us by IP
                // alone; if something already has it, take any port (mDNS
                // advertises the real one).
                match Node::start(
                    identity.clone(),
                    DEFAULT_PORT,
                    download_dir.clone(),
                    true,
                    sink.clone(),
                )
                .await
                {
                    Ok(node) => Ok(node),
                    Err(_) => Node::start(identity, 0, download_dir, true, sink).await,
                }
            })
            .map_err(|e| e.to_string())?;
            app.manage(node);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![me, devices, send_files, respond])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// The name people know this computer by: "AJ's MacBook Pro" on macOS, the
/// computer name on Windows, the hostname elsewhere.
fn device_name() -> String {
    let command = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    };
    let name = if cfg!(target_os = "macos") {
        command("scutil", &["--get", "ComputerName"])
    } else {
        None
    };
    name.or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| command("hostname", &[]))
        .map(|s| s.trim().trim_end_matches(".local").to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "OpenDrop device".to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_address;

    #[test]
    fn addresses_default_to_the_standard_port() {
        assert_eq!(
            parse_address(" 192.168.1.20 ").unwrap().to_string(),
            "192.168.1.20:45454"
        );
        assert_eq!(
            parse_address("10.0.0.2:5000").unwrap().to_string(),
            "10.0.0.2:5000"
        );
        assert!(parse_address("my laptop").is_err());
    }
}
