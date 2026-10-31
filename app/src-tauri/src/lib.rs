//! Tauri shell around [`node::Node`]: commands in, events out.

mod node;

use node::{AppEvent, Device, EventSink, Node};
use opendrop::DEFAULT_PORT;
use opendrop::identity::{DeviceIdentity, default_config_dir};
use opendrop::pairing::store::PairedDevices;
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
    /// Something the user should know about, e.g. a damaged paired-devices
    /// file.
    warning: Option<String>,
}

/// A problem found at startup, shown in the window.
struct Warning(Option<String>);

#[tauri::command]
fn me(node: State<'_, Arc<Node>>, warning: State<'_, Warning>) -> Me {
    Me {
        id: node.identity.id.clone(),
        name: node.identity.name.clone(),
        port: node.port,
        download_dir: node.download_dir.display().to_string(),
        warning: warning.0.clone(),
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

/// Start pairing with a discovered device; the codes arrive as events.
#[tauri::command]
async fn pair_device(node: State<'_, Arc<Node>>, device_id: String) -> Result<(), String> {
    node.pair_device(&device_id)
        .await
        .map_err(|e| e.to_string())
}

/// Answer a pairing code: `accept` if both screens show the same code.
#[tauri::command]
fn respond_pair(node: State<'_, Arc<Node>>, pair_id: String, accept: bool) -> bool {
    node.respond_pair(&pair_id, accept)
}

/// Forget a paired device. Returns whether it was paired.
#[tauri::command]
fn unpair_device(node: State<'_, Arc<Node>>, device_id: String) -> Result<bool, String> {
    node.unpair_device(&device_id).map_err(|e| e.to_string())
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

/// Register every command the window can call.
fn with_commands<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        me,
        devices,
        send_files,
        respond,
        pair_device,
        respond_pair,
        unpair_device
    ])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    with_commands(tauri::Builder::default())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let sink: EventSink = Arc::new(move |event: AppEvent| {
                let _ = handle.emit(EVENT, event);
            });
            // OPENDROP_NAME, OPENDROP_DIR and OPENDROP_CONFIG_DIR let two
            // copies run side by side on one machine for testing.
            let download_dir = std::env::var_os("OPENDROP_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    app.path()
                        .download_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("OpenDrop")
                });
            let name = std::env::var("OPENDROP_NAME").unwrap_or_else(|_| device_name());
            let config_dir = default_config_dir();
            let identity =
                DeviceIdentity::load_or_create(&config_dir, name).map_err(|e| e.to_string())?;
            // A damaged paired-devices file must not stop the app: start with
            // nothing paired, leave the file alone, and say so in the window.
            let (paired, warning) = match PairedDevices::load(&config_dir) {
                Ok(paired) => (paired, None),
                Err(e) => (PairedDevices::in_memory(), Some(e.to_string())),
            };
            let paired = Arc::new(paired);
            app.manage(Warning(warning));
            let node = tauri::async_runtime::block_on(async move {
                // Prefer the standard port so CLI peers can reach us by IP
                // alone; if something already has it, take any port (mDNS
                // advertises the real one).
                match Node::start_with_config(
                    identity.clone(),
                    Arc::clone(&paired),
                    DEFAULT_PORT,
                    download_dir.clone(),
                    true,
                    sink.clone(),
                    Some(config_dir.clone()),
                )
                .await
                {
                    Ok(node) => Ok(node),
                    Err(_) => {
                        Node::start_with_config(
                            identity,
                            paired,
                            0,
                            download_dir,
                            true,
                            sink,
                            Some(config_dir),
                        )
                        .await
                    }
                }
            })
            .map_err(|e| e.to_string())?;
            app.manage(node);
            Ok(())
        })
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
    use super::*;
    use node::PairStatus;
    use serde_json::{Value, json};
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context};
    use tauri::webview::InvokeRequest;
    use tokio::sync::mpsc;

    fn invoke(
        webview: &tauri::WebviewWindow<MockRuntime>,
        cmd: &str,
        args: Value,
    ) -> Result<Value, Value> {
        get_ipc_response(
            webview,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: if cfg!(windows) {
                    "http://tauri.localhost"
                } else {
                    "tauri://localhost"
                }
                .parse()
                .unwrap(),
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.into(),
            },
        )
        .map(|body| body.deserialize::<Value>().unwrap())
    }

    async fn start_node(name: &str) -> (Arc<Node>, mpsc::UnboundedReceiver<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let sink: EventSink = Arc::new(move |e| {
            let _ = tx.send(e);
        });
        let node = Node::start(
            DeviceIdentity::new(name),
            Arc::new(PairedDevices::in_memory()),
            0,
            std::env::temp_dir(),
            false,
            sink,
        )
        .await
        .unwrap();
        (node, rx)
    }

    async fn next_code(rx: &mut mpsc::UnboundedReceiver<AppEvent>) -> String {
        loop {
            if let Some(AppEvent::PairCode { pair_id, .. }) = rx.recv().await {
                return pair_id;
            }
        }
    }

    async fn next_done(rx: &mut mpsc::UnboundedReceiver<AppEvent>) -> PairStatus {
        loop {
            if let Some(AppEvent::PairDone { status, .. }) = rx.recv().await {
                return status;
            }
        }
    }

    /// The pairing commands, called through Tauri's IPC like the window
    /// does, reach the node and report back.
    #[test]
    fn pairing_commands_work_over_ipc() {
        let (mac, mut mac_events) = tauri::async_runtime::block_on(start_node("Mac"));
        let (pc, mut pc_events) = tauri::async_runtime::block_on(start_node("PC"));
        let app = with_commands(mock_builder())
            .build(mock_context(tauri::test::noop_assets()))
            .unwrap();
        app.manage(Arc::clone(&mac));
        app.manage(Warning(None));
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();

        let me = invoke(&window, "me", json!({})).unwrap();
        assert_eq!(me["id"], mac.identity.id.as_str());
        assert_eq!(me["warning"], Value::Null);
        assert_eq!(invoke(&window, "devices", json!({})).unwrap(), json!([]));

        // Unknown device and pairing ids are reported, not panics.
        let err = invoke(&window, "pair_device", json!({"deviceId": "device-nope"})).unwrap_err();
        assert!(
            err.as_str().unwrap().contains("no longer on the network"),
            "{err}"
        );
        let answer = json!({"pairId": "pair-404", "accept": true});
        assert_eq!(
            invoke(&window, "respond_pair", answer).unwrap(),
            json!(false)
        );
        let unknown = json!({"deviceId": pc.identity.id});
        assert_eq!(
            invoke(&window, "unpair_device", unknown).unwrap(),
            json!(false)
        );

        // Pair (discovery is off here, so start by address), confirming the
        // Mac's code through the command.
        let pc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], pc.port));
        tauri::async_runtime::block_on(mac.pair_with_addrs(&[pc_addr])).unwrap();
        let (mac_pair, pc_pair) = tauri::async_runtime::block_on(async {
            (
                next_code(&mut mac_events).await,
                next_code(&mut pc_events).await,
            )
        });
        assert!(pc.respond_pair(&pc_pair, true));
        let answer = json!({"pairId": mac_pair, "accept": true});
        assert_eq!(
            invoke(&window, "respond_pair", answer).unwrap(),
            json!(true)
        );
        let status = tauri::async_runtime::block_on(next_done(&mut mac_events));
        assert_eq!(status, PairStatus::Paired);
        assert!(mac.paired.get(&pc.identity.id).is_some());

        let paired = json!({"deviceId": pc.identity.id});
        assert_eq!(
            invoke(&window, "unpair_device", paired).unwrap(),
            json!(true)
        );
        assert!(mac.paired.list().is_empty());
    }

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
