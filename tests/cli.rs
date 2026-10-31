//! End-to-end tests of the `opendrop` binary: pairing, restarts, unpairing
//! and a damaged paired-devices file.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_opendrop");

/// A running `opendrop listen`, with its output collected line by line.
struct Listener {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Listener {
    fn start(config: &Path, name: &str, port: u16, downloads: &Path) -> Self {
        let mut child = Command::new(BIN)
            .args(["listen", "--port", &port.to_string(), "--name", name])
            .arg("--config")
            .arg(config)
            .arg("--dir")
            .arg(downloads)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let (tx, lines) = mpsc::channel();
        for stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut buf = Vec::new();
                // A prompt's last line has no newline until the next output,
                // so tests wait for its first line ("Pairing code: ...").
                while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                    if n == 0 {
                        break;
                    }
                    let _ = tx.send(String::from_utf8_lossy(&buf).trim_end().to_owned());
                    buf.clear();
                }
            });
        }
        let mut listener = Self {
            child,
            stdin,
            lines,
            seen: Vec::new(),
        };
        listener.wait_for("Press Ctrl+C");
        listener
    }

    /// Wait up to 10 s for a line containing `text`; returns it.
    fn wait_for(&mut self, text: &str) -> String {
        if let Some(line) = self.seen.iter().find(|l| l.contains(text)) {
            return line.clone();
        }
        loop {
            match self.lines.recv_timeout(Duration::from_secs(10)) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(text) {
                        return line;
                    }
                }
                Err(_) => panic!(
                    "never saw {text:?}; output so far:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    fn answer(&mut self, text: &str) {
        writeln!(self.stdin, "{text}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn stop(mut self) -> Vec<String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.seen.extend(self.lines.try_iter());
        self.seen
    }
}

fn run(config: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The device id printed in `"Name" (device-...) listening on ...`.
fn device_id(line: &str) -> String {
    let start = line.find("(device-").unwrap() + 1;
    let end = start + line[start..].find(')').unwrap();
    line[start..end].to_owned()
}

/// The 6-digit code in a "Pairing code: 123456" prompt.
fn code(text: &str) -> String {
    let start = text.find("Pairing code: ").unwrap() + "Pairing code: ".len();
    text[start..start + 6].to_owned()
}

#[test]
fn pair_restart_devices_and_unpair() {
    let root = tempfile::tempdir().unwrap();
    let (pc_config, mac_config) = (root.path().join("pc"), root.path().join("mac"));
    let downloads = root.path().join("downloads");
    let port = free_port();
    let target = format!("127.0.0.1:{port}");

    // Pair: the Mac asks, both users answer yes.
    let mut pc = Listener::start(&pc_config, "PC", port, &downloads);
    let pc_id = device_id(&pc.wait_for("listening on port"));
    let pairing = std::thread::spawn({
        let mac_config = mac_config.clone();
        let target = target.clone();
        move || run(&mac_config, &["pair", &target, "--name", "Mac"], "y\n")
    });
    let prompt = pc.wait_for("Pairing code:");
    assert!(prompt.contains("\"Mac\""), "{prompt}");
    pc.answer("y");
    let paired = pairing.join().unwrap();
    let mac_output = text(&paired);
    assert!(paired.status.success(), "{mac_output}");
    assert!(
        mac_output.contains(&format!("Paired with \"PC\" ({pc_id})")),
        "{mac_output}"
    );
    assert_eq!(
        code(&mac_output),
        code(&prompt),
        "the two screens showed different codes"
    );
    pc.wait_for("Paired");
    let pc_log = pc.stop();
    let mac_id = device_id(pc_log.iter().find(|l| l.contains("wants to pair")).unwrap());

    // Restart both (each command is a fresh process): each lists the other.
    let pc = Listener::start(&pc_config, "PC", port, &downloads);
    let listed = text(&run(&mac_config, &["devices", "--wait", "0"], ""));
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with("Paired") && l.contains(&pc_id)),
        "{listed}"
    );
    let listed = text(&run(&pc_config, &["devices", "--wait", "0"], ""));
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with("Paired") && l.contains(&mac_id)),
        "{listed}"
    );
    // A new connection after the restart is recognised as paired.
    let sent = run(
        &mac_config,
        &["send", &target, "hello", "--name", "Mac"],
        "",
    );
    assert!(sent.status.success(), "{}", text(&sent));
    let mut pc = pc;
    pc.wait_for(&format!("({mac_id}), paired"));

    // Unpair on the Mac: its store forgets the PC at once...
    let unpaired = run(&mac_config, &["unpair", "PC"], "");
    assert!(unpaired.status.success(), "{}", text(&unpaired));
    let store = std::fs::read_to_string(mac_config.join("paired-devices.json")).unwrap();
    assert!(!store.contains(&pc_id), "{store}");
    // ...and the PC follows on the next connection.
    let sent = run(
        &mac_config,
        &["send", &target, "still there?", "--name", "Mac"],
        "",
    );
    assert!(sent.status.success(), "{}", text(&sent));
    let line = pc.wait_for("still there?");
    assert!(!line.contains("paired"));
    let connected: Vec<String> = pc
        .stop()
        .into_iter()
        .filter(|l| l.contains("connected:"))
        .collect();
    assert!(
        connected.last().is_some_and(|l| !l.contains("paired")),
        "{connected:?}"
    );
    let store = std::fs::read_to_string(pc_config.join("paired-devices.json")).unwrap();
    assert!(!store.contains(&mac_id), "{store}");
    let listed = text(&run(&pc_config, &["devices", "--wait", "0"], ""));
    assert!(!listed.contains(&mac_id), "{listed}");
}

#[test]
fn declined_pairing_leaves_both_unpaired() {
    let root = tempfile::tempdir().unwrap();
    let (pc_config, mac_config) = (root.path().join("pc"), root.path().join("mac"));
    let port = free_port();
    let mut pc = Listener::start(&pc_config, "PC", port, &root.path().join("dl"));
    let pairing = std::thread::spawn({
        let mac_config = mac_config.clone();
        move || run(&mac_config, &["pair", &format!("127.0.0.1:{port}")], "y\n")
    });
    pc.wait_for("Pairing code:");
    pc.answer("n");
    let output = pairing.join().unwrap();
    assert!(!output.status.success());
    assert!(text(&output).contains("declined"), "{}", text(&output));
    pc.stop();
    for config in [&pc_config, &mac_config] {
        let listed = text(&run(config, &["devices", "--wait", "0"], ""));
        assert!(!listed.contains("Paired"), "{listed}");
    }
}

#[test]
fn damaged_store_is_reported_and_listen_keeps_running() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("cfg");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("paired-devices.json"), b"\x00garbage{{{").unwrap();

    let port = free_port();
    let mut listener = Listener::start(&config, "PC", port, &root.path().join("dl"));
    listener.wait_for("paired-devices.json is unreadable");
    // Still serving: a peer can connect and send.
    let other = root.path().join("other");
    let sent = run(&other, &["send", &format!("127.0.0.1:{port}"), "hi"], "");
    assert!(sent.status.success(), "{}", text(&sent));
    listener.wait_for(": hi");
    listener.stop();

    // Commands that manage pairing stop with a clear message instead.
    for args in [
        &["devices", "--wait", "0"][..],
        &["unpair", "x"],
        &["pair", "127.0.0.1:1"],
    ] {
        let output = run(&config, args, "");
        assert!(!output.status.success(), "{args:?}");
        let shown = text(&output);
        assert!(
            shown.contains("paired-devices.json is unreadable"),
            "{shown}"
        );
        assert!(shown.contains("fix or delete it"), "{shown}");
    }
    assert_eq!(
        std::fs::read(config.join("paired-devices.json")).unwrap(),
        b"\x00garbage{{{"
    );
}

/// `opendrop transfers` reaches the running `listen` over the control API.
#[test]
fn transfers_asks_the_running_listener() {
    let config = tempfile::tempdir().unwrap();
    let downloads = tempfile::tempdir().unwrap();
    let out = run(config.path(), &["transfers"], "");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("start `opendrop listen` first"),
        "{out:?}"
    );
    let listener = Listener::start(config.path(), "Desk", 0, downloads.path());
    let out = run(config.path(), &["transfers"], "");
    listener.stop();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "No transfers since the daemon started."
    );
}
