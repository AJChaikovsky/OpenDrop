# OpenDrop

Cross-platform, AirDrop-style file sharing over the local network (macOS, Windows, Linux).
No accounts, no cloud: every device runs the same app and talks directly to its peers.

**Status:** Phase 1 done (Tasks 1-3), plus an MVP desktop app. Devices find each other on the
local network over mDNS and send each other messages and files over TCP, by device name or IP
address. Files are verified with SHA-256 before they're saved.

## Desktop app

`app/` is a Tauri 2 + React + TypeScript app on top of the same crate. It lists nearby
devices, sends files you pick (click a device) or drag onto a device, asks before saving
each incoming file (Accept / Decline, declined automatically after 60 s), and shows progress
and speed on both ends. Received files go to `Downloads/OpenDrop`. It talks to the CLI too.

Click **Pair** under a device to pair with it: both screens show the same 6-digit code, and
pairing only completes once both people press Confirm (Cancel, or 60 s without an answer,
leaves both unpaired). Paired devices get a **Paired** badge; **Unpair** is in the device's
`⋯` menu, and the other device drops its badge the next time the two connect (the app
connects right away when the device is on the network).

You need Rust and Node 18+ (on Windows, WebView2, which Windows 11 ships with):

```bash
cd app
npm install
npm run tauri dev
```

`npm run tauri build` makes an installable app. `npm test` runs the UI tests and
`cargo test -p opendrop-app` the app backend's. To run two copies on one machine, start the
second with `OPENDROP_NAME`, `OPENDROP_DIR` and `OPENDROP_CONFIG_DIR` set (the last gives
it its own key); it picks a free port if 45454 is taken.

## Try it

You need Rust (`rustup.rs`). On the receiving machine:

```bash
cargo run -- listen
```

It advertises itself on the local network, prints the address other devices can use (e.g.
`192.168.1.20:45454`), and lists nearby OpenDrop devices as they appear and disappear. On
another machine, see who's around and send by name:

```bash
cargo run -- peers
cargo run -- send "AJ's MacBook" "hello from my PC"
```

Send files the same way (one or more per command, with live progress):

```bash
cargo run --release -- send-file "AJ's MacBook" photo.jpg notes.pdf
```

The receiver saves them to `~/Downloads/OpenDrop` (change with `listen --dir DIR`). Existing
files are never overwritten: a second `photo.jpg` becomes `photo (1).jpg`. Folders aren't
supported yet.

The receiver is asked about every file before anything is written:

```text
? "AJ's MacBook" (192.168.1.53) wants to send you "photo.jpg" (2.1 MB).
  Accept? [y/N] (within 60s):
```

Anything but `y`/`yes`, or no answer within 60 seconds, declines it; the sender is told and
moves on to its next file. `listen --auto-accept` skips the question (handy for scripted
tests, not for everyday use).

Names match case-insensitively; a device id (`device-1a2b3c4d`) works too. An IP still works:

```bash
cargo run -- send 192.168.1.20 "hello from my Mac"
```

Both on one machine? Use two terminals and give the second listener another port
(`--port 45455`, or `--port 0` to let the OS pick) and its own `--config DIR`.

### Identity and pairing

Each device has an Ed25519 key, made on first start and kept in its config folder
(`identity.key`, readable only by you): `~/Library/Application Support/OpenDrop` on macOS,
`%APPDATA%\OpenDrop` on Windows, `~/.config/OpenDrop` on Linux, or `OPENDROP_CONFIG_DIR` /
`--config DIR`. The device id (`device-` plus 16 hex digits) is derived from the public key,
so it stays the same across restarts; deleting the key file gives the device a new id.

Pair two devices once so each remembers the other's key:

```bash
cargo run -- pair "AJ's MacBook"      # on one device, with `listen` running on the other
```

Both terminals show the same code and ask `Does "..." show the same code? [y/N]`; only if
both answer `y` within 60 seconds are they paired. Then:

```bash
cargo run -- devices                  # Paired / Unpaired / Incompatible, plus offline paired devices
cargo run -- unpair "AJ's MacBook"    # forget it; the other side follows on the next connection
```

Paired devices are stored in `paired-devices.json` next to the key. If that file is damaged,
`listen` warns and carries on with nothing paired (leaving the file alone), while `pair`,
`devices` and `unpair` stop and say which file to fix or delete.

Options: `--port PORT` (default 45454), `--name NAME` (defaults to the hostname),
`--dir DIR` (where `listen` saves files), `--config DIR` (key and paired devices),
`--auto-accept` (`listen` takes files without
asking) and `--wait SECONDS` (how long `peers`, `send` and `send-file` look for a device by
name; default 3). Use `--release` for large files; debug
builds hash much more slowly.
Run the tests with `cargo test`; `cargo test -- --ignored` also runs a discovery test over
real multicast on this machine.

If the connection times out between two machines, check that both are on the same network
and that the receiver's firewall allows incoming connections on port 45454 (macOS will
prompt the first time; on Windows allow it in the Defender dialog). If `peers` finds nothing,
the network may block multicast (common on guest and corporate Wi-Fi, and with some VPNs);
sending by IP still works.

## Layout

| Path | Responsibility |
|---|---|
| `src/main.rs` | CLI: `listen`, `peers`, `send`, `send-file`, `pair`, `devices` and `unpair` |
| `src/lib.rs` | Library root, so the Tauri app can reuse everything later |
| `src/protocol/` | Message types, versioning, length-prefixed framing |
| `src/identity.rs` | The device key pair, its file, and the device id derived from it |
| `src/network/handshake.rs` | Signed handshake: proves each side holds its key |
| `src/pairing/` | Pairing protocol and 6-digit code; `store.rs` keeps paired devices |
| `src/network/server.rs` | Accepts connections, one Tokio task per peer |
| `src/network/client.rs` | `Connection`: connects to a peer, sends texts and files |
| `src/discovery/` | mDNS advertising, browsing and the discovered-peer table |
| `src/transfer/` | Chunked streaming with SHA-256, temp files, safe file names |
| `app/src-tauri/src/node.rs` | Desktop app backend: receive with approval, send, pair, progress and speed events |
| `app/src-tauri/src/lib.rs` | Tauri commands and event forwarding |
| `app/src/` | React UI: device list, drop targets, accept and pairing dialogs, transfers |

## Protocol (v2)

Each control message is one frame: a 4-byte big-endian length followed by that many bytes of
UTF-8 JSON. Frames over 64 KiB are rejected before any allocation. Every message carries
`version` and `type`:

```json
{"version": 2, "type": "text", "body": "hi"}
```

Keys, nonces and signatures travel as lowercase hex.

| Type | Direction | Fields |
|---|---|---|
| `hello` | client to server, first message | `device_id`, `device_name`, `public_key`, `nonce` |
| `welcome` | server reply to `hello` | `device_id`, `device_name`, `public_key`, `nonce`, `paired`, `signature` |
| `hello_proof` | client reply to `welcome` | `paired`, `signature` |
| `ready` | server, once the proof checks out | |
| `pair_request` | client | `commitment` (SHA-256 of its pairing nonce) |
| `pair_nonce` | server reply | `nonce` |
| `pair_reveal` | client | `nonce` (the committed one) |
| `pair_accept` / `pair_decline` | each side, exactly once | `pair_decline` has `timed_out` |
| `text` | client to server | `body` |
| `text_ack` | server reply to `text` | `received_bytes` |
| `file_offer` | client to server | `transfer_id`, `name` (bare file name), `size` |
| `file_accept` | server reply to `file_offer` | `transfer_id` |
| `file_decline` | server reply to `file_offer`; connection stays open | `transfer_id` |
| `file_done` | client, after the raw bytes | `transfer_id`, `sha256` (lowercase hex) |
| `file_received` | server, once verified and saved | `transfer_id`, `received_bytes` |
| `error` | either, then close | `code` (`unsupported_version`, `unexpected_message`, `bad_message`, `file_rejected`, `checksum_mismatch`, `storage_error`, `identity_mismatch`, `pairing_failed`), `message` |

A peer with a different `version` gets an `unsupported_version` error rather than a parse
failure. Reads time out after 10 seconds so a stalled peer can't hold a connection open.

### Handshake

Each side signs a transcript of both public keys and both fresh nonces (plus its `paired`
flag): the server in `welcome`, the client in `hello_proof`. Since each signature covers a
nonce the other side just picked, old signatures can't be replayed, and copying a device's
id or public key is useless without its private key. The device id must also be the
fingerprint of the presented key, and a paired device must present the key stored for it.
Any failure ends the connection with `identity_mismatch` before anything else is read. The
`paired` flags keep pairing in sync: if one side unpaired, the other forgets it too.

### Pairing

After the handshake, the client sends a commitment to a random nonce, the server answers with
its own nonce, and the client reveals its nonce. Both sides then show a 6-digit code hashed
from both keys and all four nonces and ask their user. Because the client commits first and
the server answers before the reveal, a man in the middle can't pick nonces that make the
codes on the two real screens match. Each side sends one `pair_accept` or `pair_decline`; a
decline withdraws the other side's prompt. Both store each other only if both accepted
within 60 seconds.

### File transfer

The receiver answers each `file_offer` only once its user has decided (the sender waits up
to 70 seconds). The receiver can report progress and the saved path through
`server::run_with_events`, which the desktop app uses. After `file_accept`, the sender writes exactly `size` bytes of file content straight onto the
socket (unframed, in 64 KiB chunks), then a `file_done` frame. The receiver strips any
directory parts and unsafe characters from `name` and streams the bytes into a hidden
`.opendrop-*.part` file in the download folder, hashing as it goes. Only if its SHA-256
matches `file_done` is the file synced and renamed into place, then confirmed with
`file_received`. On a mismatch, a dropped connection or a stall, the temp file is deleted.
Several files (and texts) can be sent over one connection, one after another.

## Discovery

Each device advertises one `_opendrop._tcp.local.` instance named after its device id, on its
TCP port, with TXT properties `device_id`, `device_name` (cut to 200 bytes) and
`protocol_version` (`2`). It browses for the same service type at the same time, ignores its
own instance, adds peers when they resolve and drops them when their instance is removed
(`listen` unregisters on Ctrl+C, so peers see it leave right away). A peer advertising a
different `protocol_version` is still listed, marked incompatible.
