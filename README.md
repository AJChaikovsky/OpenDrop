# OpenDrop

Cross-platform, AirDrop-style file sharing over the local network (macOS, Windows, Linux).
No accounts, no cloud: every device runs the same app and talks directly to its peers.

**Status:** Phase 1, Tasks 1 and 2 done. Devices find each other on the local network over
mDNS and exchange messages over TCP, by device name or IP address. File transfer (Task 3) is
next.

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

Names match case-insensitively; a device id (`device-1a2b3c4d`) works too. An IP still works:

```bash
cargo run -- send 192.168.1.20 "hello from my Mac"
```

Both on one machine? Use two terminals and give the second listener another port
(`--port 45455`, or `--port 0` to let the OS pick).

Options: `--port PORT` (default 45454), `--name NAME` (defaults to the hostname) and
`--wait SECONDS` (how long `peers` and `send DEVICE` browse; default 3).
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
| `src/main.rs` | CLI: `listen`, `peers` and `send` commands |
| `src/lib.rs` | Library root, so the Tauri app can reuse everything later |
| `src/protocol/` | Message types, versioning, length-prefixed framing |
| `src/network/server.rs` | Accepts connections, one Tokio task per peer |
| `src/network/client.rs` | Connects to a peer and exchanges messages |
| `src/discovery/` | mDNS advertising, browsing and the discovered-peer table |
| `src/transfer/` | Chunked file streaming (Task 3, stub) |

## Protocol (v1)

Each control message is one frame: a 4-byte big-endian length followed by that many bytes of
UTF-8 JSON. Frames over 64 KiB are rejected before any allocation. Every message carries
`version` and `type`:

```json
{"version": 1, "type": "hello", "device_id": "device-1a2b3c4d", "device_name": "MacBook Pro"}
```

| Type | Direction | Fields |
|---|---|---|
| `hello` | client to server, first message | `device_id`, `device_name` |
| `welcome` | server reply to `hello` | `device_id`, `device_name` |
| `text` | client to server | `body` |
| `text_ack` | server reply to `text` | `received_bytes` |
| `error` | either, then close | `code` (`unsupported_version`, `unexpected_message`, `bad_message`), `message` |

A peer with a different `version` gets an `unsupported_version` error rather than a parse
failure. Reads time out after 10 seconds so a stalled peer can't hold a connection open.

## Discovery

Each device advertises one `_opendrop._tcp.local.` instance named after its device id, on its
TCP port, with TXT properties `device_id`, `device_name` (cut to 200 bytes) and
`protocol_version` (`1`). It browses for the same service type at the same time, ignores its
own instance, adds peers when they resolve and drops them when their instance is removed
(`listen` unregisters on Ctrl+C, so peers see it leave right away). A peer advertising a
different `protocol_version` is still listed, marked incompatible.
