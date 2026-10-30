# OpenDrop

Cross-platform, AirDrop-style file sharing over the local network (macOS, Windows, Linux).
No accounts, no cloud: every device runs the same app and talks directly to its peers.

**Status:** Phase 1, Task 1 done. Two devices can exchange messages over TCP using a
manually entered IP address. mDNS discovery (Task 2) and file transfer (Task 3) are next.

## Try it

You need Rust (`rustup.rs`). On the receiving machine:

```bash
cargo run -- listen
```

It prints the address other devices should use, e.g. `192.168.1.20:45454`. On the sending
machine:

```bash
cargo run -- send 192.168.1.20 "hello from my Mac"
```

Both on one machine? Use two terminals and `127.0.0.1`.

Options: `--port PORT` (default 45454) and `--name NAME` (defaults to the hostname).
Run the tests with `cargo test`.

If the connection times out between two machines, check that both are on the same network
and that the receiver's firewall allows incoming connections on port 45454 (macOS will
prompt the first time; on Windows allow it in the Defender dialog).

## Layout

| Path | Responsibility |
|---|---|
| `src/main.rs` | CLI: `listen` and `send` commands |
| `src/lib.rs` | Library root, so the Tauri app can reuse everything later |
| `src/protocol/` | Message types, versioning, length-prefixed framing |
| `src/network/server.rs` | Accepts connections, one Tokio task per peer |
| `src/network/client.rs` | Connects to a peer and exchanges messages |
| `src/discovery/` | mDNS advertising and browsing (Task 2, stub) |
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
