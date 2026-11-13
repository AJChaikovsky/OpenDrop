# Changelog

All notable changes to OpenDrop. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

The first release: AirDrop-style sharing between macOS, Windows and Linux on the
local network, with no accounts and no cloud.

### Sharing
- Devices find each other over mDNS within a few seconds; no setup or IP addresses.
- Send files and whole folders by clicking a device or dragging onto it. The other side
  accepts or declines (declined automatically after 60 seconds). Files are checked with
  SHA-256 before they're saved to `Downloads/OpenDrop`.
- Progress and speed on both ends, and cancelling from either side.
- Fetching: ask a paired device for one of its files, which its owner approves.
- Send clipboard text to a device; it lands on the other device's clipboard after approval.

### Security
- Pairing with a 6-digit code that both people confirm.
- Every connection is encrypted (X25519 key exchange, ChaCha20-Poly1305) and
  authenticated with each device's Ed25519 identity. Unpaired devices are labeled
  unverified.
- An audit log of every request from AI assistants (`opendrop audit`, and Activity in
  the app).

### Desktop app
- Tauri 2 + React app for macOS, Windows and Linux.
- Transfer history that survives a restart, with "Show in folder".
- Keeps running in the system tray / menu bar when the window is closed, and notifies
  you when something needs an answer.
- "Send with OpenDrop" in the right-click menu (Finder Quick Action on macOS, Explorer
  on Windows), switched on from the app.

### AI assistants
- `opendrop mcp`: an MCP server that lets an assistant such as Claude Desktop list
  paired devices, fetch files from them and send files to them, with your approval on
  each device and time-limited folder grants.

### CLI
- `opendrop listen`, `peers`, `send`, `send-file`, `pair`, `devices`, `share`, `files`,
  `fetch`, `audit` and `mcp`, for scripting and headless machines.

### Known limitations
- The installers aren't code-signed yet; the README explains the one-time step to open
  them on macOS and Windows.
- Protocol v3 doesn't talk to builds from before v3 (encryption).

[0.1.0]: https://github.com/AJChaikovsky/OpenDrop/releases/tag/v0.1.0
