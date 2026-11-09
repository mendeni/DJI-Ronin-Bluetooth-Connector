## WebSocket control bridge

Enable the WebSocket listener in Preferences to receive pan/tilt commands (default port `81`). The listener is disabled by default and binds only to loopback unless **Allow connections from remote hosts** is explicitly enabled. Token authentication is also enabled by default and uses a nonce-based HMAC-SHA256 challenge-response; the token itself is not sent over the network. The token is stored in the macOS Keychain. See [`docs/websocket-control.md`](docs/websocket-control.md) for client details.

## OSC control bridge

Enable the OSC listener in Preferences to receive OSC over UDP (default port `8000`). OSC is disabled and loopback-only by default. OSC does not provide authentication; use a VPN or tunnel for remote control. See [`docs/osc-control.md`](docs/osc-control.md) for details.

