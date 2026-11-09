# WebSocket bridge requirements

## Scope

The macOS host can accept WebSocket text frames and translate normalized pan/tilt input into the existing gimbal speed-control path. This is a velocity control bridge, not an absolute positioning API.

## Preferences

- WebSocket listener is disabled by default and listens on port `81` when enabled; the user may select another valid TCP port (1–65535).
- The listener binds to loopback by default. Enabling **Allow connections from remote hosts** deliberately exposes it on all interfaces; use a trusted network or VPN.
- Token authentication is enabled by default and stored in the macOS Keychain. It can be disabled in Preferences; the listener remains loopback-only unless remote access is explicitly enabled.
- With authentication enabled, clients use a per-connection HMAC-SHA256 challenge-response; the token itself is never sent over the WebSocket. A successful response is required within five seconds.
- Preferences exposes independent maximum pan and tilt command strengths, each from `0%` to `100%` (default `50%`). Each axis is capped independently while preserving the command sign.
- Preferences exposes an optional WebSocket diagnostics logging toggle. Rejected command text is sanitized before it is written to `~/Library/Logs/RoninStudio-WebSocket.log`.
- The listener accepts at most eight simultaneous connections. Browser WebSocket handshakes carrying an `Origin` header are rejected.

## Message protocol

- When token authentication is enabled, the server sends `nonce:<uuid>` as its first text frame on each connection. The client replies `auth:<hex-hmac>` where `hex-hmac` is the lowercase or uppercase hex encoding of HMAC-SHA256 using the access token's UTF-8 bytes as the key and the nonce's UTF-8 bytes as the message. The nonce is single-use. The server responds `ready` after successful authentication.
- If token authentication is disabled, send motion commands immediately; no challenge or auth frame is expected.
- A motion frame contains one or two fields: `pan:X`, `tilt:Y`, or both, such as `pan:0.6 tilt:-0.2`. Fields may be separated by whitespace or a comma. Duplicate or unknown fields are invalid.
- Values are finite numbers normalized to `[-1, 1]`; values outside that interval are clamped. Positive pan is right; positive tilt is up. An omitted axis is commanded as zero for that frame; it does not retain its previous speed. Preferences limits further cap each axis magnitude.
- Valid motion frames receive `ok`. Invalid or oversized frames are rejected without generating motion. A connection that stops sending updates is stopped automatically after 600 ms; send updates at about 10 Hz for continuous movement.
- Enabling token authentication while connections are open immediately issues fresh challenges and gates subsequent commands. Disabling it removes the auth requirement. Regenerating the token closes existing connections.

## Safety and networking

A WebSocket handshake containing an `Origin` header is rejected to prevent browser pages from connecting to the local control service. The token is protected by the Keychain's `WhenUnlocked` accessibility class. Remote access should use a trusted VPN or authenticated tunnel; do not expose the listener directly to the public Internet. The limits cap command speed only. They are not angular/travel boundaries: the gimbal does not provide position feedback needed to guarantee physical pan/tilt stops.

## Examples

With authentication enabled, first read the nonce frame and calculate its HMAC-SHA256 response using the token from Preferences:

```text
server: nonce:12345678-1234-1234-1234-123456789abc
client: auth:<64 hex characters>
server: ready
client: pan:0.6
server: ok
client: tilt:0.9
server: ok
```

With authentication disabled, omit the challenge-response and send motion commands directly:

```text
pan:0.6
tilt:0.9
pan:0.4 tilt:-0.2
pan:0 tilt:0
```

A pan-only frame commands zero tilt, and a tilt-only frame commands zero pan. A client should resend the desired command periodically while movement is intended. Stopping updates causes the bridge to send a stop command after the timeout.
