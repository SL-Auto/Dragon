---
title: Chisel comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# Chisel comprehensive source analysis

## Scope and safety

Static analysis only of official revision `6d283495b5e3eff76841038d679fcc53a57ba7dd`. The source was cloned temporarily in WSL, was not built or run, and no binaries or payloads were retained. Immutable citations below use that revision.

## Completeness inventory

All deployed Go packages were inventoried: `client`, `server`, `share/settings`, `share/tunnel`, `share/cnet`, `share/cio`, `share/ccrypto`, command dispatch in `main.go`, and configuration/environment handling. Tests, CI, examples, documentation, and static web assets were excluded as non-deployed evidence. The inventory covers client/server lifecycle, WebSocket-plus-SSH transport, HTTP and SOCKS upstream proxies, TLS/mTLS, authentication and ACLs, forward/reverse TCP and UDP, SOCKS5, stdio, keepalive/retry, HTTP reverse-proxy camouflage, and teardown.

## Procedure analysis

| ID | Procedure-level behavior | Interfaces and ordered effect | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- |
| CH-P01 | Persistent client transport | Converts HTTP(S) to WS(S), connects to a server, performs SSH over WebSocket, submits tunnel configuration, maintains keepalives, and reconnects with backoff. | Process-correlated network connections, HTTP upgrade/TLS metadata, flow duration and recurrence. Encryption hides SSH/configuration; network-only attribution is weak. | T1090, T1572 | High |
| CH-P02 | Forward TCP proxy | Client creates a local TCP listener; accepted connections open an SSH `chisel` channel and the peer connects to the configured destination. | EDR listen plus outbound connection joined by process/entity; flow logs on both legs. A listener alone is common. | T1090.001, T1572 | High |
| CH-P03 | Forward UDP proxy | Client creates a UDP listener and multiplexes datagrams through the SSH tunnel to a UDP destination. | EDR UDP bind/send plus stable encrypted egress; many sensors do not expose UDP bind ownership. | T1090.001, T1572 | High |
| CH-P04 | Reverse TCP/UDP proxy | Client requests reverse remotes; server binds the exposed listener and sends accepted traffic back through the encrypted channel for client-side destination connection. | On each endpoint, correlate listen/accept with tunnel egress and uncommon cross-boundary destination access. Distributed endpoints prevent a single-host join. | T1090.001, T1572 | High |
| CH-P05 | Forward or reverse SOCKS5 | A local proxy accepts SOCKS5 requests; destinations are selected per connection and carried through SSH subject to server configuration and ACL. | SOCKS protocol metadata where available, dynamic fanout by one process, listener plus encrypted parent flow. TLS hides tunneled destinations from the tunnel observer. | T1090.001, T1572 | High |
| CH-P06 | Stdio tunnel bridge | A single non-reverse remote binds standard input/output rather than a socket and opens the same tunnel channel to the destination. | Process lineage, pipe/stdio handle telemetry, and network connection from the same process. Generic socket-only rules miss this branch. | T1572 | High |
| CH-P07 | Upstream proxy chaining | Client reaches its server through HTTP CONNECT or SOCKS5/SOCKS5H, optionally with proxy credentials and proxy-side DNS. | Proxy logs plus endpoint process-network correlation; downstream tunnel and ordinary approved proxy use overlap. | T1090.003, T1572 | High |
| CH-P08 | Server listener and HTTP camouflage | Server listens for WebSocket upgrades, may terminate TLS/mTLS, authenticates SSH users/ACLs, and may reverse-proxy non-tunnel HTTP requests to a configured backend. | Server process listen/accept, web upgrade/subprotocol, reverse-proxy upstream connection, authentication logs if collected. Generic web servers overlap. | T1090, T1572 | High |
| CH-P09 | Authentication and authorization state | Server loads/pins users, watches an auth file, verifies password and destination ACL, and client may verify server key fingerprints. | File read/change telemetry and application audit; externally invisible when application logs are absent. Compensate with resulting accepted/denied network behavior. | T1078 (context dependent) | High |
| CH-P10 | Connection maintenance and teardown | Keepalive requests detect dead paths; cancellation or retry exhaustion closes SSH, listeners, UDP state, and proxy connections. | Recurrent connect/disconnect sequences and socket close telemetry; normal unstable applications overlap. | T1572 | High |

## Evidence

- [Client transport/configuration](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/client/client.go#L73-L203)
- [WebSocket and SSH handshake/config request](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/client/client_connect.go#L77-L143)
- [Reconnect/backoff lifecycle](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/client/client_connect.go#L20-L74)
- [Remote grammar and TCP/UDP/reverse/stdio branches](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/share/settings/remote.go#L43-L132)
- [Listener creation and channel forwarding](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/share/tunnel/tunnel_in_proxy.go#L33-L161)
- [SSH channel destination, ACL, SOCKS, UDP and TCP dispatch](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/share/tunnel/tunnel_out_ssh.go#L29-L112)
- [Keepalive and proxy binding](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/share/tunnel/tunnel.go#L74-L233)
- [Server authentication, key and transport configuration](https://github.com/jpillora/chisel/blob/6d283495b5e3eff76841038d679fcc53a57ba7dd/server/server.go#L24-L120)

## Safe validation

Use synthetic process/network fixtures or an authorized benign tunnel product exercising equivalent listener/egress relationships. Do not build or execute Chisel for validation. Verify normalized process identity, socket direction, UDP ownership, HTTP Upgrade visibility, correlation windows, and collection health independently.

