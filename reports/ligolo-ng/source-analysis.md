---
title: Ligolo-ng comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# Ligolo-ng comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `e543732f4be6dc899096ae322ae620bf010bfbfc` (tag `v0.9.2`, committed 2026-09-25) from <https://github.com/nicocha30/ligolo-ng>, accessed 2026-11-21.
- **Handling:** the source was cloned to `sources/ligolo-ng-src/` (gitignored). It was not built or run, and the checkout contains no binaries. Citations below use the pinned revision.
- **Eligibility:** Ligolo-ng has two components.
  - The **agent** (`cmd/agent`, `pkg/agent`, `pkg/relay`, plus shared `pkg/protocol`, `pkg/utils`, `pkg/tlsutils`) executes on the compromised host. It is in scope.
  - The **proxy** (`cmd/proxy`, `pkg/proxy`, `pkg/controller`, `web/`) runs on operator infrastructure, where it creates a TUN interface, runs a userland network stack and hosts the console and web UI. It is out of scope. It was read only to interpret which agent requests it sends ([`pkg/proxy/netstack/handlers.go` L60, L206-214](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/proxy/netstack/handlers.go#L60), [`pkg/proxy/listeners.go` L52](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/proxy/listeners.go#L52)). No proxy-side procedure or detection is produced.

## Completeness inventory

| Path | Lines | Role | Disposition |
| --- | --- | --- | --- |
| `cmd/agent/main.go` | 354 | Flags, connect/bind modes, TLS, WebSocket, upstream proxy, yamux session, retry/reconnect | Analyzed |
| `pkg/agent/handler.go` | 381 | Dispatch of every agent request type | Analyzed |
| `pkg/agent/smartping/pinger.go` | 89 | ICMP probe (raw socket or `ping` child process) | Analyzed |
| `pkg/agent/neterror/*.go` | 76 | Mapping socket errors to RST/unreachable replies | Analyzed (no separate observable) |
| `pkg/relay/relay.go` | 287 | TCP, packet, framed-UDP and UDP-listener relays | Analyzed |
| `pkg/protocol/*.go` | 641 | Message types and encoding | Analyzed (wire format only) |
| `pkg/utils/ligolourl.go` | 107 | Connect-URL scheme parsing (TCP vs ws/wss/http/https) | Analyzed |
| `pkg/tlsutils/*.go` | 244 | Self-signed certificate for bind mode | Analyzed |
| `pkg/utils/codenames/*` | 1303 | Word lists for proxy-side naming | Excluded (not used by the agent's behavior) |
| `cmd/proxy`, `pkg/proxy`, `pkg/controller`, `web/` | 4,000+ | Operator proxy, TUN, console, web UI | Excluded (attacker infrastructure) |
| `*_test.go`, `doc/`, `Makefile` | n/a | Tests, documentation and build | Excluded (non-deployed) |

The agent answers exactly the request types in [`pkg/protocol/packets.go` L30-46](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/protocol/packets.go#L30-L46):
- info
- connect
- host ping
- listener start, bind, sock and close
- agent kill

Each is dispatched in [`HandleConn`, `handler.go` L102-381](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L102-L381). Every branch is mapped to a procedure below.

## Procedure analysis

| ID | Procedure | Trigger, ordered behavior and OS interfaces | Security effect and artifacts | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| LG-P01 | Outbound tunnel transport and reconnect | `-connect` starts the session. It uses either a direct TCP dial plus TLS client (optional fingerprint pinning or `-ignore-cert`) or a WebSocket dial for `ws/wss/http/https` URLs, with a fixed default Chrome/103 User-Agent. Either can go through an HTTP or SOCKS5 upstream proxy. The agent then runs a yamux server (60 s keepalive). Retries are every 5 s; reconnects every 20 s for up to 300 s. | Encrypted control channel from the compromised host to operator infrastructure. No files are written. | Process-attributed outbound connection, proxy and HTTP logs, TLS metadata. An idle tunnel is one long-lived TLS flow and is weak alone. The User-Agent is mutable but is the default. | T1572, T1090, T1071.001, T1573.002 | High |
| LG-P02 | Bind mode (inbound tunnel) | `-bind ip:port` creates a self-signed certificate, listens on TCP and runs the same yamux session over each accepted TLS connection. | The compromised host accepts the operator's inbound connection instead of dialing out. | Listen and inbound accept by the agent process, followed by pivot connections. An inbound listener alone is common. | T1572, T1090 | High |
| LG-P03 | Host and interface reporting | An info request reads hostname, current username and every network interface (addresses, MTU, flags), and returns them with a MAC-derived session ID. | Discovery data sent to the operator. | API reads (`os.Hostname`, `user.Current`, `net.Interfaces`) produce no standard telemetry. | T1082, T1016, T1033 | High |
| LG-P04 | TCP/UDP pivot connections | A connect request makes the agent dial the operator-chosen IPv4/IPv6 TCP or UDP destination with a 5 s timeout. It replies established, refused or reset (`neterror` maps connection reset or abort to RST), then relays bytes or framed datagrams. Operator traffic and scans through the proxy's TUN interface each become one agent-side dial. | The compromised host becomes a router into internal networks. Scans appear as many full connection attempts from one process. | Process-attributed outbound connections to many internal IPs/ports from the process that also holds the tunnel. Packet-level scan signatures (SYN-only) disappear, because the agent completes every dial. | T1090.001, T1572, T1046 | High |
| LG-P05 | Agent-host loopback access | The proxy rewrites destinations in `240.0.0.0/4` to `127.0.0.1` before sending a connect request, so the agent dials its own host's loopback services. | Remote access to services bound only to localhost on the compromised host. | Loopback connections from the tunnel process. These are observationally equivalent to LG-P04, with the destination in `127.0.0.0/8`. | T1090.001 | High |
| LG-P06 | ICMP host discovery | A ping request first tries a raw ICMP echo (privileged; forced on Windows). If that fails, the agent runs the system `ping` with fixed arguments: `ping /n 1 /w 3000 <target>` on Windows, `ping -c 1 -W 3 <target>` elsewhere. Addresses in `240.0.0.0/4` short-circuit to "alive". | Host discovery of internal ranges on the operator's behalf. | Child `ping` processes with an exact argument shape, spawned by a non-shell parent, one per target. The raw-ICMP branch has no per-process telemetry in common sensors. | T1018 | High |
| LG-P07 | Agent-side listeners (reverse forwarding and double pivot) | A listener request binds a TCP or UDP socket on the requested address. Accepted TCP connections are relayed back over the tunnel after a sock request; UDP datagrams are relayed by the listener relay. A close request closes the listener. | Exposes a port on the compromised host that forwards into the operator's network, or chains agents. | Listen by the process that also holds external tunnel egress, then inbound accepts. | T1090.001, T1572 | High |
| LG-P08 | Teardown and agent kill | A kill request calls `os.Exit(0)`. Listener close and relay shutdown release sockets. | Ends the session. No cleanup artifacts. | Process termination and socket close are generic and not distinctive. | T1572 (lifecycle) | High |
| LG-P09 | TLS trust configuration | `-ignore-cert` disables verification; `-accept-fingerprint` pins a SHA-256 certificate hash; SNI is taken from the connect host. | Determines the operator server the agent will trust. | Configuration only. Host telemetry sees just the resulting connection. Network TLS metadata (self-signed server certificate, SNI) is a compensating signal. | T1573.002 | High |

## Evidence

- [Agent flags, defaults and User-Agent, `main.go` L52-63](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L52-L63)
- [Connect loop, retry and reconnect, `main.go` L123-216](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L123-L216)
- [SOCKS5 upstream dial, `main.go` L220-229](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L220-L229)
- [yamux session and keepalive, `main.go` L232-254](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L232-L254)
- [Bind mode with self-signed certificate, `main.go` L256-287](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L256-L287)
- [WebSocket transport and HTTP proxy, `main.go` L290-354](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/cmd/agent/main.go#L290-L354)
- [Connect request handling, `handler.go` L112-165](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L112-L165)
- [Ping request, `handler.go` L166-175](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L166-L175), and [raw ICMP and `ping` child process, `pinger.go` L29-89](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/smartping/pinger.go#L29-L89)
- [Host info reply, `handler.go` L176-205](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L176-L205)
- [Listener start, bind, sock and close, `handler.go` L206-375](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L206-L375)
- [Agent kill, `handler.go` L377-378](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/agent/handler.go#L377-L378)
- [Relays, `relay.go` L50-287](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/relay/relay.go#L50-L287)
- [Loopback "magic IP" rewrite (proxy, read for interpretation only), `handlers.go` L206-214](https://github.com/nicocha30/ligolo-ng/blob/e543732f4be6dc899096ae322ae620bf010bfbfc/pkg/proxy/netstack/handlers.go#L206-L214)

## Observed facts versus inference

- **Observed in source:** every behavior in the procedure table, the exact `ping` argument vectors, the default User-Agent, the retry/reconnect timings and the loopback rewrite.
- **Inference (medium confidence):**
  - On Windows, Go's `exec.Command("ping", ...)` produces a command line beginning with the bare name `ping` followed by the arguments as written. Detection logic tolerates a full path.
  - Scans routed through the proxy's network stack reach the agent as individual connect requests. This is supported by the connect-request design, but per-scan volume depends on proxy behavior not analyzed here.
