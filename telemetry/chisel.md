# Chisel telemetry requirements

## Consolidated collection plan

| Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- |
| EDR process-network sensor | `NETWORK_CONNECTION` | host, process entity/PID, direction, destination IP/port, protocol, timestamp | Enable process-attributed TCP and UDP connections | At least 30 minutes hot correlation | Encryption hides tunneled target; PID reuse | all five rules; CH-P01–P08/P10 |
| EDR socket sensor | `NETWORK_LISTEN` | host, process entity/PID, local IP/port, protocol, timestamp | Enable TCP listen/accept events | 15 minutes | Some agents record accept but not bind | listener and fanout; CH-P02/P04/P05/P08 |
| EDR UDP sensor | `UDP_BIND`, `UDP_RECEIVE` | host, process entity/PID, local/remote address and port | Enable process-owned UDP bind/receive | 10 minutes | Often absent or sampled | UDP rule; CH-P03/P04 |
| EDR process-handle sensor | `PROCESS_STDIO_REDIRECT` | host, process entity/PID, handle type, parent process | Enable redirected standard-handle or pipe semantics | 10 minutes | No portable Windows/Linux event ID | stdio rule; CH-P06 |
| HTTP proxy or network metadata | HTTP WebSocket Upgrade / TLS flow | host identity, process when available, destination, method, upgrade, subprotocol, TLS SNI/cert | Retain upgrade headers and TLS metadata | 30 minutes | TLS and generic WebSocket overlap | recurrence and proxy fanout; CH-P01/P07/P08 |

## Rule-by-rule requirements

| Rule | Severity | Provider / event | Required fields | Enablement / configuration | Known gaps | Procedures |
| --- | --- | --- | --- | --- | --- | --- |
| `chisel_recurrent_encrypted_process_egress` | Medium | EDR `NETWORK_CONNECTION` | host, process entity, destination, direction, time | Process network collection | misses single long flow | CH-P01, CH-P10 |
| `chisel_listener_with_tunnel_egress` | High | EDR `NETWORK_LISTEN` + `NETWORK_CONNECTION` | host, process entity, direction | Listen and connect telemetry | distributed reverse mode | CH-P02, CH-P04, CH-P08 |
| `chisel_udp_bind_with_tunnel_egress` | High | EDR `UDP_BIND`/`UDP_RECEIVE` + `NETWORK_CONNECTION` | host, process entity, UDP endpoints | UDP ownership collection | sensor coverage varies | CH-P03, CH-P04 |
| `chisel_proxy_destination_fanout` | High | EDR `NETWORK_LISTEN` + `NETWORK_CONNECTION` | host, process entity, destinations, prevalence | Listen/connect plus enrichment | benign proxy overlap | CH-P05, CH-P07 |
| `chisel_stdio_network_bridge` | Medium | EDR `PROCESS_STDIO_REDIRECT` + `NETWORK_CONNECTION` | host, process entity, handle semantics | Handle/pipe semantic collection | no universal provider mapping | CH-P06 |
