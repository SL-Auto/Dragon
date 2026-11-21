# Ligolo-ng telemetry requirements

Scope: the victim-side agent at revision `e543732f4be6dc899096ae322ae620bf010bfbfc`. The operator proxy is out of scope.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LG-TEL-01 | Microsoft Sysmon or EDR process-network sensor | Sysmon Event ID 3 / `NETWORK_CONNECTION` (OUTBOUND, INBOUND, LISTEN) | host, stable process ID (`principal.process.product_specific_process_id`), image path, direction, source and destination IP and port, protocol, timestamp | Enable process-attributed TCP and UDP connection logging for all processes; do not restrict Sysmon Event ID 3 to a port allowlist, or internal fan-out is lost. Record LISTEN or accept where the sensor supports it | Correlate by host and process ID for 15 minutes; retain at least 7 days | Sysmon Event ID 3 does not log ICMP or socket listen; high-volume filtering often drops internal connections; inbound field orientation varies by parser (LG-DR-03) | `ligolo_tunnel_process_internal_fanout`, `ligolo_bind_listener_internal_fanout`, `ligolo_agent_listener_with_tunnel_egress`, `ligolo_process_internal_admin_port_sweep`; LG-P01, P02, P04, P05, P07 |
| LG-TEL-02 | Code-signing enrichment | `principal.process.file.signature_info.verification_status` on network events | verification status per image | EDR signer enrichment, or join with Sysmon Event ID 7 or 1 hashes | Same event | Absent enrichment makes the exclusion fail open (more noise, no misses) | fan-out and listener rules |
| LG-TEL-03 | Process creation | Sysmon Event ID 1, Windows Security 4688 (with command-line auditing), Linux auditd `EXECVE` or EDR `PROCESS_LAUNCH` | host, parent process ID and image path, child command line | Enable "Include command line in process creation events" for 4688, or Sysmon Event ID 1 | 10 minutes per parent; retain 7 days | Raw-ICMP branch spawns no child (LG-DR-04) | `ligolo_agent_ping_probe_children`, `ligolo_agent_command_line_trust_flags`; LG-P01, LG-P06, LG-P09 |
| LG-TEL-04 | Web proxy, NDR or EDR HTTP sensor | `NETWORK_HTTP` (proxy access log, Zeek `http.log`) | source host or IP, User-Agent, destination host, initiating process where available | Log the User-Agent header for all requests, including WebSocket upgrades; with TLS, requires interception or endpoint HTTP telemetry | 1 hour per source | Header hidden in TLS without interception; one flag changes the value | `ligolo_websocket_default_user_agent`; LG-P01 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `ligolo_tunnel_process_internal_fanout` | LG-P01, LG-P04, LG-P05 | LG-TEL-01, LG-TEL-02 | OUTBOUND `NETWORK_CONNECTION` with destination IP and port, host and process ID, for both internet-bound and internal or loopback destinations | signature verification status; asset role; approved scanner inventory | Without internal-destination logging the fan-out leg never accumulates. Upstream through an internal proxy hides the external leg (LG-DR-01) |
| `ligolo_bind_listener_internal_fanout` | LG-P02, LG-P04, LG-P05 | LG-TEL-01 | INBOUND accept with remote source IP for the local process, plus OUTBOUND internal connections from the same process ID | asset role (internet-facing services) | Parser that places the local process in `target` breaks the join (LG-DR-03) |
| `ligolo_agent_ping_probe_children` | LG-P06 | LG-TEL-03 | `PROCESS_LAUNCH` with child command line, parent image path and parent process ID | approved monitoring parents | Without command lines the argument shape cannot be matched; an elevated agent uses raw ICMP instead (LG-DR-04) |
| `ligolo_agent_listener_with_tunnel_egress` | LG-P07 | LG-TEL-01, LG-TEL-02 | LISTEN, INBOUND and OUTBOUND `NETWORK_CONNECTION` for one process ID within 10 minutes | signature verification status | Sensors without LISTEN events cannot satisfy the rule; accepts delayed beyond 10 minutes are missed (LG-DR-09) |
| `ligolo_websocket_default_user_agent` | LG-P01 | LG-TEL-04 | `NETWORK_HTTP` with User-Agent and source IP | initiating process image | Direct-TLS transport has no HTTP layer; a changed User-Agent defeats it (LG-DR-07) |
| `ligolo_process_internal_admin_port_sweep` | LG-P02, LG-P04 | LG-TEL-01, LG-TEL-02 | OUTBOUND `NETWORK_CONNECTION` with destination IP, integer port, host and process ID for internal destinations | signature verification status; approved scanner inventory | Port-filtered or sampled network logging hides the sweep; slow sweeps under 30 hosts in 10 minutes are missed (LG-DR-10) |
| `ligolo_agent_command_line_trust_flags` | LG-P01, LG-P09 | LG-TEL-03 | `PROCESS_LAUNCH` with the full command line and image path | none | Without command-line capture the flags are invisible; bind mode and CA-valid connect without trust flags are not matched (LG-DR-11) |

## Deployment order

1. Process-attributed network logging without internal-destination filtering (LG-TEL-01). It feeds four of the seven rules.
2. Process-creation command lines (LG-TEL-03) for the ping and command-line flag rules.
3. Signer enrichment (LG-TEL-02) to cut fan-out noise before raising severity in triage.
4. Proxy User-Agent logging (LG-TEL-04) as corroboration.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] The inbound field orientation was verified in the target parser.
- [ ] Internal-destination network events are retained without sampling.
- [ ] Command-line capture was confirmed for 4688 or Sysmon Event ID 1.
- [ ] Approved scanners, agents and monitoring parents were baselined.

## Unresolved telemetry gaps

- ICMP attribution (LG-DR-04), upstream through an internal proxy or double pivot (LG-DR-01), and idle tunnels (LG-DR-07) are inherent collection limits. Each has a named compensating signal in `reviews/ligolo-ng/detection-review.md`.
