# Ligolo-ng adversarial detection-logic review

## Review scope

- Revision `e543732f4be6dc899096ae322ae620bf010bfbfc` (`v0.9.2`), procedures LG-P01 to LG-P09 in `reports/ligolo-ng/source-analysis.md`.
- Rules reviewed:
  - `ligolo_process_internal_admin_port_sweep` and `ligolo_agent_command_line_trust_flags` (added after comparison; LG-DR-10, LG-DR-11)
  - `ligolo_tunnel_process_internal_fanout`
  - `ligolo_bind_listener_internal_fanout`
  - `ligolo_agent_ping_probe_children`
  - `ligolo_agent_listener_with_tunnel_egress`
  - `ligolo_websocket_default_user_agent`
- Method: every rule was assumed wrong until supported. Each branch, join, window, threshold and exclusion was traced against the agent source and against common sensor and parser behavior.

## Overall assessment

The agent has no unique host artifact: no files, no registry keys and no service. Detection rests on behavior:
- one process combining tunnel egress (or an external inbound session) with internal fan-out
- the hard-coded `ping` fallback
- agent-side listeners
- the default WebSocket User-Agent

The fan-out rules are the primary signals. The ping and User-Agent rules corroborate them. No blocker remains after the revisions below.

## Findings

### LG-DR-01 — upstream proxy or double pivot hides the external leg

- Severity: `medium`
- Rules: `ligolo_tunnel_process_internal_fanout`, `ligolo_agent_listener_with_tunnel_egress`
- Assumption challenged: the tunnel always reaches a non-internal address directly.
- Gap or failure mode:
  - With `-proxy` (HTTP or SOCKS5), the agent's only egress is to the internal proxy (LG-P01).
  - In a double pivot, a second agent's upstream is the first agent's internal listener (LG-P07).
  - In both cases the `$up` leg never matches.
- Resolution: `accepted_gap`. Relaxing `$up` to any destination would turn the rule into generic internal fan-out with high benign volume. Compensating signals:
  - proxy logs: `ligolo_websocket_default_user_agent`, and CONNECT to a rare destination
  - `ligolo_agent_listener_with_tunnel_egress` on the first hop
  - `ligolo_agent_ping_probe_children` on every hop

### LG-DR-02 — benign fan-out from signed software

- Severity: `high`
- Rule: `ligolo_tunnel_process_internal_fanout`
- Assumption challenged: external egress plus ten internal destinations is uncommon.
- Gap or failure mode: browsers, collaboration clients and management agents routinely meet both conditions.
- Resolution: `fixed`. The upstream leg now requires `signature_info.verification_status != "VERIFIED"`. The filter fails open: without signature enrichment the rule still fires, just with more noise, instead of silently suppressing. A self-signed or stolen-certificate agent is a residual false negative, compensated by the ping and listener rules.

### LG-DR-03 — inbound field orientation is parser-dependent

- Severity: `medium`
- Rules: `ligolo_bind_listener_internal_fanout`, `ligolo_agent_listener_with_tunnel_egress`
- Assumption challenged: for INBOUND events, the local process is in `principal.process` and the remote peer in `principal.ip`.
- Gap or failure mode: some parsers place the local endpoint in `target` for accepted connections. The rules then join nothing.
- Resolution: `accepted_gap` until tenant validation. This follows the repository convention used by the Sliver and Chisel listener rules. The prerequisites state the orientation, and the validation method requires confirming it before enabling.

### LG-DR-04 — raw-ICMP branch produces no child process

- Severity: `medium`
- Rule: `ligolo_agent_ping_probe_children`
- Gap or failure mode: the agent tries a raw ICMP echo first. On Windows it forces privileged mode, which succeeds when the agent runs elevated. Only the unprivileged fallback spawns `ping`. Common sensors do not attribute ICMP to a process (Sysmon Event ID 3 does not log ICMP).
- Resolution: `accepted_gap`, inherent to collection. Compensating signals: `ligolo_tunnel_process_internal_fanout` for TCP/UDP activity that normally follows discovery, and NDR ICMP sweep analytics.

### LG-DR-05 — ping argument matching depends on command-line rendering

- Severity: `low`
- Rule: `ligolo_agent_ping_probe_children`
- Assumption challenged: the child command line is exactly `ping /n 1 /w 3000 <target>`.
- Gap or failure mode: Go builds the Windows command line from the argument vector, with `ping` as argv[0] (inference, medium confidence). Some sensors substitute the resolved image path, or add quoting or extra spacing.
- Resolution: `fixed` in design. The regex allows an optional quoted full path, an optional `.exe`, flexible whitespace, a trailing-space tolerance and the Linux `-c 1 -W 3` form. The exact numeric values are kept, because they are what distinguishes the agent from interactive use.

### LG-DR-06 — slow pivoting below the fan-out threshold

- Severity: `medium`
- Rules: both fan-out rules.
- Gap or failure mode: an operator who reaches one or two internal services (for example one RDP host) stays under ten destinations and ten ports.
- Resolution: `accepted_gap`. A lower threshold overlaps heavily with ordinary software. Compensating signals: the listener rule, the ping rule, and resource-side authentication from the pivot host.

### LG-DR-07 — idle tunnel without pivot activity

- Severity: `low`
- Procedure: LG-P01.
- Gap or failure mode: a connected agent with no operator traffic is one long-lived TLS (or WebSocket) flow. Only the WebSocket User-Agent rule applies, and only for `ws/wss/http/https` URLs with the default header.
- Resolution: `accepted_gap`. Compensating signals: TLS metadata (self-signed server certificate, rare SNI) and destination-prevalence analytics outside this tool's rules.

### LG-DR-08 — loopback access counted with internal fan-out

- Severity: `low`
- Procedure: LG-P05.
- Assumption challenged: loopback connections need their own rule.
- Resolution: `fixed` in design. `127.0.0.0/8` and `::1` are included in the internal destination set, because the agent-side observable (a dial from the tunnel process) is identical. Loopback-heavy legitimate software is mitigated by the signature filter (LG-DR-02).

### LG-DR-09 — the listener rule window may miss a delayed accept

- Severity: `low`
- Rule: `ligolo_agent_listener_with_tunnel_egress`
- Gap or failure mode: a reverse-forward listener can wait more than 10 minutes for its first peer.
- Resolution: `accepted_gap`. A longer window raises benign correlation. Compensating signal: the fan-out rules once the relayed session produces internal traffic.

## Comparison-driven additions (2026-11-21)

The public comparisons ran after the review above. Two proposals were adopted as new rules, and each was reviewed here before adoption.

### LG-DR-10 — process-attributed admin-port sweep without a tunnel leg

- Severity: `medium`
- Rule: new `ligolo_process_internal_admin_port_sweep` (from the `ligolo_tunnel_process_internal_fanout` and `ligolo_bind_listener_internal_fanout` comparisons).
- Assumption challenged: that pivot fan-out is only detectable when the tunnel leg is visible (LG-DR-01, LG-DR-03).
- Design:
  - At least 30 distinct internal hosts on remote-administration ports (21, 22, 23, 135, 139, 445, 3389, 5985, 5986) from one unverified process within 10 minutes.
  - Ports use integer equality.
  - The signature exclusion fails open.
- Challenges:
  - Unapproved scanners match by design (medium severity).
  - Slow sweeps under 30 hosts in 10 minutes are missed (LG-DR-06 still applies).
  - Loopback is excluded, because admin-port loopback sweeps are not the target.
- Resolution: `compensating_signal`. It narrows LG-DR-01 and LG-DR-03 for scan-type activity. Interactive single-service pivots remain an accepted gap.

### LG-DR-11 — compiled flag grammar makes trust configuration observable

- Severity: `medium`
- Rule: new `ligolo_agent_command_line_trust_flags` (from the `ligolo_agent_listener_with_tunnel_egress` comparison).
- Assumption challenged: that LG-P09 is configuration-only and not observable.
- Design:
  - The agent's `flag` definitions (`main.go` L52-63) fix the names `-connect`, `-ignore-cert` and `-accept-fingerprint`. Go's flag package accepts single dash, double dash and `=` forms, and the regexes allow all three.
  - The fingerprint branch requires a 64-hex SHA-256 value.
  - `openssl s_client -connect` alone does not match, because it lacks both trust flags.
- Challenges:
  - Bind mode (`-bind`) and connect without a trust flag (a CA-valid server certificate) are not matched. `-bind` alone is too generic to use.
  - Command-line spoofing or a recompiled agent with renamed flags defeats it. That is a deliberate change, unlike renaming the file, so the rule is kept at high severity.
- Resolution: `compensating_signal`. LG-P09 moves from `not_observable` to `detected`, and LG-P01 gains a process-creation signal.

## Not observable procedures

- **LG-P03 host reporting:** the API reads produce no standard telemetry.
- **LG-P08 teardown:** process exit and socket close are generic.

Each has its closest compensating signal recorded in `coverage/ligolo-ng.yml`.

## Re-review of revised rules

- All seven rules were re-traced after LG-DR-02, LG-DR-10 and LG-DR-11.
- Every event variable appears in its condition. Every multi-event join carries host and process ID. Exclusions fail open.
- Thresholds are computed in `outcome`. Time windows are bounded (10 or 15 minutes; 1 hour for the User-Agent rule).
- No unresolved `blocker` remains.

## Required follow-up

- Compile every rule against the tenant YARA-L version and verify `net.ip_in_range_cidr`, inbound field orientation (LG-DR-03) and the signature-status field.
- Validate with positive, benign, near-threshold, missing-field and filtered-network fixtures; baseline approved scanners, agents and monitoring parents.
- Implement the three multi-event correlations natively per backend before relying on secondary drafts.
- Keep all rules experimental; comprehensive source coverage does not imply production validation.
