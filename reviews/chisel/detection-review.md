# Chisel adversarial detection-logic review

## Overall assessment

The five canonical rules cover every externally observable procedure without relying on product name, filename, default port, or command-line flags. They detect effects rather than attribute them to Chisel. All remain experimental because UDM provider mappings and tenant baselines are unvalidated.

## Findings

### CH-DR-01 — TCP-only logic omitted UDP forwarding

- Severity: `high`
- Assumption challenged: generic listener events cover UDP.
- Gap or failure mode: many providers distinguish TCP listen from UDP bind/receive.
- Resolution: `fixed`; added `chisel_udp_bind_with_tunnel_egress` with explicit UDP semantic events.

### CH-DR-02 — listener plus egress can be benign

- Severity: `high`
- Assumption challenged: two socket roles uniquely imply tunnelling.
- Gap or failure mode: proxies, VPNs and service meshes behave identically.
- Resolution: `compensating_signal`; added destination fanout rule and required process prevalence/approval baselines. Attribution claims removed.

### CH-DR-03 — stdio branch has no listener

- Severity: `medium`
- Assumption challenged: all forwarding starts with a socket listener.
- Gap or failure mode: redirected standard handles bridge directly to the encrypted connection.
- Resolution: `fixed`; added a dedicated stdio/network correlation rule.

### CH-DR-04 — reverse proxy spans hosts

- Severity: `medium`
- Assumption challenged: one host exposes both listener and destination connection.
- Gap or failure mode: reverse mode distributes effects between client and server.
- Resolution: `accepted_gap`; deploy same behavior rules at both ends and correlate entities centrally where cross-host session telemetry exists.

### CH-DR-05 — recurrence thresholds are environmental

- Severity: `medium`
- Assumption challenged: four connections in thirty minutes is universally suspicious.
- Gap or failure mode: long-lived sessions may create one flow; unstable benign applications may reconnect often.
- Resolution: `compensating_signal`; recurrence is medium severity and stable-destination grouping is required; listener/fanout rules cover non-recurrent sessions.

### CH-DR-06 — process identifiers can be reused

- Severity: `medium`
- Assumption challenged: PID alone is stable.
- Gap or failure mode: PID reuse can create false cross-process joins.
- Resolution: `accepted_gap`; prerequisite requires provider process entity identity; current UDM uses PID only as a portable hypothesis pending mapping.

## Required follow-up

- Validate exact `NETWORK_LISTEN`, `UDP_BIND`, `UDP_RECEIVE`, and `PROCESS_STDIO_REDIRECT` mappings per provider.
- Replace PID joins with process entity IDs where available.
- Establish approved proxy/VPN/remote-support inventories and destination prevalence.
- Test cross-host reverse-proxy correlation with synthetic telemetry; do not execute Chisel.

