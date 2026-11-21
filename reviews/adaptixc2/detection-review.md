# AdaptixC2 adversarial detection-logic review

## Review scope

- Revision `e99535c9ef4642190f7ea125c2983d1611f1a3f3`, procedures AX-P01 to AX-P11 in `reports/adaptixc2/source-analysis.md` (beacon and gopher agents only).
- 10 rules under `detections/adaptixc2/yaral/`.
- Method: every rule was assumed wrong until supported. Transports, process creation, memory loading and tunnels were traced against agent source; joins, fields and exclusions were challenged.

## Overall assessment

Transport and pivot behavior gives the strongest host signals: raw-socket DNS from a user process, named-pipe servers with remote peers, and tunnel fan-out. Profile values (user agent, URIs, pipe names) are operator-defined and are not used. No blocker remains.

## Findings

### AX-DR-01 — profile-defined indicators are deliberately unused

- Severity: `low`
- Rules: all transport rules.
- Assumption challenged: that default user agents, URIs or pipe names identify the agent.
- Gap or failure mode: every one of these values comes from the listener profile at build time.
- Resolution: `fixed` in design. The rules use behavior (raw DNS, pipe service to remote peers, recurrence, fan-out) instead of profile strings.

### AX-DR-02 — raw-socket DNS needs UDP logging

- Severity: `medium`
- Rule: `adaptix_raw_socket_dns_from_user_process`
- Gap or failure mode: some deployments filter UDP or port 53 from Sysmon Event ID 3. DNS-over-UDP resolvers in browsers or VPN clients also send UDP/53.
- Resolution: `accepted_gap`. The prerequisites require UDP logging. A fail-open signer filter, a system-binary exclusion and a recurrence requirement (6 or more over 4 or more minutes) reduce benign matches.

### AX-DR-03 — pipe name normalization differs between Sysmon and 5145

- Severity: `medium`
- Rule: `adaptix_named_pipe_server_with_network_peer`
- Gap or failure mode: Sysmon Event ID 17 records `\pipename`, while 5145 records the relative target name without the leading backslash. A raw join fails without normalization.
- Resolution: `accepted_gap` pending parser normalization. The prerequisites require both values normalized to the bare pipe name in `target.resource.name`. Compensating signal: `adaptix_tcp_bind_listener_with_internal_peer` for TCP links.

### AX-DR-04 — seclogon parentage also covers runas

- Severity: `medium`
- Rule: `adaptix_secondary_logon_hidden_interpreter`
- Gap or failure mode: administrators' runas sessions produce the same parentage.
- Resolution: `accepted_gap`, at medium severity. The public comparison's SYSTEM-only narrowing was rejected (see that comparison), because it would miss token theft of non-SYSTEM users.

### AX-DR-05 — RWX and screen-capture telemetry is vendor-specific

- Severity: `medium`
- Rules: `adaptix_rwx_memory_in_network_process`, `adaptix_screen_capture_then_egress`
- Gap or failure mode: Sysmon does not report memory protection or screen capture. Only some EDRs emit these events.
- Resolution: `accepted_gap`. The prerequisites name the vendor event normalization. Compensating signals: the network-process child rule and the transport rules.

### AX-DR-06 — API hashing and sleep behavior are not independently observable

- Severity: `low`
- Procedure: AX-P11.
- Gap or failure mode: hash-based API resolution and sleep timing leave no discrete event.
- Resolution: `accepted_gap`. AX-P11 is `not_observable`. Compensating signals: recurrence rules on the transports.

### AX-DR-07 — host and process discovery commands are API-only

- Severity: `low`
- Procedure: AX-P08.
- Gap or failure mode: process list, getuid and disk enumeration run through APIs without child processes.
- Resolution: `accepted_gap`. AX-P08 is `not_observable`. Compensating signals: transport and child-process rules.

## Not observable or excluded

- AX-P08 and AX-P11 are not observable.
- The server, listeners, client and install scripts are excluded as operator infrastructure.

## Re-review

- All 10 rules were re-traced after the enum-equality fix for `network.ip_protocol`.
- Joins carry host and process ID, thresholds are computed in `outcome`, and exclusions fail open.
- No unresolved `blocker` remains.

## Required follow-up

- Confirm UDP logging, pipe-name normalization and EDR memory and screen-capture event mappings.
- Baseline unsigned software.
- Keep all rules experimental.
