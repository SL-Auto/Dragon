# Public-rule comparison: ligolo_agent_listener_with_tunnel_egress

## Identity and independence gate

- Internal tool: `ligolo-ng` (revision `e543732f4be6dc899096ae322ae620bf010bfbfc`)
- Internal canonical rule: `detections/ligolo-ng/yaral/ligolo_agent_listener_with_tunnel_egress.yaral`
- Internal SHA-256: `cc94941e54cdd003b5fb857a7903b21d39da5f4f409de8276a8c31571138e053`
- Internal review completed before public comparison: `yes` (`reviews/ligolo-ng/detection-review.md`, LG-DR-01 to LG-DR-09)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/command_and_control_linux_tunneling_and_port_forwarding.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/command_and_control_linux_tunneling_and_port_forwarding.toml) - SHA-256 `104ed9d94d539987d6d56d2f5cf9bacd799b182456b938698096dde527386808`
- Scope mapping rationale: Both address tunnelling and port forwarding on a host (T1572, T1090). The Elastic rule matches known tunnelling tools by process name and arguments; ours matches the socket behavior of the agent's listener.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Agent-side listener plus accepted peer plus external egress | covered | not covered (Ligolo is not in its tool list) | listen plus accept plus egress - moderate | fan-out rules - moderate | ours_stronger |
| Tunnelling tool identified at launch by its argument grammar | not covered by this rule | covered for gost, pivotnacci, ssh -R/-L/-D and others | process arguments - moderate | `ligolo_agent_command_line_trust_flags` - strong | public_stronger |
| Agent trust configuration at launch (LG-P09) | not covered before this comparison | not covered | flag grammar - strong | TLS metadata - weak | insufficient_evidence |

## Missing detection branches

- Launch-time identification of the agent by its compiled flags was absent; LG-P09 was `not_observable`.

## Detection edge cases and blind spots

- The public rule is Linux-only and name-based.
- Our listener rule misses accepts delayed beyond 10 minutes (LG-DR-09).

## Signal-quality assessment

- Ours: socket correlation - moderate.
- Public: process name and arguments - moderate, defeated by renaming.
- Adopted flag rule: compiled flag names - strong (renaming the file does not help).

## Public-rule weaknesses

- Depends on process names, has no Ligolo entry and is Linux-only.

## Internal-rule weaknesses

- No launch-time signal; LG-P09 was not observable.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/ligolo-ng/source-analysis.md`, `telemetry/ligolo-ng.md` and `reviews/ligolo-ng/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The public rule's branch (tool identification from launch arguments) is real. A name-based copy would be weak, so the adopted rule keys on the agent's compiled flag names instead.
  - The adopted rule requires `-connect` together with `-ignore-cert` or `-accept-fingerprint` and a 64-hex value. It accepts single-dash, double-dash and `=` forms, and drops the proposal's `-retry` and `-proxy` alternatives, which collide with other tools (for example `openssl s_client -proxy`).
  - LG-P09 moves to `detected` (LG-DR-11).
- Canonical result: `detections/ligolo-ng/yaral/ligolo_agent_command_line_trust_flags.yaral`, SHA-256 `5eeab19c362dcb45dabfdd0862ab9220b2a472b145e90f54ed2a78ec7814dd2c`.
- Regeneration: new canonical rule `ligolo_agent_command_line_trust_flags`. Detection review (LG-DR-11), coverage (LG-P09 now detected), `telemetry/ligolo-ng.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison were produced in the same run.

## Unmatched scope

The public rule's ssh, gost and pivotnacci branches are other tools' procedures. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Launch-time identification of the agent and its trust configuration (LG-P01, LG-P09).
- Required telemetry: PROCESS_LAUNCH with full command line and image path.
- Validation status: `unvalidated_proposal`

```yaral
rule ligolo_agent_launch_arguments {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "LG-P01,LG-P09"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.command_line, `(?i)-connect\s+\S+`)
    re.regex($p.target.process.command_line, `(?i)-(ignore-cert|accept-fingerprint|retry|proxy)`)
  condition:
    $p
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/ligolo-ng/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule ligolo_agent_command_line_trust_flags {
  meta:
    author = "Detection Research Agent"
    description = "Detects a process started with the agent's compiled flag grammar: a -connect target together with -ignore-cert or -accept-fingerprint followed by a 64-hex-character SHA-256 value. Flag names are fixed in the agent binary and survive renaming the executable."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "The combination of a connect target with certificate-verification bypass or certificate pinning is specific to the agent's trust configuration (LG-P09) and its outbound transport (LG-P01). Unlike name-based rules, it does not depend on the file name."
    procedure_ids = "LG-P01,LG-P09"
    log_source_prerequisites = "PROCESS_LAUNCH telemetry (Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE or EDR) with the full command line, image path and host."
    false_positives = "Other tools that happen to share both -connect and -ignore-cert or -accept-fingerprint flags; authorized red-team exercises."
    references = "reports/ligolo-ng/source-analysis.md#evidence; public-rules/comparisons/ligolo-ng/ligolo_agent_listener_with_tunnel_egress.md; reviews/ligolo-ng/detection-review.md#lg-dr-11"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized command lines in single-dash, double-dash and = forms; search historical process telemetry for the flag pair to measure benign prevalence before enabling."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/ligolo-ng/detection-review.md"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    re.regex($p.target.process.command_line, `(?i)(^|\s)-{1,2}connect(\s+|=)"?\S+`)
    re.regex($p.target.process.command_line, `(?i)(^|\s)-{1,2}(ignore-cert(\s|=|$)|accept-fingerprint(\s+|=)"?[0-9a-f]{64})`)
    $p.target.process.file.full_path = $image
  match:
    $host, $image over 1h
  outcome:
    $command_lines = array_distinct($p.target.process.command_line)
    $parents = array_distinct($p.principal.process.file.full_path)
  condition:
    $p
}
```
