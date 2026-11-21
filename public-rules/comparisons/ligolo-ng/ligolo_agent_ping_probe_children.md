# Public-rule comparison: ligolo_agent_ping_probe_children

## Identity and independence gate

- Internal tool: `ligolo-ng` (revision `e543732f4be6dc899096ae322ae620bf010bfbfc`)
- Internal canonical rule: `detections/ligolo-ng/yaral/ligolo_agent_ping_probe_children.yaral`
- Internal SHA-256: `74fdfae3154c99992c9c5d3000efe83ab47d15e96c94b9adebcbc5dc74f98ff9`
- Internal review completed before public comparison: `yes` (`reviews/ligolo-ng/detection-review.md`, LG-DR-01 to LG-DR-09)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_delayed_via_ping_lolbas_unsigned.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_delayed_via_ping_lolbas_unsigned.toml) - SHA-256 `c791de0b8fa2b93e4814fc187557e3e306a5fc8f133137f0b68b7aa5551a14ce`
- Scope mapping rationale: Both key on child `ping` processes. The Elastic rule detects `ping -n` used as a delay before a LOLBin from `cmd.exe`; ours detects the agent's single-probe discovery fallback. The overlap is the observable (ping child), not the procedure.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Non-shell parent spawning single-probe pings to many targets | covered (>= 3 distinct commands per parent) | not covered (requires `cmd.exe` parent) | exact argument vector plus non-shell parent - strong | fan-out rules - moderate | ours_stronger |
| Ping as an execution delay before a LOLBin | not targeted | covered | cmd-parented ping then LOLBin - moderate | none | different_scope |
| Raw ICMP from an elevated agent (LG-DR-04) | not covered | not covered | none | NDR ICMP sweep - moderate | insufficient_evidence |

## Missing detection branches

- Raw-ICMP discovery when the agent runs elevated (LG-DR-04).

## Detection edge cases and blind spots

- Sensors that render the resolved image path instead of argv[0] (handled by the regex).
- Fewer than three probed hosts in 10 minutes.

## Signal-quality assessment

- Ours: compiled argument vector plus parent-shell exclusion - strong.
- Public: delay pattern requiring a `cmd.exe` parent - moderate, for a different procedure.

## Public-rule weaknesses

- Requires `cmd.exe` as the parent and a following LOLBin, so it never matches the agent's direct child process.

## Internal-rule weaknesses

- Silent for the privileged raw-ICMP branch (LG-DR-04).

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/ligolo-ng/source-analysis.md`, `telemetry/ligolo-ng.md` and `reviews/ligolo-ng/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would require the ping parent to also show internal outbound connections. That adds no closed branch: the raw-ICMP gap is unaffected, and requiring network events would add a false-negative path where network logging is filtered.
  - The public rule addresses a different procedure (execution delay) and offers no branch to adopt.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The public rule's LOLBin execution branch is outside Ligolo-ng's procedures. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Correlate ping children with internal connections from the same parent.
- Required telemetry: PROCESS_LAUNCH with command line and parent process ID, plus process-attributed NETWORK_CONNECTION.
- Validation status: `unvalidated_proposal`

```yaral
rule ligolo_ping_probe_with_parent_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "LG-P06"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.principal.process.product_specific_process_id = $parent
    re.regex($p.target.process.command_line, `(?i)ping(\.exe)?"?\s+/n\s+1\s+/w\s+3000`)
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $parent
  match:
    $host, $parent over 10m
  condition:
    $p and $n
}
```
