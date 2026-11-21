# Public-rule comparison: adaptix_raw_socket_dns_from_user_process

## Identity and independence gate

- Internal tool: `adaptixc2` (revision `e99535c9ef4642190f7ea125c2983d1611f1a3f3`)
- Internal canonical rule: `detections/adaptixc2/yaral/adaptix_raw_socket_dns_from_user_process.yaral`
- Internal SHA-256: `5f4556e97298db4eacf64e2dfcc35cae6f43d858bae0a9cce0166474c1017a2c`
- Internal review completed before public comparison: `yes` (`reviews/adaptixc2/detection-review.md`, AX-DR-01 to AX-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/command_and_control_dns_tunneling_nslookup.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/command_and_control_dns_tunneling_nslookup.toml) - SHA-256 `aab55b1c39bffe5bab4b8efb622f628138b00980283f43da181bf0696377d541`
- Scope mapping rationale: Both detect DNS used as a command channel (T1071.004). The public rule detects repeated nslookup query-type invocations; ours detects a user process sending raw UDP/53 itself.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Agent sends DNS over its own UDP socket | covered | not covered | process-attributed UDP/53 recurrence - strong | none | ours_stronger |
| DNS tunnelling through repeated nslookup child processes | not covered (AdaptixC2 does not spawn nslookup) | covered | nslookup run count - moderate | none | different_scope |

## Missing detection branches

- None for AdaptixC2.

## Detection edge cases and blind spots

- UDP logging and DNS-over-UDP resolvers (AX-DR-02).

## Signal-quality assessment

- Ours: raw-socket recurrence - strong.
- Public: nslookup repetition - moderate.

## Public-rule weaknesses

- Requires nslookup processes.

## Internal-rule weaknesses

- Depends on UDP logging.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/adaptixc2/source-analysis.md`, `telemetry/adaptixc2.md` and `reviews/adaptixc2/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal adds a repeated-nslookup branch. The beacon's DNS connector uses `sendto` and never spawns nslookup (`ConnectorDNS.cpp` L70, L561), so it adds no AdaptixC2 branch.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

nslookup tunnelling belongs to other tools. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Repeated nslookup query-type invocations.
- Required telemetry: Process creation.
- Validation status: `unvalidated_proposal`

```yaral
rule adaptix_nslookup_tunnel {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "AX-P02"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.command_line, `(?i)nslookup(\\.exe)?\\s+-(q|qt|querytype|type)=`)
    $p.principal.hostname = $host
  match:
    $host over 5m
  outcome:
    $runs = count($p.metadata.id)
  condition:
    $p and $runs >= 10
}
```
