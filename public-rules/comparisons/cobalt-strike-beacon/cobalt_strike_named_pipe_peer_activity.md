# Public-rule comparison: cobalt_strike_named_pipe_peer_activity

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_named_pipe_peer_activity.yaral`
- Internal SHA-256: `5d8dd04225288eba55e28ed5ebf75eff4a0207f095c377d72755231caee04b25`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-007`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_named_pipe_impersonation.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_named_pipe_impersonation.toml) - SHA-256 `e852ff5df2d0c00aed2fc8748923292a6318f73fc92ba23e924c76486f8028a1`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| named-pipe creation/connect supporting SMB peer communication | rare/unsigned process pipe events without mutable pipe names | named-pipe rules add impersonation and known-malicious pipe branches but often depend on names | remote IPC$ plus same-host rare pipe connection - strong | ordered downstream security effect | complementary | Procedure `CSB-007` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: remote SMB connection to IPC$ immediately preceding local pipe connect.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

software agents and service frameworks create many rare pipes. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| remote IPC$ plus same-host rare pipe connection | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but remote SMB connection to IPC$ immediately preceding local pipe connect. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Event type `PIPE_CONNECT` replaced by inventory `NAMED_PIPE_CONNECTION` (legacy alias kept) (DR-13).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_named_pipe_peer_activity_compensating_signal.yaral`, SHA-256 `d80f4931f7b6e274d98366a911dfaa51a586a785a1fefceb523a189d252f0538`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-007`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: remote SMB connection to IPC$ immediately preceding local pipe connect.
- Required telemetry: normalized `NETWORK_CONNECTION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_named_pipe_peer_activity_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-007"
  events:
    $smb.metadata.event_type = "NETWORK_CONNECTION"
        $smb.target.port = 445
        $smb.principal.hostname = $source
        $smb.target.hostname = $host
        $pipe.metadata.event_type = "PIPE_CONNECT"
        $pipe.principal.hostname = $host
        $pipe.additional.fields["pipe_prevalence"].value.string_value = "RARE"
  match:
    $source, $host over 5m
  condition:
    $smb and $pipe
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `d80f4931f7b6e274d98366a911dfaa51a586a785a1fefceb523a189d252f0538`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/privilege_escalation_named_pipe_impersonation.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Remote SMB session then rare local pipe connect on target | covered, SMB first | `privilege_escalation_named_pipe_impersonation.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | remote session plus rare pipe - moderate | base pipe-rarity rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_named_pipe_peer_activity_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates a remote SMB connection to IPC$ with a subsequent rare local pipe connect on the same host, closing the ordered remote-peer branch that the standalone pipe-rarity base rule does not capture."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A remote IPC$ session immediately followed by a rare pipe connect is a strong SMB-peer-channel signal, though software agents and service frameworks also open rare pipes after remote sessions."
    procedure_ids = "CSB-007"
    log_source_prerequisites = "Normalize NETWORK_CONNECTION to TCP/445 with source/target hostname, plus NAMED_PIPE_CONNECTION (Sysmon 18 or EDR pipe connect) with a pipe-rarity enrichment field, joined on source-to-target host within 5 minutes, SMB connection first."
    false_positives = "Remote administration frameworks, backup/replication agents, and clustered service frameworks that legitimately combine SMB sessions with rare local pipes."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_named_pipe_peer_activity.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized SMB-session-plus-pipe-connect fixtures from approved remote-administration and backup tooling; confirm rarity enrichment suppresses known-benign pipes."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_named_pipe_peer_activity"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_named_pipe_peer_activity.md"
  events:
    $smb.metadata.event_type = "NETWORK_CONNECTION"
    $smb.target.port = 445
    $smb.principal.hostname = $source
    $smb.target.hostname = $host
    $pipe.metadata.event_type = /^(NAMED_PIPE_CONNECTION|PIPE_CONNECT)$/
    $pipe.principal.hostname = $host
    $pipe.additional.fields["pipe_prevalence"].value.string_value = "RARE"
    $smb.metadata.event_timestamp.seconds <= $pipe.metadata.event_timestamp.seconds
  match:
    $source, $host over 5m
  outcome:
    $pipes = array_distinct($pipe.target.resource.name)
  condition:
    $smb and $pipe
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
