# Public-rule comparison: sliver_parent_egress_with_spawned_interpreter

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_parent_egress_with_spawned_interpreter.yaral`
- Internal SHA-256: `77773ed643ed469e21a483d7b7e2af49ba9c5c0f9a8a8127d7ad817dfcd10d21`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-010`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_command_shell_started_by_unusual_process.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_command_shell_started_by_unusual_process.toml) - SHA-256 `d1b7654c3ab90fd554847304f66134781385b24070318b18561b8410ac958222`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-010` inventory; cited candidate. |
| egressing parent creates a command interpreter | Principal event family covered | Overlapping behavior under candidate-specific assumptions | same process entity with egress creates a child carrying inherited anomalous network or token context - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Interpreter naming is mutable and the rule lacks parent process identity, command provenance, token, and child network/result context.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| same process entity with egress creates a child carrying inherited anomalous network or token context | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Interpreter naming is mutable and the rule lacks parent process identity, command provenance, token, and child network/result context. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal still matched the same mutable interpreter-name list and added no provenance or token field, so it did not close its stated gap (REVIEW-013).
  - Its only material change was strict event ordering, which REVIEW-008 and REVIEW-010 established as brittle across collection pipelines.
  - The canonical rule already correlates parent PID to egress without that ordering.
- Canonical result: no canonical logic changed; the proposed code is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The candidate does not cover all of `PROC-010`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Interpreter naming is mutable and the rule lacks parent process identity, command provenance, token, and child network/result context.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_parent_egress_with_spawned_interpreter_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-010"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $parent_pid
    $n.network.direction = "OUTBOUND"
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.process.pid = $parent_pid
    $p.target.process.pid = $child_pid
    $p.target.process.file.full_path = /(?i)(cmd|powershell|pwsh|sh|bash|zsh)(\.exe)?$/
    $n.metadata.event_timestamp.seconds <= $p.metadata.event_timestamp.seconds
  match:
    $parent_pid, $child_pid over 10m
  condition:
    $n and $p
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/execution_command_shell_started_by_unusual_process.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Egressing parent spawns a command interpreter | covered (parent PID joined to egress) | `execution_command_shell_started_by_unusual_process.toml`: cmd.exe from a listed unusual parent image | same-PID egress plus interpreter child - moderate | unusual-parent heuristic - moderate | complementary |

- Re-comparison outcome: canonical logic is unchanged; the comparison conclusions above stand against the re-pinned candidate.
