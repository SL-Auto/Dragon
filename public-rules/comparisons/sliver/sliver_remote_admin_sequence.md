# Public-rule comparison: sliver_remote_admin_sequence

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_remote_admin_sequence.yaral`
- Internal SHA-256: `7e3aecb58a46abde8ed1b771bcec5b6c442b77a8944f012112b056ccecba41e3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-020`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_remote_services.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_remote_services.toml) - SHA-256 `95963d6a99a37667979bc001f5c10a1b8005395748650ae968250cf4b81b8b38`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-020` inventory; cited candidate. |
| remote authentication is followed by service or SSH execution | Principal event family covered | Overlapping behavior under candidate-specific assumptions | remote session identifier joined to service/SSH execution and resulting child - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| remote session identifier joined to service/SSH execution and resulting child | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Rewritten in place on 2026-08-16 to join 4624 and the execution event by logon/session identifier instead of host plus account alone (REVIEW-007, REVIEW-014).
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Re-review on 2026-11-21 removed System 7045 from the session-joined branch, because 7045 carries no logon identifier and could never match, and anchored both alternations (REVIEW-015).
- Canonical result: `detections/sliver/yaral/sliver_remote_admin_sequence.yaral`, SHA-256 `7eaf7e6e08e4dc460a0be5e7a36f6f7b8516f70c06f4e2800178e498a6ddd1aa`.
- Regeneration: canonical change on 2026-11-21; detection review, telemetry row, five translations (after the generator anchoring fix), dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The candidate does not cover all of `PROC-020`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Host and user joins can associate unrelated administration; stable logon/session identity, source continuity and created process are absent.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_remote_admin_sequence_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-020"
    source_comparison = "unvalidated_proposal"
  events:
    $l.metadata.product_event_type = /4624|sshd_auth_success/
    $l.principal.ip = $source
    $l.target.hostname = $host
    $l.target.user.userid = $user
    $l.network.session_id = $session
    $x.metadata.product_event_type = /4697|7045|sshd_command/
    $x.principal.user.userid = $user
    $x.target.hostname = $host
    $x.network.session_id = $session
    $l.metadata.event_timestamp.seconds <= $x.metadata.event_timestamp.seconds
  match:
    $source, $host, $user, $session over 10m
  condition:
    $l and $x
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/lateral_movement_remote_services.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Remote logon followed by service install in the same logon session | covered (4624 TargetLogonId = 4697 SubjectLogonId) | `lateral_movement_remote_services.toml`: inbound RPC to services.exe followed within 1s by a services.exe child (by host and process entity) | session-joined logon plus 4697 - strong | RPC-to-services child sequence - moderate | complementary |
| Service install observed only through System 7045 | covered by `sliver_identity_or_service_from_network_process` and `sliver_explicit_credential_service_creation` | covered through the resulting process | 7045 plus host context - moderate | none | complementary |
| SSH authentication followed by remote command | covered when SSH events carry a session ID | not covered (Windows only) | SSH session join - strong | none | ours_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_remote_admin_sequence.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_remote_admin_sequence {
  meta:
    author = "Detection Research Agent"
    description = "Remote authentication followed by Windows service installation (4697) or SSH command execution on the target, joined by logon/session identity"
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Adding the logon/session identifier to the join key closes the review-identified gap that a bare host-plus-user join can associate unrelated administration on a busy host; System 7045 carries no logon identifier and was removed from the session-joined branch (REVIEW-015); 7045-only service installs remain covered by sliver_identity_or_service_from_network_process and sliver_explicit_credential_service_creation"
    procedure_ids = "PROC-020"
    log_source_prerequisites = "Windows Security 4624 and 4697 (TargetLogonId / SubjectLogonId normalized to network.session_id) or SSH authentication and command events with target host, account and session identifier"
    false_positives = "Deployment, backup, authorized remote administration"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_remote_admin_sequence.md, reviews/sliver/detection-review.md#review-015"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "modified_from_unvalidated_proposal"
  events:
    $l.metadata.product_event_type = /^(4624|sshd_auth_success)$/
    $l.target.hostname = $host
    $l.target.user.userid = $user
    $l.network.session_id = $session

    $x.metadata.product_event_type = /^(4697|sshd_command)$/
    $x.target.hostname = $host
    $x.principal.user.userid = $user
    $x.network.session_id = $session
  match: $host, $user, $session over 10m
  condition: $l and $x
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
