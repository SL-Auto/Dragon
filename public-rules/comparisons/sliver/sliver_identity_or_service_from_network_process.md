# Public-rule comparison: sliver_identity_or_service_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_identity_or_service_from_network_process.yaral`
- Internal SHA-256: `73ef2e2699a7255f2a3a5426fe7ed971a018b289d04b33f1f62c5faeb5000169`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-016,PROC-017,PROC-019`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/win_susp_or_malicious_service_created.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/win_susp_or_malicious_service_created.yaral) - SHA-256 `ffca062a76c08fcc3917a87424760bba8042c956275b072e962943ac5f3803f7`

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-016,PROC-017,PROC-019` inventory; cited candidate. |
| network-active identity performs explicit-credential, privilege, or service operations | Principal event family covered | Overlapping behavior under candidate-specific assumptions | stable process/logon session joined to explicit credentials and resulting privileged action - strong | ordered child/file/network/state effect - moderate | complementary | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Four event families with different meanings are conflated and account-based correlation can join unrelated processes.
- Missing from public: The public candidate does not cover complete Sliver procedure ordering, the internal process-to-effect correlation, or tool-name-independent downstream confirmation.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| stable process/logon session joined to explicit credentials and resulting privileged action | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

The candidate supplies useful behaviorally relevant telemetry but not the whole Sliver procedure. Backend assumptions and fixed thresholds are not tenant validation; its predicates must not be copied blindly.

## Internal-rule weaknesses

Four event families with different meanings are conflated and account-based correlation can join unrelated processes. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule chains 4648 explicit-credential use to a 4697/7045 service install as the credentialed account on the same host, separating it from the four-family base rule (REVIEW-014).
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
  - Anchored the 4697/7045 alternation on 2026-11-21 (REVIEW-016).
- Canonical result: `detections/sliver/yaral/sliver_identity_or_service_from_network_process.yaral`, SHA-256 `f9d5d6618d160cefcac63d5691612b565047b039a69b4030b94e34a499577a04`.
- Canonical result: `detections/sliver/yaral/sliver_explicit_credential_service_creation.yaral`, SHA-256 `b3ed99f9a80da02ec97e7243bf92a6ff2fd7ee21611b170136f0679b85d28d07`.
- Regeneration: canonical change on 2026-11-21; detection review, telemetry row, five translations (after the generator anchoring fix), dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The candidate does not cover all of `PROC-016,PROC-017,PROC-019`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Four event families with different meanings are conflated and account-based correlation can join unrelated processes.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_identity_or_service_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-016,PROC-017,PROC-019"
    source_comparison = "unvalidated_proposal"
  events:
    $c.metadata.product_event_type = "4648"
    $c.principal.process.pid = $pid
    $c.principal.user.userid = $actor
    $c.target.user.userid = $credential_user
    $s.metadata.product_event_type = /4697|7045/
    $s.principal.user.userid = $credential_user
    $s.target.hostname = $host
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $c.metadata.event_timestamp.seconds <= $s.metadata.event_timestamp.seconds
  match:
    $pid, $credential_user, $host over 10m
  condition:
    $c and $s and $n
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/win_susp_or_malicious_service_created.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Explicit-credential logon followed by service install | covered by `sliver_explicit_credential_service_creation` | `win_susp_or_malicious_service_created.yaral`: 7045 service names on a suspicious/known-malicious list | 4648 to 4697/7045 account chain - strong | known-bad service name - weak (mutable) | complementary |
| Privilege assignment or service creation from a network-active process | covered by base rule | service creation only | privileged event plus host egress - weak | none | complementary |
| Service carrying a known-malicious name | not targeted (names are mutable) | covered | service-name list - weak | none | different_scope |

- Current canonical YARA-L `detections/sliver/yaral/sliver_identity_or_service_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_identity_or_service_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "Explicit credentials privileged logon or service operation associated with a network process/account"
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Covers durable privilege and service effects"
    procedure_ids = "PROC-016,PROC-017,PROC-019"
    log_source_prerequisites = "Windows identity/service and process network telemetry normalized by host and account"
    false_positives = "Deployment, backup, authorized administration"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $a.metadata.product_event_type = /(4648|4672|4697|7045)/
    $a.target.hostname = $host
    $a.principal.user.userid = $user

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.user.userid = $user
  match: $host, $user over 10m
  condition: $a and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_explicit_credential_service_creation.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_explicit_credential_service_creation {
  meta:
    author = "Detection Research Agent"
    description = "An explicit-credential logon is followed by a service or task creation performed as that credentialed account on the same host"
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Chaining an explicit-credential logon (4648) to a subsequent service/task creation (4697/7045) under the same account is a materially stronger sequence signal than co-occurrence of any one of four unrelated event families with generic account-based network correlation"
    procedure_ids = "PROC-016,PROC-017,PROC-019"
    log_source_prerequisites = "Windows explicit-credential logon and service/task-creation events correlated by target account and host, plus process-attributed network telemetry on the same host"
    false_positives = "Software deployment tooling, backup agents, and authorized administrators who run-as another account before installing a service"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_identity_or_service_from_network_process.md, reviews/sliver/detection-review.md#review-016"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $c.metadata.product_event_type = "4648"
    $c.target.hostname = $host
    $c.target.user.userid = $credential_user

    $s.metadata.product_event_type = /^(4697|7045)$/
    $s.principal.user.userid = $credential_user
    $s.target.hostname = $host

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
  match: $host, $credential_user over 15m
  condition: $c and $s and $n
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
