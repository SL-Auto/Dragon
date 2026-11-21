# Public-rule comparison: sliver_file_activity_from_network_process

## Identity and independence gate

- Internal tool: `sliver`
- Internal canonical rule: `detections/sliver/yaral/sliver_file_activity_from_network_process.yaral`
- Internal SHA-256: `7bc97d7f36f98463ce7c984c4203a230eefa7b45e0b835c336042b7e2797ff9c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-007,PROC-008,PROC-009`
- Scope mapping rationale: procedure, ordered behavior, security effect, platform and telemetry; names and syntax were not mapping criteria.

Public candidate:
- No credible behaviorally comparable public rule was found in the pinned corpus; candidate evidence status: `insufficient_evidence`.

## Procedure and detection-branch matrix

| Procedure branch / effect | Ours | Public | Primary signal and strength | Compensating signal | Conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process/session prerequisite | Partial process or identity context | Adjacent behavior only | Stable process/session entity - moderate | signer, first-seen and host-role context | complementary | Internal `PROC-007,PROC-008,PROC-009` inventory; cited candidate. |
| network-active process reads, mutates, stages, or deletes files | Principal event family covered | No credible counterpart; not scored | sensitive-file access or archive/staging burst by the same process entity - strong | ordered child/file/network/state effect - moderate | insufficient_evidence | Security effect is closer to procedure than a tool name. |
| Result, recurrence or cleanup | Partial or absent | Partial or outside scope | Verified resulting state - strong | subsequent access, transfer, deletion or authentication - moderate | different_scope | Neither rule closes every downstream branch. |

## Missing detection branches

- Missing from ours: Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup.
- Missing from public: No public counterpart was identified, so public branch coverage is unknown rather than assumed absent.
- Missing from both: activity split across processes/hosts, low-and-slow execution, encrypted application content, telemetry outages, and reliable confirmation of operator intent.

## Detection edge cases and blind spots

Process identifiers can be reused and differ across sensors; prefer a sensor-issued process entity ID when available. NAT, proxies, resolver infrastructure, delayed ingestion, clock skew and partial endpoint visibility can break ordering. Legitimate software deployment, remote support, browsers, proxies, backup, monitoring and administration overlap with individual primitives. Baselines should raise or lower confidence without excluding the sensitive effect. Distributed and low-rate activity needs longer-lived entity analytics rather than simply expanding every correlation window.

## Signal-quality assessment

| Signal | Strength | Used by | Reason | Fragility |
| --- | --- | --- | --- | --- |
| sensitive-file access or archive/staging burst by the same process entity | strong | proposed refinement | Close to the security effect and behavior-based. | Requires stable entity joins and declared telemetry. |
| Process-attributed egress | moderate | ours | Valuable causal context but common alone. | Proxying and sensor gaps reduce attribution. |
| Image, argument, port or default name | weak | some public logic | Useful enrichment, not durable intent. | Mutable and common in benign workloads. |

## Public-rule weaknesses

No candidate was forced into this comparison. The pinned corpus provides insufficient evidence for a public-versus-internal branch conclusion.

## Internal-rule weaknesses

Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup. Broad joins risk benign collisions; narrow windows and same-process assumptions risk false negatives during delayed, delegated or distributed behavior.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/sliver/detection-review.md`.
- Prior state: this trail still read `deferred_pending_rule_improvement_run`, although the 2026-08-16 backlog resolution (REVIEW-010 to REVIEW-014) had already acted on the proposal; this pass re-reviews that action and records the terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The narrow rule targets credential stores (SAM/SECURITY/SYSTEM hives, ntds.dit, browser Login Data/Cookies) read or created by an egressing process within 15 minutes.
  - Removed the proposal's `event_timestamp.seconds <=` ordering; bounded co-occurrence in the match window is kept (REVIEW-010).
  - Adopted as an additional narrow rule beside the broad base rule, not as a replacement, so procedures without the narrow sub-case keep coverage (REVIEW-012).
- Canonical result: `detections/sliver/yaral/sliver_file_activity_from_network_process.yaral`, SHA-256 `d7aef3488a738edc1852067a77cbb6afcafcccf543e6534ba055f248154a2b54`.
- Canonical result: `detections/sliver/yaral/sliver_credential_file_access_from_network_process.yaral`, SHA-256 `09a23fd9b35b055d8339c047862124dfe9406769a9cd978430c1c216ad064d67`.
- Regeneration: coverage, telemetry, `telemetry/MASTER.md`, five translations and dependency hashes were regenerated on 2026-08-16 when the rule was adopted; re-verified present and hash-consistent on 2026-11-21.

## Unmatched scope

The candidate does not cover all of `PROC-007,PROC-008,PROC-009`. No global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Generic file activity is common and the rule conflates credential access, collection, transfer staging, and cleanup.
- Required telemetry: stable process/session entity, actor, host, event time, action/result and procedure-specific file/network/state fields.
- Validation status: `unvalidated_proposal`

```yaral
rule sliver_file_activity_from_network_process_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007,PROC-008,PROC-009"
    source_comparison = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.process.pid = $pid
    $n.network.direction = "OUTBOUND"
    $f.metadata.event_type = /FILE_READ|FILE_CREATION|FILE_MODIFICATION|FILE_DELETION/
    $f.principal.process.pid = $pid
    $f.target.file.full_path = /(?i)(\\Windows\\System32\\config\\(SAM|SECURITY|SYSTEM)|ntds\.dit|\\Users\\[^\\]+\\AppData\\.*(Login Data|Cookies))/
  match:
    $pid over 15m
  condition:
    $n and $f
}
```

The proposal uses concrete telemetry semantics but does not prove tool identity. It remains limited by collection health, process-entity fidelity, enrichment quality and activity outside the window. If accepted or modified, complete the full downstream workflow; if rejected, preserve the rationale without changing canonical logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Egressing process reads a credential store | covered by `sliver_credential_file_access_from_network_process` | no credible counterpart in the pinned snapshots | credential-store path plus same-PID egress - strong | base file rule - moderate | ours_stronger |
| Non-credential file staging, upload or deletion | covered by base rule | not covered | same-PID file and network activity - weak | none | ours_stronger |

- Current canonical YARA-L `detections/sliver/yaral/sliver_file_activity_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_file_activity_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "File read or mutation by an outbound-network process"
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Covers collection transfer metadata and cleanup surfaces"
    procedure_ids = "PROC-007,PROC-008,PROC-009"
    log_source_prerequisites = "EDR file and network telemetry sharing stable PID"
    false_positives = "Sync, backup, browsers, package managers"
    references = "reports/sliver/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
  events:
    $f.metadata.event_type = /(FILE_READ|FILE_CREATION|FILE_MODIFICATION|FILE_DELETION)/
    $f.principal.hostname = $host
    $f.principal.process.product_specific_process_id = $pid

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 10m
  condition: $f and $n
}
```

- Current canonical YARA-L `detections/sliver/yaral/sliver_credential_file_access_from_network_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule sliver_credential_file_access_from_network_process {
  meta:
    author = "Detection Research Agent"
    description = "Network-active process reads or creates a well-known credential-material file"
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Path-specific match on SAM/SECURITY/SYSTEM hives, ntds.dit, and browser credential stores is a high-specificity signal for credential-access collection, compensating for the broad file-activity rule that conflates credential access, general collection, staging, and cleanup"
    procedure_ids = "PROC-007,PROC-008"
    log_source_prerequisites = "EDR file read/creation telemetry with full path, and process-attributed network telemetry, sharing a stable process entity"
    false_positives = "Backup and imaging software, credential-manager and password-migration tools, EDR/AV scanners"
    references = "reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_file_activity_from_network_process.md"
    validation_status = "needs_validation"
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/sliver/detection-review.md"
    source_comparison = "accepted_as_compensating_rule_from_unvalidated_proposal"
  events:
    $f.metadata.event_type = /(FILE_READ|FILE_CREATION)/
    $f.principal.hostname = $host
    $f.principal.process.product_specific_process_id = $pid
    re.regex($f.target.file.full_path, `(?i)(\\windows\\system32\\config\\(sam|security|system)$|ntds\.dit$|\\appdata\\.*(login data|cookies)$)`)

    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.network.direction = "OUTBOUND"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
  match: $host, $pid over 15m
  condition: $f and $n
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry. Remaining limits are the accepted gaps in `reviews/sliver/detection-review.md`.
