# Public-rule comparison: bloodhound_remote_session_registry_collection

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_remote_session_registry_collection.yaral`
- Internal SHA-256: `04b7b4beccf1a5fbe7e865b2607013220de88ce37d7c17f27caa58ab211be393`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-007,BH-008`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate assessment:
- No credible public counterpart was found in the pinned corpus for this procedure branch. Public coverage is therefore `insufficient_evidence`, not an inferred equivalence.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SRVSVC session enumeration or remote logged-on-user registry reads across hosts | operation-name regex and five targets | no equivalent procedure branch | resolved NetSessionEnum or remote-registry logged-on-user operation with source process - strong | generic RPC_CALL label - weak | ours_stronger | Canonical rule and pinned-corpus search, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | No credible public counterpart; distributed coverage is also absent | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: endpoint-local RPC telemetry, operation UUID/opnum forms, single high-value target and mixed SRVSVC/registry sequences.
- Missing from the pinned public corpus: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Operation labels are vendor-normalized and may omit encrypted RPC detail; helpdesk and inventory agents can be broad. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| resolved NetSessionEnum or remote-registry logged-on-user operation with source process | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| generic RPC_CALL label | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

No behaviorally credible public counterpart was identified. Treating broad AD-property access as equivalent to this RPC/registry procedure would overstate public coverage; comparative strength is therefore `insufficient_evidence`.

## Internal-rule weaknesses

endpoint-local RPC telemetry, operation UUID/opnum forms, single high-value target and mixed SRVSVC/registry sequences. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption matches an `operation` label regex over 15 minutes and at least 5 targets instead of the proposal's operation-ID or registry-key branches.
  - Re-review added `NetWkstaUserEnum`, `NetrWkstaUserEnum`, `WKSSVC` and `NetrSessionEnum`, which SharpHound's logged-on collection uses (`ComputerSessionProcessor.cs` L190-246; BH-DR-29).
  - The proposal's endpoint registry-key branch is not adopted, because endpoint registry telemetry attributes remote reads to the local RemoteRegistry service (BH-DR-21).
- Canonical result: `detections/bloodhound/yaral/bloodhound_remote_session_registry_collection.yaral`, SHA-256 `12a2d834a76b9578b6c81d51998c4393bcd14444d63967ae3e944b9d18df72fc`.
- Regeneration: canonical change on 2026-11-21; detection review, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: endpoint-local RPC telemetry, operation UUID/opnum forms, single high-value target and mixed SRVSVC/registry sequences.
- Required telemetry: resolved RPC interface/operation or full remote registry path, source process and target host.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_remote_session_or_loggedon_collection {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-007,BH-008"
  events:
    $e.metadata.product_event_type = /(RPC_CALL|REGISTRY_READ)/
    $e.principal.hostname = $source
    $e.principal.process.product_specific_process_id = $pid
    $e.target.hostname = $target
    ($e.target.resource.attribute.labels["rpc_operation_id"] = "SRVSVC:NetSessionEnum" or re.regex($e.target.registry.registry_key, `(?i)HKEY_USERS|Volatile Environment`))
  match:
    $source, $pid over 30m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 3
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Session (NetSessionEnum) and logged-on (NetWkstaUserEnum) enumeration across many hosts | covered | no public candidate in the pinned snapshots | RPC operation per target - strong | SMB/IPC$ authentication fan-out - weak | ours_stronger |
| Remote-registry logged-on enumeration seen only on the target endpoint | not covered (no source attribution) | not covered | none | NDR winreg - moderate | insufficient_evidence |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_remote_session_registry_collection.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_remote_session_registry_collection {
  meta:
    author = "Detection Research Agent"
    description = "Correlates SRVSVC session enumeration or remote registry reads, bound to a stable source process entity, with multi-host SMB/RPC activity."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Remote session and logged-on-user collection reveals lateral-movement opportunities."
    procedure_ids = "BH-007,BH-008"
    log_source_prerequisites = "NDR/EDR RPC interface or REGISTRY_READ telemetry plus source process entity, source identity and target host."
    false_positives = "Endpoint inventory, helpdesk, EDR and authorized administration."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_remote_session_registry_collection.md, reviews/bloodhound/detection-review.md#bh-dr-29"
    validation_status = "needs_validation"
    validation_method = "Use sanitized SRVSVC and remote-registry fixtures with approved-management negatives and PID-reuse/concurrent-session cases."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = /(RPC_CALL|REGISTRY_READ)/
    $e.principal.hostname = $source
    $e.principal.process.product_specific_process_id = $pid
    $e.target.hostname = $target
    re.regex($e.target.resource.attribute.labels["operation"], `(?i)(NetSessionEnum|NetrSessionEnum|SRVSVC|NetWkstaUserEnum|NetrWkstaUserEnum|WKSSVC|remote.registry|logged.on)`)
  match:
    $source, $pid over 15m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 5
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
