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

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

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
