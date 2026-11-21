# Public-rule comparison: cobalt_strike_directory_discovery

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_directory_discovery.yaral`
- Internal SHA-256: `86081ee86a59ca118c4f803db16cdb3c34224d7030ab29448b8681ca4b7a9a28`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-022`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/recon_successful_logon_enumeration_powershell_T1033_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/recon_successful_logon_enumeration_powershell_T1033_cisa_report.yaral) - SHA-256 `f389319b9b9338ae14c60de28995cbad5c21be1d07ea78c804bc13381443fedd`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| broad LDAP or RPC enumeration across accounts, groups, trusts, sessions, shares, and hosts | object-class/operation fan-out from a single process | public discovery rules often match command text or one API family, providing narrower but deployable branches | process-attributed multi-class directory query - moderate | ordered downstream security effect | complementary | Procedure `CSB-022` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: distributed discovery across multiple short-lived processes owned by the same user/session.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

directory management and inventory agents legitimately enumerate many classes. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed multi-class directory query | moderate | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but distributed discovery across multiple short-lived processes owned by the same user/session. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Event type `LDAP_QUERY` replaced by inventory `LDAP_SEARCH` (legacy alias kept) (DR-13).
  - Approval enrichment now fails open with `!= true`, so missing enrichment cannot silently suppress (DR-16).
  - Distinct-class count moved to `outcome`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_directory_discovery_compensating_signal.yaral`, SHA-256 `8724b7c5d9e11283629cc714dcd7de4b33cd1493621fa7de0c67250563830efe`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-022`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: distributed discovery across multiple short-lived processes owned by the same user/session.
- Required telemetry: normalized `LDAP_QUERY` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_directory_discovery_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-022"
  events:
    $e.metadata.event_type = "LDAP_QUERY"
        $e.principal.user.userid = $user
        $e.principal.hostname = $host
        $e.additional.fields["object_class"].value.string_value = $class
        $e.additional.fields["approved_directory_scanner"].value.bool_value = false
  match:
    $user, $host over 30m
  condition:
    $e and #class >= 4
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `8724b7c5d9e11283629cc714dcd7de4b33cd1493621fa7de0c67250563830efe`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/recon_successful_logon_enumeration_powershell_T1033_cisa_report.yaral` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Multi-class LDAP discovery split across short-lived processes | covered per user/host | `recon_successful_logon_enumeration_powershell_T1033_cisa_report.yaral`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | user/host object-class breadth - moderate | base directory rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_directory_discovery_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Aggregates multi-class LDAP directory queries by user and host, independent of any single process, to surface discovery distributed across multiple short-lived processes in the same session."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Session-scoped multi-class directory enumeration is useful reconnaissance context but directory-management and inventory agents legitimately enumerate many classes."
    procedure_ids = "CSB-022"
    log_source_prerequisites = "Normalize LDAP_QUERY with client account, hostname, and object-class field, plus an allowlist enrichment identifying approved directory-scanning software."
    false_positives = "Identity governance, endpoint inventory, directory health, administration and vulnerability-assessment tooling that legitimately queries many object classes."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_directory_discovery.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized domain-inventory logs spanning several object classes from approved scanners; confirm the allowlist enrichment suppresses them."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_directory_discovery"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_directory_discovery.md"
  events:
    $e.metadata.event_type = /^(LDAP_SEARCH|LDAP_QUERY)$/
    $e.principal.user.userid = $user
    $e.principal.hostname = $host
    $e.additional.fields["object_class"].value.string_value = $class
    $e.additional.fields["approved_directory_scanner"].value.bool_value != true
  match:
    $user, $host over 30m
  outcome:
    $classes = count_distinct($class)
  condition:
    $e and $classes >= 4
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
