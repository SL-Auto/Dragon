# Public-rule comparison: mimikatz_cross_process_tamper

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_cross_process_tamper.yaral`
- Internal SHA-256: `0b01786c2b755dcad09c4fcf1cc279a888f708b492f022af28af0bce78c1742a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P22,P27,P28,P32,P40`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [PowerShell process injection](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/defense_evasion_posh_process_injection.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `6d9b8743b0caf3e0ed247114e2d6fbf954962dc83debdafa4e1064088b1683bd`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| a process opens, writes, injects into or tampers with another security-sensitive process | cross-process access/tamper correlation | PowerShell-specific injection sequence | write/allocate/protect/thread sequence against a sensitive target - strong | one cross-process handle open - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: non-PowerShell injection, memory protection changes, sensitive target classes and remote thread creation.
- Missing from public rule: complete coverage of `P22,P27,P28,P32,P40` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| write/allocate/protect/thread sequence against a sensitive target | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| one cross-process handle open | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

non-PowerShell injection, memory protection changes, sensitive target classes and remote thread creation. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The public PowerShell-injection rule is genuine (`complementary`), but the proposed rewrite requires `metadata.product_event_type` values `VIRTUAL_ALLOC_EX`, `WRITE_PROCESS_MEMORY`, `CREATE_REMOTE_THREAD`, `QUEUE_APC` (Windows API names, not vendor event-type strings any product emits) and a fabricated `target.process.file.labels["security_sensitive"]` field, none of which are documented in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`. Converting the existing atomic rule into a strict two-stage join on these non-existent fields would only reduce recall relative to the current `re.regex($e.security_result.description, "(?i)(write|inject|remote.thread|tamper)")` check, which already provides equivalent conceptual coverage as an `accepted_gap` per `reviews/mimikatz/detection-review.md` REVIEW-006, and contradicts the deliberate atomic-signal architecture recorded in REVIEW-008. Evidence resolved via `coverage/mimikatz.yml` (P22,P27,P28,P32,P40), the canonical rule, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_cross_process_tamper.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: non-PowerShell injection, memory protection changes, sensitive target classes and remote thread creation.
- Required telemetry: EDR cross-process allocation/write/thread events with stable source/target process entities and sensitive-target classification.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_cross_process_write_execute_sequence {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P22,P27,P28,P32,P40"
  events:
    $a.metadata.product_event_type = /(PROCESS_OPEN|VIRTUAL_ALLOC_EX)/
    $a.principal.process.product_specific_process_id = $source
    $a.target.process.product_specific_process_id = $target
    $w.metadata.product_event_type = /(WRITE_PROCESS_MEMORY|CREATE_REMOTE_THREAD|QUEUE_APC)/
    $w.principal.process.product_specific_process_id = $source
    $w.target.process.product_specific_process_id = $target
    $w.target.process.file.labels["security_sensitive"] = "true"
  match:
    $source, $target over 5m
  outcome:
    $stages = count_distinct($w.metadata.product_event_type)
  condition:
    $a and $w
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/defense_evasion_posh_process_injection.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
