# Public-rule comparison: mimikatz_clipboard_device_access

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_clipboard_device_access.yaral`
- Internal SHA-256: `ad4933fcfd4caf8b8714edf38d3469a4651e1f9b221d13c7f65e210513375683`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P34,P42`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [PowerShell process injection](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/defense_evasion_posh_process_injection.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `6d9b8743b0caf3e0ed247114e2d6fbf954962dc83debdafa4e1064088b1683bd`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| clipboard or hardware device content is accessed for collection/control | device/clipboard access context | No credible public counterpart in the pinned corpus; the examined PowerShell process injection rule is adjacent only and is rejected as a procedure comparator | rare process repeatedly reading clipboard or protected device objects - strong | clipboard API access alone - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: clipboard read APIs, raw device handle access, caller trust.
- Missing from public rule: complete coverage of `P34,P42` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| rare process repeatedly reading clipboard or protected device objects | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| clipboard API access alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

clipboard read APIs, raw device handle access, caller trust. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`, and the examined public candidate (PowerShell process injection) is topically unrelated to clipboard/device access — the weakest grounding of any comparison in this backlog. The proposed `split` rule depends entirely on a fabricated `CLIPBOARD_READ` event type and `principal.process.file.labels["approved_clipboard_app"]` / `target.resource.attribute.labels["content_present"]` fields with no basis in `schemas/chronicle-udm.yml`, `telemetry/mimikatz.md`, or `reports/mimikatz/source-analysis.md`. No genuine capability gap is evidenced. Evidence resolved via `coverage/mimikatz.yml` (P34,P42) and `telemetry/mimikatz.md`.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_clipboard_device_access.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: clipboard read APIs, raw device handle access, caller trust.
- Required telemetry: EDR clipboard-read or API telemetry with process entity, content-present flag and approved application enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_untrusted_clipboard_collection {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P34,P42"
  events:
    $e.metadata.product_event_type = "CLIPBOARD_READ"
    $e.principal.process.product_specific_process_id = $pid
    $e.principal.process.file.labels["approved_clipboard_app"] = "false"
    $e.target.resource.attribute.labels["content_present"] = "true"
    $e.principal.hostname = $host
  match:
    $host, $pid over 10m
  outcome:
    $reads = count($e.metadata.id)
  condition:
    $e and $reads >= 3
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/defense_evasion_posh_process_injection.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
