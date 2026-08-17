# Public-rule comparison: mimikatz_rpc_pipe_activity

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_rpc_pipe_activity.yaral`
- Internal SHA-256: `e4cebbd18de3614394a0b9f48df377f4a36dde4b5cf070297ad091e384956887`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P35,P38`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [alternate-credential lateral movement](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_alternate_creds_pth.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `c97393830fa3ec379bd46076c8f75be58db509c63c1d5661ef5f976d5f40f43b`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| named-pipe/RPC control or forced-authentication procedure is invoked | pipe/RPC operation correlation | No credible public counterpart in the pinned corpus; the examined alternate-credential lateral movement rule is adjacent only and is rejected as a procedure comparator | resolved coercion RPC operation followed by target authentication to caller-controlled endpoint - strong | named pipe string alone - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: interface UUID/opnum, pipe creation/access direction, target identity, result and subsequent authentication.
- Missing from public rule: complete coverage of `P35,P38` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| resolved coercion RPC operation followed by target authentication to caller-controlled endpoint | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| named pipe string alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

interface UUID/opnum, pipe creation/access direction, target identity, result and subsequent authentication. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; the examined alternate-credential lateral-movement rule was explicitly rejected as a non-comparator. The proposed rewrite depends on fabricated `RPC_CALL`/`NTLM_AUTH`/`KERBEROS_AUTH` event types and a `target.resource.attribute.labels["rpc_operation_class"]` field with no source in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`. Evidence resolved via `coverage/mimikatz.yml` (P35,P38) and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_rpc_pipe_activity.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: interface UUID/opnum, pipe creation/access direction, target identity, result and subsequent authentication.
- Required telemetry: resolved RPC interface/operation plus network authentication events joined by coerced target and time.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_rpc_coercion_to_authentication {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P35,P38"
  events:
    $r.metadata.product_event_type = "RPC_CALL"
    $r.principal.hostname = $source
    $r.target.hostname = $target
    $r.target.resource.attribute.labels["rpc_operation_class"] = "authentication_coercion"
    $a.metadata.product_event_type = /(NTLM_AUTH|KERBEROS_AUTH)/
    $a.principal.hostname = $target
    $a.target.hostname = $destination
  match:
    $target over 5m
  outcome:
    $destinations = count_distinct($destination)
  condition:
    $r and $a
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
