# Public-rule comparison: mimikatz_kerberos_activity

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_kerberos_activity.yaral`
- Internal SHA-256: `b9713ec360f243b84beccaff1303475e73258cdf600d3ca0ea6b56a133201886`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P10`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [Kerberos ticket artifact creation](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kirbi_file.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `6456b8900761c8253414fcd3b06d1eb2d57255d1a88ee8712b53b4ddd5a7c1e8`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Kerberos cache tickets are listed, exported, purged or submitted | cache/API and ticket artifact behavior | kirbi file creation only | caller-attributed LSA ticket submission followed by use - strong | kirbi extension alone - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: LSA ticket submit/retrieve, cache purge, ticket use after submission and in-memory-only operations.
- Missing from public rule: complete coverage of `P10` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| caller-attributed LSA ticket submission followed by use | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| kirbi extension alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

LSA ticket submit/retrieve, cache purge, ticket use after submission and in-memory-only operations. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The public kirbi-file rule is genuine (`complementary`), but the proposed `LSA_KERBEROS_TICKET_SUBMIT` event type does not correspond to any OS-observable telemetry: `kerberos::ptt` operates purely in-memory via `LsaCallAuthenticationPackage` and generates no Windows security event, consistent with the already-documented `not_observable` status of the closely related P11 (offline Kerberos construction) in `coverage/mimikatz.yml`. Adopting a rule keyed on this non-existent event would falsely claim observability that `reports/mimikatz/source-analysis.md` does not support, violating the "no telemetry without evidence" quality gate. Evidence resolved via `coverage/mimikatz.yml` (P10, P11) and the source report.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_kerberos_activity.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: LSA ticket submit/retrieve, cache purge, ticket use after submission and in-memory-only operations.
- Required telemetry: caller-attributed LSA Kerberos package operations and subsequent Kerberos authentication joined by logon session.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_ticket_submission_and_use {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P10"
  events:
    $s.metadata.product_event_type = "LSA_KERBEROS_TICKET_SUBMIT"
    $s.principal.user.userid = $user
    $s.principal.process.product_specific_process_id = $pid
    $s.target.resource.attribute.labels["logon_id"] = $luid
    $u.metadata.product_event_type = /(4769|KERBEROS_SERVICE_AUTH)/
    $u.principal.user.userid = $user
    $u.principal.resource.attribute.labels["logon_id"] = $luid
  match:
    $user, $luid over 30m
  outcome:
    $services = count_distinct($u.target.resource.name)
  condition:
    $s and $u
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
