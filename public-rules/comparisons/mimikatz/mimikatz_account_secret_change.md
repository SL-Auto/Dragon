# Public-rule comparison: mimikatz_account_secret_change

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_account_secret_change.yaral`
- Internal SHA-256: `eff1b1e06143deca4e83be2e06b325a8189a34ecfd256e54c9ec1ad817381cd1`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P16`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [alternate-credential lateral movement](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_alternate_creds_pth.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `c97393830fa3ec379bd46076c8f75be58db509c63c1d5661ef5f976d5f40f43b`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SAMR or Netlogon changes a machine/account secret | secret-change events across multiple accounts | No credible public counterpart in the pinned corpus; the examined alternate-credential lateral movement rule is adjacent only and is rejected as a procedure comparator | successful secret change by a non-management caller with later authentication - strong | generic password reset - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: single high-value account, protocol result, caller trust and subsequent authentication.
- Missing from public rule: complete coverage of `P16` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| successful secret change by a non-management caller with later authentication | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| generic password reset | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

single high-value account, protocol result, caller trust and subsequent authentication. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; no credible public rule was found for this branch (the examined candidate was explicitly rejected as a non-comparator), so there is no external evidence of a real capability gap. The proposed rewrite also depends on `metadata.product_event_type` literals (`NETLOGON_SECRET_CHANGE`, `SAMR_PASSWORD_SET`) and a `principal.labels["approved_password_manager"]` boolean trust label that appear in no telemetry source in `telemetry/mimikatz.md`, `schemas/chronicle-udm.yml`, or `reports/mimikatz/source-analysis.md`. This reproduces the brittle single-label allowlist pattern that `reviews/mimikatz/detection-review.md` REVIEW-003 already found `high` severity and removed; an unpopulated label would make the proposed rule silently never fire, which is strictly worse than the existing broad rule it would replace. Evidence resolved via `coverage/mimikatz.yml` (P16), `telemetry/mimikatz.md`, `schemas/chronicle-udm.yml`, and `reviews/mimikatz/detection-review.md`.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_account_secret_change.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: single high-value account, protocol result, caller trust and subsequent authentication.
- Required telemetry: successful SAMR/Netlogon or Windows password-change events with actor, target and approved-management enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_untrusted_account_secret_change {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P16"
  events:
    $e.metadata.product_event_type = /(4723|4724|NETLOGON_SECRET_CHANGE|SAMR_PASSWORD_SET)/
    $e.principal.user.userid = $actor
    $e.target.user.userid = $account
    $e.security_result.action = "ALLOW"
    $e.principal.labels["approved_password_manager"] = "false"
  match:
    $actor over 30m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 2
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
