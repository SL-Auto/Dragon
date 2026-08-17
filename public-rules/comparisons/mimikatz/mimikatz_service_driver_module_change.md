# Public-rule comparison: mimikatz_service_driver_module_change

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_service_driver_module_change.yaral`
- Internal SHA-256: `a1210bce3c5fe64b4a8008b424b845ab9c2bbede5ff0a0fffda6bb50a7da1c6c`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P06,P36,P44,P45`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [LSA security-package registration](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/persistence_via_lsa_security_support_provider_registry.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `49cfe6d605473eedb20f48f0d285a100081ea4f3f91bcc9f3e21cf02a47410a6`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| service, driver, print monitor or LSA module state is changed | service/module change correlation | specific security-package registry persistence | untrusted module registration followed by load into a protected service process - strong | 7045 service install alone - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: print monitor, service DLL, driver load result, module load into LSASS/spooler and signer trust.
- Missing from public rule: complete coverage of `P06,P36,P44,P45` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted module registration followed by load into a protected service process | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| 7045 service install alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

print monitor, service DLL, driver load result, module load into LSASS/spooler and signer trust. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `modify`.
- Reason: Accept the identified gap — the public LSA security-package registration rule is genuine (`complementary`), and a module load into a protected process (LSASS or the print spooler) is materially stronger evidence than a bare service/registry registration event alone. Reject the specific proposed implementation: `metadata.product_event_type` values `REGISTRY_VALUE_SET`/`IMAGE_LOAD` and a `target.file.labels["trusted_module"]` field are undocumented in `schemas/chronicle-udm.yml` and `telemetry/mimikatz.md`, and the proposed registration-to-load join has no validated field mapping. The gap is independently reimplemented using only the raw Sysmon Image Load event ID ("7") already used in the existing `mimikatz_service_driver_module_change` rule, matched against `principal.process.file.full_path` for `lsass.exe`/`spoolsv.exe` — no invented labels, no unvalidated join.
- Regeneration performed: added new canonical rule `detections/mimikatz/yaral/mimikatz_module_load_into_lsass_or_spooler.yaral` (additive; the original broad `mimikatz_service_driver_module_change` rule is unchanged); adversarial review recorded as REVIEW-011 in `reviews/mimikatz/detection-review.md`; `coverage/mimikatz.yml` reconciled to add the new rule against P06,P36,P44,P45; `telemetry/mimikatz.md` rule-by-rule table updated with a new row; all 5 secondary translations generated under `detections/mimikatz/{spl,kql,sql,eql,sigma}/mimikatz_module_load_into_lsass_or_spooler.*` with `source_yaral`, `translation_status` and `fidelity: partial` recorded; `dependencies/mimikatz/*.yml` and `manifests/mimikatz.yml` refreshed via `scripts/update-context-index.ps1`.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: print monitor, service DLL, driver load result, module load into LSASS/spooler and signer trust.
- Required telemetry: registry/service/module registration plus image-load telemetry with normalized module path, target process and signature trust.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_module_registration_to_protected_load {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P06,P36,P44,P45"
  events:
    $r.metadata.product_event_type = /(4657|REGISTRY_VALUE_SET|7045)/
    $r.principal.hostname = $host
    $r.target.file.full_path = $module
    $l.metadata.product_event_type = /(7|IMAGE_LOAD)/
    $l.principal.hostname = $host
    $l.target.file.full_path = $module
    $l.principal.process.file.full_path = /(?i)(lsass|spoolsv)\.exe$/
    $l.target.file.labels["trusted_module"] = "false"
  match:
    $host, $module over 30m
  outcome:
    $loads = count($l.metadata.id)
  condition:
    $r and $l
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.
