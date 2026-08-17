# Public-rule comparison: rubeus_as_request_anomaly

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_as_request_anomaly.yaral`
- Internal SHA-256: `729c1bcd9139583935f6c96e78cc35b0ea7a8a52d8e2518bd02cf9bd4dafc3cf`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-001`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `a4eb95afd079e1433cd4ec4cb5420d592edcd4f597fd85b3f0104b29555794ab`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| AS request reaches a KDC | 4768 fan-out by source across three accounts | Port 88 flow followed by authentication from a nonstandard process | 4768 account/source cardinality - moderate | Process-attributed KDC network flow - moderate | complementary | Ours covers multi-principal probing; public adds process/network context. |
| Atypical preauthentication or failed probing | Not distinguished beyond 4768 count | Authentication result is present but public sequence is not AS-specific | 4768 result and PreAuthType - moderate | 4768 failure/result baselines | ours_stronger | Public rule does not isolate AS request failure/preauthentication branches. |
| Single-account TGT acquisition | Below three-account threshold | Can detect an unusual process making a KDC request | Process-to-KDC flow - moderate | Rare-process and account baseline | public_stronger | Ours deliberately misses a single targeted request. |

## Missing detection branches

- Missing from ours: Single-account requests; repeated requests spread across source IPs; account-specific preauthentication anomalies.
- Missing from public rule: AS-specific request/result semantics and multi-principal probing.
- Missing from both: Encrypted or un-attributed KDC traffic when neither DC 4768 nor endpoint network attribution is complete.

## Detection edge cases and blind spots

NAT can merge independent clients; DHCP and IPv6 representations can split one source. Password audits and identity infrastructure create benign fan-out. Source-only cardinality does not model account sensitivity or per-account history.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4768 across distinct principals | moderate | ours | Behavioral fan-out but common in scanners and identity systems. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process contacting KDC | moderate | public | Adds endpoint context but process rarity is environment-dependent. | Requires tenant-specific validation and collection-health monitoring. |
| Single 4768 | weak | both | Normal authentication is overwhelmingly common. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Broad Kerberos network/authentication sequence is not AS-specific and can conflate normal ticket activity.

## Internal-rule weaknesses

The condition does not implement the advertised atypical PreAuthType or result branches; it is only a three-account source fan-out.

## Decision trail

- Candidate improvement: Add separate 4768 branches for failure/preauthentication anomalies and sensitive-account baselines; keep process-to-KDC context as a compensating signal, subject to independent telemetry verification.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-001` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Failed or atypical-preauthentication AS probing that does not reach the existing generic fan-out threshold.
- Required telemetry: DC Security 4768; source IP, target account, result/action and normalized PreAuthType.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_as_request_failed_preauth_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-001"
  events:
    $e.metadata.product_event_type = "4768"
    $e.security_result.action != "ALLOW"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source over 10m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 3
}
```

Separates failed AS probing from successful TGT acquisition, producing a clearer branch than the current all-4768 cardinality. It still depends on tenant-specific result normalization and can miss single-account probing.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
