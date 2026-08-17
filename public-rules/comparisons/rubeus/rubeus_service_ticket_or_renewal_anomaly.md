# Public-rule comparison: rubeus_service_ticket_or_renewal_anomaly

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_service_ticket_or_renewal_anomaly.yaral`
- Internal SHA-256: `7b517d0087da933b30c0326252764286fce35c23f3284e9780614bd99b81e0e4`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-002`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/SecurityEvent/PotentialKerberoast.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/SecurityEvent/PotentialKerberoast.yaml) - SHA-256 `747d8097f4af3b53bd1d3093223a149055eac51ac600d1e272b42d9567028f51`
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberos_service_ticket_rc4.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberos_service_ticket_rc4.toml) - SHA-256 `e085313adc2c36de162560a69535264691aa9b43290e4ac4cf707551d7d3b155`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High-volume TGS acquisition | 20 events or 10 services per source/user | Sentinel detects RC4/options service burst with historical comparison | RC4/options service-ticket burst - strong | Requester-to-service novelty | public_stronger | Public logic is more specific to roastable ticket acquisition. |
| New requester-to-service RC4 relationship | Only volume | Elastic new-terms rule covers first/infrequent RC4 relationship | New RC4 relationship - moderate | Service-account sensitivity | public_stronger | Public covers low-volume novelty. |
| Ticket renewal activity | 4770 included in same volume | Not covered by compared public rules | Abnormal renewal rate/context - moderate | Ticket lifetime and source baseline | ours_stronger | Ours includes renewal, though with weak generic thresholds. |

## Missing detection branches

- Missing from ours: Encryption/options, first-seen relationship, per-service sensitivity, distinct treatment of 4769 and 4770, low-and-slow acquisition.
- Missing from public rule: Renewal anomalies and non-RC4 ticket fan-out.
- Missing from both: Normal-volume requests for one high-value service and incomplete DC coverage.

## Detection edge cases and blind spots

Application servers and SSO create high cardinality. RC4 may be legitimate for legacy services. A fixed ten-minute threshold does not transfer across environments.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| RC4/options burst | strong | public | More closely matches roastable ticket collection. | Requires tenant-specific validation and collection-health monitoring. |
| First-seen RC4 relationship | moderate | public | Useful low-volume context but depends on history. | Requires tenant-specific validation and collection-health monitoring. |
| Generic 4769/4770 volume | weak | ours | Broad and noisy without ticket properties. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

RC4 focus misses AES and legitimate legacy environments need tuning; historical novelty depends on stable retention.

## Internal-rule weaknesses

Combines acquisition and renewal and uses fixed generic volume without ticket result, encryption or options.

## Decision trail

- Candidate improvement: Split 4769 acquisition from 4770 renewal; add encryption/options, rarity and sensitive-service branches; retain generic fan-out only as a lower-confidence signal.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-002` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Service-ticket acquisition separated from ticket renewal, with RC4/legacy context.
- Required telemetry: DC Security 4769 with requester, service, encryption type and approved legacy-service enrichment; retain 4770 for a separate renewal baseline.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_unapproved_rc4_service_ticket_burst {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-002,PROC-004"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value = false
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 10m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
```

Replaces a weak combined 4769/4770 count with a more specific acquisition branch. Renewal needs its own account/source historical baseline; fixed public thresholds are not adopted without local distributions.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
