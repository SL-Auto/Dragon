# Public-rule comparison: rubeus_service_ticket_or_renewal_anomaly

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_service_ticket_or_renewal_anomaly.yaral`
- Internal SHA-256: `7b517d0087da933b30c0326252764286fce35c23f3284e9780614bd99b81e0e4`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-002`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/SecurityEvent/PotentialKerberoast.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/SecurityEvent/PotentialKerberoast.yaml) - SHA-256 `747d8097f4af3b53bd1d3093223a149055eac51ac600d1e272b42d9567028f51`
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberos_service_ticket_rc4.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberos_service_ticket_rc4.toml) - SHA-256 `44920ffa1bab5f18bf5ec564c014586c3cfdb71302d80a42e884e0eb1e70d010`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The split was adopted as `rubeus_rc4_service_ticket_fanout` and `rubeus_ticket_renewal_anomaly`, with the base rule kept for generic volume.
  - The RC4 approval fails open (`!= true`) rather than the proposal's `= false`, Status `0x0` is required, and machine-account and `krbtgt` services are excluded (REVIEW-008).
  - Renewal severity was lowered to LOW because low-rate auto-renewal is inherent to 4770 (REVIEW-009).
- Canonical result: `detections/rubeus/yaral/rubeus_service_ticket_or_renewal_anomaly.yaral`, SHA-256 `54cb207aa111ac266e97d3ebdb87128c1a060a7a7879788b0cddcb5a54f28654`.
- Canonical result: `detections/rubeus/yaral/rubeus_rc4_service_ticket_fanout.yaral`, SHA-256 `d3c84be9ce37220cb488f1a2c1c1acb6083442186c8a54b1f3a729a9d689d541`.
- Canonical result: `detections/rubeus/yaral/rubeus_ticket_renewal_anomaly.yaral`, SHA-256 `2a04cd4cec661d477073af7413f648513699dfc8752a94bef58041f113a5fb86`.
- Regeneration: the split rules were reviewed and regenerated earlier on 2026-11-21 (REVIEW-008, REVIEW-009); re-verified current.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_kerberos_service_ticket_rc4.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| RC4 TGS acquisition for a newly seen requester/service pair | covered by fan-out (>= 3 services in 15m), not by novelty | `credential_access_kerberos_service_ticket_rc4.toml`: 7-day new-terms on requester/service RC4 pair | RC4 success fan-out - moderate | public new-terms - moderate | complementary |
| Single novel RC4 service ticket | not covered | covered | new-terms pair - moderate | `rubeus_kerberos_transport_from_unexpected_process` - strong | public_stronger |
| Ticket renewal bursts | covered by `rubeus_ticket_renewal_anomaly` (LOW) | not covered | 4770 burst - weak | none | ours_stronger |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_service_ticket_or_renewal_anomaly.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_service_ticket_or_renewal_anomaly {
  meta:
    author = "Detection Research Agent"
    description = "Detects unusual service-ticket (4769) acquisition volume by one source and identity. Split from ticket renewal, which is a separately scored signal covered by rubeus_ticket_renewal_anomaly, and complemented by the ticket-property-specific rubeus_rc4_service_ticket_fanout."
    date = "2026-08-16"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Generic 4769 fan-out is a useful lead but common in service and SSO workflows and does not use ticket-property specificity; kept as a broad compensating signal alongside the RC4-specific and LDAP-sequence rules."
    procedure_ids = "PROC-002"
    log_source_prerequisites = "Normalize DC Security 4769 with account, source IP, service, result, and encryption type."
    false_positives = "SSO, service accounts, application servers, and scanners generating broad service-ticket fan-out."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md"
    validation_status = "needs_validation"
    validation_method = "Measure account/source baselines and replay near-threshold fixtures. Confirm this rule, rubeus_ticket_renewal_anomaly, and rubeus_rc4_service_ticket_fanout are all enabled together, since renewal (4770) and the RC4-specific branch were split out of this rule's scope on 2026-08-16."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4769"
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 10m
  outcome:
    $event_count = count($e.metadata.id)
    $service_count = count_distinct($service)
  condition:
    $e and ($event_count >= 20 or $service_count >= 10)
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_rc4_service_ticket_fanout.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_rc4_service_ticket_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects a single requester obtaining RC4-encrypted service tickets for three or more distinct unapproved-legacy services within a 15-minute window, independent of LDAP SPN-discovery visibility."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "RC4 service-ticket fan-out against services not on the approved-legacy allowlist closely matches offline-crackable ticket collection (Kerberoasting) and low-and-slow renewal-adjacent acquisition, and is more specific than generic 4769 volume."
    procedure_ids = "PROC-002,PROC-004"
    log_source_prerequisites = "Normalize DC Security 4769 with source IP, requesting user, target service, TicketEncryptionType and Status, plus an approved-legacy-RC4-service enrichment keyed by target service (missing enrichment fails open)."
    false_positives = "Approved legacy RC4 services and application servers that have not yet been migrated to AES; environments where the legacy-RC4-service enrichment is stale, incomplete, or absent (an unpopulated enrichment field defaults to unapproved and will over-alert until the allowlist is built)."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md"
    validation_status = "needs_validation"
    validation_method = "Verify the TicketEncryptionType parser mapping for 0x17 (RC4-HMAC) with sanitized fixtures. Build and validate the approved-legacy-RC4-service allowlist before enabling, and confirm services correctly marked approved do not fire. This rule intentionally consolidates two independently proposed comparison improvements (rubeus_kerberoast_sequence.md and rubeus_service_ticket_or_renewal_anomaly.md both proposed a near-identical RC4 service-ticket fan-out compensating rule under different names and thresholds); adopting both separately would have duplicated the same detection logic, so a single shared rule is canonical for both procedures."
    review_status = "reviewed"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["Status"].value.string_value = "0x0"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value != true
    not re.regex($e.target.resource.name, `(?i)(\$$|^krbtgt$)`)
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_ticket_renewal_anomaly.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_ticket_renewal_anomaly {
  meta:
    author = "Detection Research Agent"
    description = "Detects a burst of Kerberos ticket renewals (4770) by one source and identity, a scripted or looping renewal anomaly separated from service-ticket (4769) acquisition volume. It does not identify low-rate automatic renewal, which is indistinguishable from native LSA renewal."
    date = "2026-11-21"
    status = "experimental"
    severity = "LOW"
    severity_rationale = "A renewal burst is anomalous but weakly attributable: native clients renew automatically, and tool-driven auto-renewal near expiry produces low-rate events identical to the operating system's. Severity lowered from MEDIUM after review REVIEW-009."
    procedure_ids = "PROC-002"
    log_source_prerequisites = "Normalize DC Security 4770 with account, source IP, service, and result."
    false_positives = "Long-running services, SSO session-renewal components, and scheduled tasks that legitimately renew tickets repeatedly."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md"
    validation_status = "needs_validation"
    validation_method = "Measure per-account/source renewal baselines and replay near-threshold fixtures before enabling; the 15-event/10-minute threshold is a starting point and requires tenant-specific tuning."
    review_status = "reviewed"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4770"
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 10m
  outcome:
    $event_count = count($e.metadata.id)
    $services = array_distinct($service)
  condition:
    $e and $event_count >= 15
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
