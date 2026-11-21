# Public-rule comparison: rubeus_ticket_use_without_credible_kdc_issue

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_ticket_use_without_credible_kdc_issue.yaral`
- Internal SHA-256: `2e7c381cd1ad64d6959f2187fa2e384081edacc3c80881c22fbbe5a7f26e2478`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-008,PROC-009`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Alsid For AD/Analytic Rules/GoldenTicket.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Alsid For AD/Analytic Rules/GoldenTicket.yaml) - SHA-256 `2fd3d8af02686d7b5ec8dc3056a8cc20393639d0bd6a32cf98093e1e4f93a846`
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `6ab27ba3bdb4279de4387de8a76f928fc24dd16eb25a2e8d7658cd9d447c1648`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Forged or mutated ticket used at service | Kerberos service use with PAC anomaly | Alsid emits vendor Golden Ticket alert; Elastic observes Kerberos network/auth sequence | Resource-side PAC/identity anomaly - strong | Vendor identity analytic | complementary | Ours states the raw effect; public supplies alternate analytic/process context. |
| No credible KDC issuance exists | Requires zero matching 4769 for 12 hours | Public rules do not require issuance absence | Complete multi-DC issuance absence - moderate | Cross-DC replication and referral-aware correlation | ours_stronger | Unique branch, but only trustworthy with complete telemetry. |
| Ticket use resembles normal activity | PAC anomaly required | Vendor analytic may use proprietary context; Elastic process sequence can add endpoint evidence | Multiple independent anomalies - strong | Rare process/source/service baseline | complementary | Layering can raise confidence without treating absence alone as proof. |

## Missing detection branches

- Missing from ours: Cross-realm referrals, cached ticket lifetime, DC completeness proof, clock skew, identity aliases, silver-ticket cases with no DC contact, and resource-specific PAC fields.
- Missing from public rule: Transparent raw-event explanation for proprietary Golden Ticket alert; issuance-absence branch.
- Missing from both: Forged tickets whose PAC and use look valid and where resource telemetry lacks anomaly fields.

## Detection edge cases and blind spots

Missing one DC invalidates absence. Cached tickets legitimately outlive the search window. Source NAT and service aliases break joins. Vendor alert semantics are opaque.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Resource-side PAC/identity anomaly | strong | ours | Close to validation failure or identity inconsistency. | Requires tenant-specific validation and collection-health monitoring. |
| No matching 4769 | moderate | ours | Useful only with provably complete DC logs. | Requires tenant-specific validation and collection-health monitoring. |
| Vendor Golden Ticket alert | moderate | public | Potentially strong but opaque and product-dependent. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Alsid rule merely forwards a vendor codename; Elastic sequence is broad and neither exposes complete forgery reasoning.

## Internal-rule weaknesses

Depends on a nonstandard identity_or_pac_anomaly field and a fragile 12-hour absence join; cannot safely operate with incomplete DC telemetry.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The 2026-08-16 adoption equals the proposal. Re-review found `$health` unjoined to the activity, so any healthy report anywhere satisfied the gate; it now joins on `target.administrative_domain` (REVIEW-013).
  - `#tgs = 0` replaced with the documented non-existence form `!$tgs`.
- Canonical result: `detections/rubeus/yaral/rubeus_ticket_use_without_credible_kdc_issue.yaral`, SHA-256 `d0d1d14b898aaad946ceb026c8cd37f449c323cca9cc756df15a6440719ac9f1`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

Public candidates do not cover the full `PROC-008,PROC-009` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: PAC/identity anomaly and KDC-issuance absence gated by explicit DC collection health.
- Required telemetry: Resource-side Kerberos use/PAC anomaly, complete 4769 from all authoritative DCs, and a collection-health event proving coverage for the window.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_ticket_use_without_issue_with_healthy_dc_coverage {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-008,PROC-009"
  events:
    $health.metadata.product_event_type = "COLLECTION_HEALTH"
    $health.additional.fields["all_domain_controllers_reporting"].value.bool_value = true
    $access.metadata.event_type = "USER_LOGIN"
    $access.security_result.auth_details = "KERBEROS"
    $access.additional.fields["identity_or_pac_anomaly"].value.bool_value = true
    $access.target.user.userid = $user
    $access.principal.ip = $source
    $access.target.resource.name = $service
    $tgs.metadata.product_event_type = "4769"
    $tgs.target.user.userid = $user
    $tgs.principal.ip = $source
    $tgs.target.resource.name = $service
  match:
    $user, $source, $service over 12h
  condition:
    $health and $access and #tgs = 0
}
```

Prevents absence logic from firing when DC coverage is known to be incomplete. Production design must bind health to the same domain/window and account for referrals, cache lifetime and cross-realm issuance.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/lateral_movement_credential_access_kerberos_correlation.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Resource-side Kerberos use with PAC/identity anomaly and no observed TGS | covered, gated on domain-joined DC collection health | `GoldenTicket.yaml`: Alsid/Tenable AD product alert | absence + PAC anomaly - moderate | vendor golden-ticket alert - moderate | complementary |
| Unusual process to port 88 correlated with a DC ticket request | covered by `rubeus_kerberos_transport_from_unexpected_process` (without DC correlation) | `lateral_movement_credential_access_kerberos_correlation.toml` | non-LSA port 88 - strong | DC 4768/4769 - moderate | complementary |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_ticket_use_without_credible_kdc_issue.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_ticket_use_without_credible_kdc_issue {
  meta:
    author = "Detection Research Agent"
    description = "Detects anomalous Kerberos-authenticated service use without a corresponding observed service-ticket issue, gated on an explicit domain-controller collection-health signal so absence-based logic never fires during known incomplete DC coverage."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "The pattern can expose forged or mutated tickets, but incomplete DC logging can create false positives; the collection-health gate reduces that specific failure mode."
    procedure_ids = "PROC-008,PROC-009"
    log_source_prerequisites = "Centralize complete 4769 telemetry and resource-side Kerberos service-use/PAC anomaly data with normalized user, source, and service, plus a collection-health event that proves all authoritative domain controllers reported for the correlation window. The health event and the resource-side access event must both carry the AD domain in target.administrative_domain; that field joins the health gate to the activity."
    false_positives = "Missing DC logs, cached tickets, referrals, cross-realm activity, and parser mismatches; the collection-health gate mitigates but does not eliminate these because health may be reported as true while an individual DC's forwarder is silently stalled."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_ticket_use_without_credible_kdc_issue.md; reviews/rubeus/detection-review.md#review-013"
    validation_status = "needs_validation"
    validation_method = "Test complete and intentionally incomplete DC-log fixtures, including cases where the collection-health signal itself is stale, delayed, or missing; never infer forgery from absence alone. Confirm the collection-health source is authoritative for the same domain and window as the correlated user/source/service activity."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $health.metadata.product_event_type = "COLLECTION_HEALTH"
    $health.additional.fields["all_domain_controllers_reporting"].value.bool_value = true
    $health.target.administrative_domain = $domain

    $access.metadata.event_type = "USER_LOGIN"
    $access.security_result.auth_details = "KERBEROS"
    $access.target.user.userid = $user
    $access.principal.ip = $source
    $access.target.resource.name = $service
    $access.target.administrative_domain = $domain
    $access.additional.fields["identity_or_pac_anomaly"].value.bool_value = true

    $tgs.metadata.product_event_type = "4769"
    $tgs.target.user.userid = $user
    $tgs.principal.ip = $source
    $tgs.target.resource.name = $service
  match:
    $user, $source, $service over 12h
  condition:
    $health and $access and !$tgs
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
