# Public-rule comparison: rubeus_ticket_use_without_credible_kdc_issue

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_ticket_use_without_credible_kdc_issue.yaral`
- Internal SHA-256: `2e7c381cd1ad64d6959f2187fa2e384081edacc3c80881c22fbbe5a7f26e2478`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-008,PROC-009`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/Alsid For AD/Analytic Rules/GoldenTicket.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/Alsid For AD/Analytic Rules/GoldenTicket.yaml) - SHA-256 `2fd3d8af02686d7b5ec8dc3056a8cc20393639d0bd6a32cf98093e1e4f93a846`
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `a4eb95afd079e1433cd4ec4cb5420d592edcd4f597fd85b3f0104b29555794ab`

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

- Candidate improvement: Gate the rule on DC coverage health, separate PAC-anomaly and issuance-absence branches, and ingest vendor alerts as independent corroboration rather than ground truth.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

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
