# Public-rule comparison: rubeus_asrep_roast_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_asrep_roast_sequence.yaral`
- Internal SHA-256: `a61074793e9cd077527eb94cab74d29e00008a858ebdca4747b5512dfe52eca3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-003`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_disable_kerberos_preauth.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_disable_kerberos_preauth.toml) - SHA-256 `087a8e0ac15450e25ce75c6b1c2e316f9502728c980336484c27053541c23bfb`
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `a4eb95afd079e1433cd4ec4cb5420d592edcd4f597fd85b3f0104b29555794ab`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Account becomes roastable | Not covered | Public rule detects disabling Kerberos preauthentication | Directory account-control change - strong | Change actor and approved-change context | public_stronger | Public covers the enabling configuration change, which is causally prior to roasting. |
| No-preauthentication AS response requested | 4768 PreAuthType 0 for three accounts from one source | Only broad KDC traffic/authentication context | 4768 PreAuthType 0 - strong | Endpoint process-to-KDC flow | ours_stronger | Ours directly observes the no-preauthentication request branch. |
| AS-REP collection against one account | Below threshold | Broad unusual-process flow may alert | Process-attributed KDC flow - moderate | Sensitive-account and first-seen baselines | public_stronger | Public compensating signal can cover a single request where ours requires three accounts. |

## Missing detection branches

- Missing from ours: Single-account roasting; requests distributed across sources or beyond ten minutes; parser variants where PreAuthType is numeric.
- Missing from public rule: Direct no-preauthentication request semantics and AS-REP fan-out.
- Missing from both: Offline cracking after response collection has no distinctive standard log.

## Detection edge cases and blind spots

PreAuthType representation varies by collector. NAT can aggregate sources. Existing accounts without preauthentication produce no configuration-change event during the detection window.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4768 with PreAuthType 0 | strong | ours | Close to the roastable AS exchange and relatively uncommon. | Requires tenant-specific validation and collection-health monitoring. |
| Preauthentication disabled | strong | public | Security-relevant enabling state change, though not proof of exploitation. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process to port 88 | moderate | public | Useful compensation but not AS-REP specific. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

The configuration rule cannot show exploitation of accounts already configured without preauthentication; the network rule is broad.

## Internal-rule weaknesses

The three-account threshold creates a material targeted-single-account gap and assumes one stable source.

## Decision trail

- Candidate improvement: Retain the strong PreAuthType branch; add a lower-volume sensitive/rare-account branch and separately monitor preauthentication-disable changes after verifying directory audit mappings.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-003` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Targeted no-preauthentication request against one sensitive or unusually roastable account.
- Required telemetry: DC Security 4768 with normalized PreAuthType plus an independently maintained account-risk enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_asrep_roast_sensitive_account {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-003"
  events:
    $e.metadata.product_event_type = "4768"
    $e.additional.fields["PreAuthType"].value.string_value = "0"
    $e.additional.fields["account_risk_tier"].value.string_value = "high"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  condition:
    $e
}
```

Closes the single-account gap without weakening the existing multi-account rule. The risk tier must come from authoritative identity enrichment; a hard-coded account list would be too fragile.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
