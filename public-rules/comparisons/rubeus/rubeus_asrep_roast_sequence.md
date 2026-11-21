# Public-rule comparison: rubeus_asrep_roast_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_asrep_roast_sequence.yaral`
- Internal SHA-256: `a61074793e9cd077527eb94cab74d29e00008a858ebdca4747b5512dfe52eca3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-003`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_disable_kerberos_preauth.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_disable_kerberos_preauth.toml) - SHA-256 `68728c5adca5762dcb512cf2f536800499057a791dc74dd50fa81b0a6c2da6ff`
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `6ab27ba3bdb4279de4387de8a76f928fc24dd16eb25a2e8d7658cd9d447c1648`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Adopted as additive `rubeus_asrep_single_account_sensitive` with Status `0x0` added, so only issued AS-REPs count (REVIEW-014).
  - The hard `account_risk_tier = "high"` dependency is kept: without enrichment the additive rule stays silent instead of alerting on every legitimate no-pre-authentication account.
- Canonical result: `detections/rubeus/yaral/rubeus_asrep_roast_sequence.yaral`, SHA-256 `c083b11b86d7df5571ad9071069c797b9fb9cd7d8733c37e0c314fadd928f338`.
- Canonical result: `detections/rubeus/yaral/rubeus_asrep_single_account_sensitive.yaral`, SHA-256 `1d3c6021dc3fe12d0ab18b357146b8530fc905b8aa7aa9de1233a7fa55c72618`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_disable_kerberos_preauth.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
- `rules/windows/lateral_movement_credential_access_kerberos_correlation.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Multi-account no-pre-authentication AS requests | covered by base rule (>= 3 accounts) | not covered | PreAuthType 0 fan-out - strong | transport rule - strong | ours_stronger |
| Targeted single high-risk account | covered by `rubeus_asrep_single_account_sensitive` when risk enrichment exists | not covered | PreAuthType 0 + Status 0x0 + high-risk tier - strong | none without enrichment | ours_stronger |
| Attacker disables pre-authentication on an account first | not covered by Rubeus rules (precondition, outside PROC-003) | `credential_access_disable_kerberos_preauth.toml`: 4738 UAC change disabling pre-authentication | UAC change - strong | none | public_stronger |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_asrep_roast_sequence.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_asrep_roast_sequence {
  meta:
    author = "Detection Research Agent"
    description = "Detects one source requesting no-preauthentication AS responses for multiple accounts."
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Multi-account no-preauthentication requests closely match AS-REP roasting discovery and collection."
    procedure_ids = "PROC-003"
    log_source_prerequisites = "Normalize 4768 with source IP, account, and PreAuthType in the configured additional field."
    false_positives = "Authorized account configuration audits and identity assessment."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md"
    validation_status = "needs_validation"
    validation_method = "Verify the parser's PreAuthType representation with sanitized fixtures."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4768"
    $e.additional.fields["PreAuthType"].value.string_value = "0"
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

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_asrep_single_account_sensitive.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_asrep_single_account_sensitive {
  meta:
    author = "Detection Research Agent"
    description = "Detects a successful AS request without pre-authentication data for an account the tenant has classified as high-risk, compensating for targeted single-account AS-REP roasting below the three-account threshold of rubeus_asrep_roast_sequence."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A pre-authentication-free AS-REP for a high-risk account yields offline-crackable material even when only one account is targeted."
    procedure_ids = "PROC-003"
    log_source_prerequisites = "DC Security 4768 with PreAuthType, Status, source IP and target account, plus an account-risk enrichment that sets additional.fields[account_risk_tier] = high for privileged, service and other sensitive accounts. Without that enrichment this rule stays silent; the base three-account rule still applies."
    false_positives = "Sensitive accounts that legitimately have pre-authentication disabled for legacy clients; record them as approved exceptions in the risk enrichment."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_asrep_roast_sequence.md; reviews/rubeus/detection-review.md#review-014"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized 4768 fixtures for one high-risk no-pre-authentication account, one ordinary account and one failed request; confirm only the first matches and that the risk enrichment is present on 4768 events."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4768"
    $e.additional.fields["PreAuthType"].value.string_value = "0"
    $e.additional.fields["Status"].value.string_value = "0x0"
    $e.additional.fields["account_risk_tier"].value.string_value = "high"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source, $account over 1h
  outcome:
    $requests = count($e.metadata.id)
    $encryption_types = array_distinct($e.additional.fields["TicketEncryptionType"].value.string_value)
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
