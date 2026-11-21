# Public-rule comparison: cloudfox_azure_app_settings_secret_list

## Identity and independence gate

- Internal tool: `cloudfox` (revision `f65be085cde3768281c2dbafc57542a56ee12ebe`)
- Internal canonical rule: `detections/cloudfox/yaral/cloudfox_azure_app_settings_secret_list.yaral`
- Internal SHA-256: `ad2744863bf1af37f032a5b6f9c02ef4019fe38d98b4c0edb41eecb8f25f057b`
- Internal review completed before public comparison: `yes` (`reviews/cloudfox/detection-review.md`, CF-DR-01 to CF-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_azure_storage_account_keys_accessed.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_azure_storage_account_keys_accessed.toml) - SHA-256 `b877d974abef3955e9ad8885556a0483caf2625a836d3794ec06526797b852c7`
- Scope mapping rationale: Both detect Azure Activity Log list actions that return secrets in clear text (T1552). The public rule targets storage account keys (LISTKEYS); ours targets App Service settings.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| App Service settings or connection strings listed across sites | covered | not covered | list action - strong | ARM read fan-out - moderate | ours_stronger |
| Storage account keys listed by a privileged user | not covered (CloudFox does not call listKeys) | covered | LISTKEYS action - strong | none | different_scope |

## Missing detection branches

- None for CloudFox; storage key listing is outside its source.

## Detection edge cases and blind spots

- The portal Configuration blade issues the same action (CF-DR-05).

## Signal-quality assessment

- Both: secret-returning list actions - strong.

## Public-rule weaknesses

- It requires role evidence in the log record and new-terms history.

## Internal-rule weaknesses

- No user agent is available to separate portal traffic.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/cloudfox/source-analysis.md`, `telemetry/cloudfox.md` and `reviews/cloudfox/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would add the storage LISTKEYS action. CloudFox's storage module uses data-plane listing with a token (`azure/storage.go`) and never calls listKeys, so this adds a procedure the tool does not perform.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

Storage account key access belongs to tools that call listKeys. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Storage account key listing.
- Required telemetry: Azure Activity Log list actions.
- Validation status: `unvalidated_proposal`

```yaral
rule cloudfox_azure_secret_list_actions_extended {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "CF-Z04"
    source_comparison = "unvalidated_proposal"
  events:
    re.regex($e.metadata.product_event_type, `(?i)^(MICROSOFT\.WEB/SITES/CONFIG/LIST/ACTION|MICROSOFT\.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION)$`)
    $e.principal.user.userid = $caller
  match:
    $caller over 30m
  condition:
    $e
}
```
