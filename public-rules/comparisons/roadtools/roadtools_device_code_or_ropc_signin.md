# Public-rule comparison: roadtools_device_code_or_ropc_signin

## Identity and independence gate

- Internal tool: `roadtools` (revision `792708365789be4e6f58db65c3f90701159fd0ea`)
- Internal canonical rule: `detections/roadtools/yaral/roadtools_device_code_or_ropc_signin.yaral`
- Internal SHA-256: `5532e503822502b951c1afd797b56c8bb1c7421bd3ee2e5ff392b9d413f16530`
- Internal review completed before public comparison: `yes` (`reviews/roadtools/detection-review.md`, RT-DR-01 to RT-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/initial_access_entra_id_device_code_auth_with_broker_client.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/initial_access_entra_id_device_code_auth_with_broker_client.toml) - SHA-256 `71fc6d487e8ed21ea573cfd89644da3833daeeb4cd643362a6dd8ef308956b84`
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_ropc_unknown_client_id.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_ropc_unknown_client_id.toml) - SHA-256 `edc12c73b4fadb96016e32297b6731ffa2c71d4830e76d63517eeec393a3576b`
- Scope mapping rationale: All detect abuse of non-interactive sign-in protocols (T1078.004, T1528): device code to the Microsoft Authentication Broker, and ROPC with unknown client IDs.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Successful device-code or ROPC sign-in | covered | partially (broker device code; failed ROPC with unknown client) | protocol - moderate | FOCI hopping - strong | complementary |
| Device code to the broker client | not covered before this comparison | covered | broker appId plus device code - strong | new rule | public_stronger |
| ROPC attempts with nonexistent client IDs (error 700016) | not covered | covered | error code - moderate | none | different_scope |

## Missing detection branches

- The broker-client branch was missing (RT-DR-10).

## Detection edge cases and blind spots

- Legitimate device-code and ROPC usage.

## Signal-quality assessment

- Adopted broker rule - strong.
- Generic protocol rule - moderate.

## Public-rule weaknesses

- ROPC unknown-client applies to tools that send random client IDs; ROADtools uses known first-party IDs.

## Internal-rule weaknesses

- The generic rule is noisy.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/roadtools/source-analysis.md`, `telemetry/roadtools.md` and `reviews/roadtools/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The broker-client device-code branch is adopted as `roadtools_broker_client_device_code_signin` (RT-DR-10).
  - The ROPC unknown-client branch is rejected: ROADtools uses known first-party client IDs, so error 700016 is not a ROADtools effect.
- Canonical result: `detections/roadtools/yaral/roadtools_broker_client_device_code_signin.yaral`, SHA-256 `229762937b025c763008f4f699936fa0e1a60442ce4e92240fa26a02e36a1450`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/roadtools.md`, `telemetry/MASTER.md` (new AADGraphActivityLogs row), native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

ROPC unknown-client attempts belong to other tools. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Device code to the broker client.
- Required telemetry: Sign-in logs with authenticationProtocol and appId.
- Validation status: `unvalidated_proposal`

```yaral
rule roadtools_device_code_broker {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "RT-P04"
    source_comparison = "unvalidated_proposal"
  events:
    $e.additional.fields["authenticationProtocol"] = "deviceCode"
    $e.additional.fields["appId"] = "29d9ed98-a469-4536-ade2-f981bc1d605e"
  condition:
    $e
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/roadtools/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule roadtools_broker_client_device_code_signin {
  meta:
    author = "Detection Research Agent"
    description = "Detects successful device-code sign-ins to the Microsoft Authentication Broker client (29d9ed98-a469-4536-ade2-f981bc1d605e), the client ROADtools uses for device registration and PRT acquisition."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Device-code authentication to the broker client is not part of normal user flows; it lets a phished code yield device-registration and PRT capability."
    procedure_ids = "RT-P01,RT-P03,RT-P04"
    log_source_prerequisites = "Entra ID sign-in logs with authenticationProtocol and appId in additional.fields, UPN in principal.user.userid."
    false_positives = "Rare administrative device-enrollment scenarios using device code with the broker."
    references = "reports/roadtools/source-analysis.md#procedure-analysis; public-rules/comparisons/roadtools/roadtools_device_code_or_ropc_signin.md; reviews/roadtools/detection-review.md#rt-dr-10"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized sign-ins with authenticationProtocol deviceCode and the broker appId."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/roadtools/detection-review.md"
  events:
    $e.metadata.product_event_type = /^(SigninLogs|AADNonInteractiveUserSignInLogs)$/
    re.regex($e.additional.fields["authenticationProtocol"], `(?i)^deviceCode$`)
    $e.additional.fields["appId"] = "29d9ed98-a469-4536-ade2-f981bc1d605e"
    $e.additional.fields["resultType"] = "0"
    $e.principal.user.userid = $user
  match:
    $user over 1h
  outcome:
    $ips = array_distinct($e.principal.ip)
    $resources = array_distinct($e.additional.fields["resourceId"])
  condition:
    $e
}
```
