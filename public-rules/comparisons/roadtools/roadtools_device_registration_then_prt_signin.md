# Public-rule comparison: roadtools_device_registration_then_prt_signin

## Identity and independence gate

- Internal tool: `roadtools` (revision `792708365789be4e6f58db65c3f90701159fd0ea`)
- Internal canonical rule: `detections/roadtools/yaral/roadtools_device_registration_then_prt_signin.yaral`
- Internal SHA-256: `e0e18e94827e029023d129a439a203d391c16485f652b58454bff720a602de68`
- Internal review completed before public comparison: `yes` (`reviews/roadtools/detection-review.md`, RT-DR-01 to RT-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_prt_from_unusual_device_ip.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_prt_from_unusual_device_ip.toml) - SHA-256 `e7bbddf2028778bff57b91af60d1adcb1070fc3f8966282fbd396803ce568a51`
- Scope mapping rationale: Both target abuse of Primary Refresh Tokens (T1550.001). The public rule flags PRT sign-ins from a compliant or managed device at a previously unseen IP; ours links a new device registration to subsequent PRT use.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| New device registered, then PRT used | covered | not covered | registration-to-PRT chain - strong | none | ours_stronger |
| Stolen PRT from an existing managed device used from a new IP | not covered | covered (new terms) | device-IP novelty - moderate | legacy PRT-cookie user agent - moderate | public_stronger |

## Missing detection branches

- Stolen PRTs of existing managed devices.

## Detection edge cases and blind spots

- Novelty needs a baseline.

## Signal-quality assessment

- Ours: chain - strong.
- Public: novelty - moderate.

## Public-rule weaknesses

- Depends on a new-terms history.

## Internal-rule weaknesses

- Misses PRT theft from existing devices.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/roadtools/source-analysis.md`, `telemetry/roadtools.md` and `reviews/roadtools/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal is a device-and-IP new-terms rule. YARA-L has no native new-terms baseline, and without one it fires on every PRT sign-in. The PRT-cookie user-agent and scripting user-agent rules compensate for theft from existing devices.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: PRT use from a new IP for a managed device.
- Required telemetry: Sign-in logs with incomingTokenType, deviceId and IP history.
- Validation status: `unvalidated_proposal`

```yaral
rule roadtools_prt_from_new_ip {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "RT-P04"
    source_comparison = "unvalidated_proposal"
  events:
    re.regex($e.additional.fields["incomingTokenType"], `(?i)primaryRefreshToken`)
    $e.additional.fields["deviceId"] = $device
    $e.principal.ip = $ip
  match:
    $device, $ip over 1h
  condition:
    $e
}
```
