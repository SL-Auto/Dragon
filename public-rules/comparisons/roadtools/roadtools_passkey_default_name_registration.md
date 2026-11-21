# Public-rule comparison: roadtools_passkey_default_name_registration

## Identity and independence gate

- Internal tool: `roadtools` (revision `792708365789be4e6f58db65c3f90701159fd0ea`)
- Internal canonical rule: `detections/roadtools/yaral/roadtools_passkey_default_name_registration.yaral`
- Internal SHA-256: `47f0eda83c3a0ffb5d9100869d99083dec44156037a66452225c2ba2230f0f4a`
- Internal review completed before public comparison: `yes` (`reviews/roadtools/detection-review.md`, RT-DR-01 to RT-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_potential_passkey_downgrade.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_entra_id_potential_passkey_downgrade.toml) - SHA-256 `ab4889c16eaf2a4ca3b10bc3a940e49765231f8328482a4442eb2018de2aff0d`
- Scope mapping rationale: Both concern passkey-related authentication abuse (T1556). The public rule detects a session that falls back from a passkey to a weaker method; ours detects registration of a passkey with the ROADtools default name.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Attacker passkey registration (default name) | covered | not covered | audit key name - strong | device-to-key chain - moderate | ours_stronger |
| Authentication-method downgrade from passkey | not covered | covered | per-session method sequence - moderate | none | different_scope |

## Missing detection branches

- Passkey downgrade is a different procedure (phishing-proxy fallback), not ROADtools persistence.

## Detection edge cases and blind spots

- Custom passkey names.

## Signal-quality assessment

- Ours: default name - strong when present.
- Public: downgrade sequence - moderate.

## Public-rule weaknesses

- Different procedure.

## Internal-rule weaknesses

- Name is operator-changeable.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/roadtools/source-analysis.md`, `telemetry/roadtools.md` and `reviews/roadtools/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal adds downgrade detection, which targets adversary-in-the-middle phishing rather than ROADtools' passkey registration, so it adds no ROADtools branch.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

Downgrade detection belongs to phishing-proxy analyses. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Passkey-to-password downgrade.
- Required telemetry: Sign-in logs with authentication details.
- Validation status: `unvalidated_proposal`

```yaral
rule roadtools_passkey_downgrade {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "RT-P05"
    source_comparison = "unvalidated_proposal"
  events:
    re.regex($e.additional.fields["authenticationDetails"], `(?i)passkey.*false.*password.*true`)
  condition:
    $e
}
```
