# Public-rule comparison: adaptix_secondary_logon_hidden_interpreter

## Identity and independence gate

- Internal tool: `adaptixc2` (revision `e99535c9ef4642190f7ea125c2983d1611f1a3f3`)
- Internal canonical rule: `detections/adaptixc2/yaral/adaptix_secondary_logon_hidden_interpreter.yaral`
- Internal SHA-256: `2ba9e45e7ee479d7644ba058dae38482010ae86f92405e197297080ed6fff390`
- Internal review completed before public comparison: `yes` (`reviews/adaptixc2/detection-review.md`, AX-DR-01 to AX-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_via_token_theft.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_via_token_theft.toml) - SHA-256 `2f1c7ec1e9bb90f6864eb3e460a78dddbe64508e46fe57e4e87ffba002434dae`
- Scope mapping rationale: Both detect processes created with a stolen token through CreateProcessWithToken (T1134.002). The public rule requires a SYSTEM token and an Elastic Defend effective-parent field; ours uses the Secondary Logon parent.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Interpreter created through seclogon with a token | covered | covered when the token is SYSTEM and the effective parent is a privileged service binary | seclogon parentage - moderate | network-process child rule - moderate | complementary |
| Token theft of a non-SYSTEM user | covered | not covered | seclogon parentage - moderate | none | ours_stronger |
| Effective-parent attribution to the token source | not available in generic telemetry | covered (Elastic Defend field) | effective parent - strong | none | public_stronger |

## Missing detection branches

- Effective-parent attribution requires vendor telemetry.

## Detection edge cases and blind spots

- runas overlap (AX-DR-04).

## Signal-quality assessment

- Public: effective parent - strong but vendor-specific.
- Ours: seclogon parent - moderate.

## Public-rule weaknesses

- SYSTEM-only; vendor field.

## Internal-rule weaknesses

- runas overlap.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/adaptixc2/source-analysis.md`, `telemetry/adaptixc2.md` and `reviews/adaptixc2/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal narrows our rule to SYSTEM tokens. AdaptixC2 executes with whatever token the operator stored (`Commander.cpp` L879-894), so the narrowing would miss non-SYSTEM token theft. The effective-parent field is not available in generic UDM.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: SYSTEM-token narrowing.
- Required telemetry: Process creation with user SID.
- Validation status: `unvalidated_proposal`

```yaral
rule adaptix_seclogon_system_token {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "AX-P05"
    source_comparison = "unvalidated_proposal"
  events:
    $c.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($c.principal.process.command_line, `(?i)seclogon`)
    $c.target.user.windows_sid = "S-1-5-18"
  condition:
    $c
}
```
