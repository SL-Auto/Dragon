# Public-rule comparison: cobalt_strike_alternate_identity_process

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_alternate_identity_process.yaral`
- Internal SHA-256: `6f8ab791f0538b46d0f34f125cd8d09211f06d6801c45f1e99bbb07eb0017305`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-012`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_create_process_with_token_unpriv.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_create_process_with_token_unpriv.toml) - SHA-256 `3c5cbda8b671438ba5af2933a41fee9fc46ad35f4bc10dbb58043b335b2584d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| alternate credentials produce a new process and subsequent resource access | 4648 followed by process launch under the resulting identity | rare token/process creation and suspicious logon rules cover process context but generally not the ordered explicit-credential sequence | 4648-to-process correlation - strong | ordered downstream security effect | complementary | Procedure `CSB-012` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: resource-side authentication confirming that the alternate identity was actually used.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

identity normalization can split domain-qualified and SID forms; delayed network use may exceed the process window. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4648-to-process correlation | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but resource-side authentication confirming that the alternate identity was actually used. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal matches every successful AUTHENTICATION by any user (`#target >= 1`), with no link to the 4648 alternate identity, so it would alert on all authentication (DR-24).
  - Resource-side confirmation would need a cross-host join (4648 TargetServerName to a 4624 on that server with the source workstation), and WorkstationName is not reliably populated for Kerberos network logons.
  - Compensating signal: `cobalt_strike_unusual_authentication_material_use`. Re-review also recorded the new-credentials token limitation as an accepted gap.
- Canonical result: no canonical logic changed; the proposed code is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The public candidate does not cover all branches in `CSB-012`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: resource-side authentication confirming that the alternate identity was actually used.
- Required telemetry: normalized `AUTHENTICATION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_alternate_identity_process_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-012"
  events:
    $use.metadata.event_type = "AUTHENTICATION"
        $use.security_result.action = "ALLOW"
        $use.principal.user.userid = $user
        $use.principal.hostname = $host
        $use.target.hostname = $target
  match:
    $user, $host over 30m
  condition:
    $use and #target >= 1
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/privilege_escalation_create_process_with_token_unpriv.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Explicit-credential use (4648) followed by a process running as that account | covered | `privilege_escalation_create_process_with_token_unpriv.toml`: process created with another logon session's token | 4648 + same-account process - moderate | token-impersonation process creation - strong | complementary |
| Process created with a stolen or duplicated token | not covered by this rule | covered | token-session mismatch - strong | none | public_stronger |
| Resource-side use of the alternate identity | not covered (no reliable cross-host key) | not covered | none | resource 4624 analytics - weak | insufficient_evidence |

- Re-comparison outcome: canonical logic is unchanged; the token-impersonation branch is a recorded public_stronger gap.
