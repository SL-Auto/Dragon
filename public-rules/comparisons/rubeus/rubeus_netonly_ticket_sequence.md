# Public-rule comparison: rubeus_netonly_ticket_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_netonly_ticket_sequence.yaral`
- Internal SHA-256: `f11263a04941a655998465f56374367b5336e64b02adf129bf2a7d26665f6a19`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-007`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_newcreds_logon_rare_process.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_newcreds_logon_rare_process.toml) - SHA-256 `59279f96db8edd7131d9ea95ce159dbe08b1b2a045087e139a5128b6774634c3`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Net-only session created | 4624 Type 9 with host and LUID | Public detects first-seen NewCredentials process | Type 9 logon - weak | Rare process and actor baseline | public_stronger | Public covers unusual session creation even without API telemetry. |
| Ticket submitted into new session | Correlates submit API to same LUID | Not covered | Type 9 plus submit-to-same-LUID - strong | Subsequent Kerberos use by session | ours_stronger | The correlation is tightly aligned to the procedure. |
| Session used for remote access | Not required | Not required | Resource-side Kerberos use tied to LUID - strong | Network destination/service fan-out | different_scope | Both stop before confirming the session effect. |

## Missing detection branches

- Missing from ours: Subsequent use, submit success, creator/child process, cross-host entity mapping and delayed submissions beyond five minutes.
- Missing from public rule: Ticket submission; public rarity state may reset or be poisoned by common admin tools.
- Missing from both: Net-only creation without 4624 collection or ticket submission without target-LUID API telemetry.

## Detection edge cases and blind spots

Runas /netonly and admin tooling are common. LUID formatting and reuse can break or misjoin the sequence. A five-minute window may be too short for staged workflows.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Type 9 plus same-LUID ticket submit | strong | ours | Ordered, entity-bound procedure signal. | Requires tenant-specific validation and collection-health monitoring. |
| First-seen NewCredentials process | moderate | public | Covers precursor but rarity is mutable. | Requires tenant-specific validation and collection-health monitoring. |
| Type 9 alone | weak | both | Common administrative behavior. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Rarity and program-files exclusions can miss established or relocated tooling and do not show ticket injection.

## Internal-rule weaknesses

Depends on uncommon target-LUID API telemetry and does not confirm the submitted ticket was used.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal's third leg requires a host-side Kerberos logon event carrying the net-only session LUID (`subject_luid`), which standard Windows auditing does not produce; requiring it would remove existing coverage.
  - It also dropped the `EDR_API_CALL` event-type constraint on the submission leg, widening that leg to any event with a message-type field.
  - Compensating signals: `rubeus_lsa_ticket_submission` and resource-side `rubeus_ticket_use_without_credible_kdc_issue`.
- Canonical result: no canonical logic changed; the proposed code is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

Public candidates do not cover the full `PROC-007` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Confirmation that the submitted ticket is used from the same net-only session.
- Required telemetry: 4624 Type 9, EDR ticket-submit target LUID, and resource/endpoint Kerberos authentication tied to host and LUID.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_netonly_submit_and_use_sequence {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007"
  events:
    $logon.metadata.product_event_type = "4624"
    $logon.additional.fields["LogonType"].value.string_value = "9"
    $logon.target.hostname = $host
    $logon.additional.fields["TargetLogonId"].value.string_value = $luid
    $submit.additional.fields["kerberos_message_type"].value.string_value = "KerbSubmitTicketMessage"
    $submit.principal.hostname = $host
    $submit.additional.fields["target_luid"].value.string_value = $luid
    $use.metadata.event_type = "USER_LOGIN"
    $use.security_result.auth_details = "KERBEROS"
    $use.principal.hostname = $host
    $use.additional.fields["subject_luid"].value.string_value = $luid
  match:
    $host, $luid over 30m
  condition:
    $logon and $submit and $use
}
```

Adds the missing security-effect branch and extends the window for staged administration. It requires reliable LUID propagation; retain the existing two-event rule as a lower-confidence compensating alert where service-use LUID is unavailable.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/privilege_escalation_newcreds_logon_rare_process.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Logon type 9 followed by ticket submission into that LUID | covered | `privilege_escalation_newcreds_logon_rare_process.toml`: new-terms on the process creating a type-9 logon | 4624 type 9 + KerbSubmitTicket LUID join - strong | rare-process new-terms - moderate | complementary |
| Submitted ticket used from the net-only session | not covered (no standard LUID-attributed use event) | not covered | none | `rubeus_ticket_use_without_credible_kdc_issue` - moderate | insufficient_evidence |

- Re-comparison outcome: canonical logic is unchanged; the conclusions above stand against the re-pinned candidates.
