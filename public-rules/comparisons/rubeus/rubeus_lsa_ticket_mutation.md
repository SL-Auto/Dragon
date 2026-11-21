# Public-rule comparison: rubeus_lsa_ticket_mutation

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_lsa_ticket_mutation.yaral`
- Internal SHA-256: `e8a2e9830d7dd25bf11b35ae1472ba0f0a1afaebae4029bd371dcb401851a45d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-007`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `6ab27ba3bdb4279de4387de8a76f928fc24dd16eb25a2e8d7658cd9d447c1648`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Ticket submitted to LSA | Direct KerbSubmitTicketMessage API | Public rule observes later Kerberos network/authentication sequence | Ticket-submit API - strong | Resource-side Kerberos use | ours_stronger | Ours is closest to the mutation operation. |
| Ticket cache purged | Direct purge API | No direct public branch | Purge API plus caller - moderate | Abrupt cache-state change or reauthentication | ours_stronger | Public corpus has no equivalent purge operation. |
| Submitted ticket used | Not required | Public network/authentication sequence can observe use | Resource-side Kerberos authentication - strong | 4769 and service access correlation | public_stronger | Public compensation can confirm security effect after submission. |

## Missing detection branches

- Missing from ours: Submission success/result, target LUID sensitivity, subsequent use, caller trust and cross-user mutation.
- Missing from public rule: Direct mutation and purge.
- Missing from both: Mutation when EDR lacks API telemetry and the ticket is never used during retention.

## Detection edge cases and blind spots

Approved SSO and IR tools submit/purge tickets. API telemetry may expose caller LUID but not target LUID consistently. A purge may be routine troubleshooting rather than concealment.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| KerbSubmitTicketMessage | strong | ours | Direct ticket mutation operation. | Requires tenant-specific validation and collection-health monitoring. |
| KerbPurgeTicketCacheMessage | moderate | ours | Direct but commonly administrative. | Requires tenant-specific validation and collection-health monitoring. |
| Subsequent Kerberos service use | strong | public | Confirms effect but is not uniquely malicious. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Post-use behavior cannot establish how the ticket entered the cache and misses unused mutations.

## Internal-rule weaknesses

Combines submit and purge despite different risk and does not require success or follow-on use.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/rubeus/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Anchored the message type and aggregated per host and caller process with target-LUID outcomes; the unused `$luid` placeholder became an outcome (REVIEW-006, REVIEW-007).
- Canonical result: `detections/rubeus/yaral/rubeus_lsa_ticket_submission.yaral`, SHA-256 `4c96e521594655227dcea0c02e64bb944173243fb10e10b169d546d67fcd9330`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

Public candidates do not cover the full `PROC-007` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Successful ticket submission separated from cache purge.
- Required telemetry: EDR LsaCallAuthenticationPackage telemetry with Kerberos message type, result, caller and target LUID.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_lsa_ticket_submission {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-007"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    $e.additional.fields["kerberos_message_type"].value.string_value = "KerbSubmitTicketMessage"
    $e.security_result.action = "ALLOW"
    $e.additional.fields["target_luid"].value.string_value = $luid
  condition:
    $e
}
```

Prevents purge activity from diluting the stronger ticket-submission branch and requires a successful operation. Purge should remain a separate moderate-severity rule with repetition or suspicious caller context.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `4c96e521594655227dcea0c02e64bb944173243fb10e10b169d546d67fcd9330`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/lateral_movement_credential_access_kerberos_correlation.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Ticket submitted to LSA (pass-the-ticket) | covered per caller process | `lateral_movement_credential_access_kerberos_correlation.toml`: later Kerberos network/authentication sequence | KerbSubmitTicket API success - strong | resource-side Kerberos use - moderate | ours_stronger | Revised canonical rule, re-pinned candidate, `reviews/rubeus/detection-review.md`. |
| Submitted ticket later used against a resource | not covered by this rule | covered by the public correlation | resource authentication sequence - moderate | `rubeus_ticket_use_without_credible_kdc_issue` - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/rubeus/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule rubeus_lsa_ticket_submission {
  meta:
    author = "Detection Research Agent"
    description = "Detects a successful Kerberos ticket submission into an LSA logon session through LsaCallAuthenticationPackage, separated from lower-confidence cache-purge activity."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A successful KerbSubmitTicketMessage call is the direct mechanism for pass-the-ticket; it is a stronger and more specific signal than purge activity and is kept as its own high-confidence rule."
    procedure_ids = "PROC-007"
    log_source_prerequisites = "EDR must expose LsaCallAuthenticationPackage API calls with Kerberos message type, a success/failure result, and the target LUID; caller process, user, and host are required for triage."
    false_positives = "SSO and identity middleware, credential-isolation software, and authorized red-team/IR tooling that submits tickets into a logon session."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_mutation.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized submit API fixtures from approved administration and SSO components before enabling at high severity."
    review_status = "reviewed"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $process
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    re.regex($e.additional.fields["kerberos_message_type"].value.string_value, `(?i)^KerbSubmitTicket(Message)?$`)
    $e.security_result.action = "ALLOW"
  match:
    $host, $process over 10m
  outcome:
    $target_luids = array_distinct($e.additional.fields["target_luid"].value.string_value)
    $caller_paths = array_distinct($e.principal.process.file.full_path)
    $accounts = array_distinct($e.principal.user.userid)
  condition:
    $e
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/rubeus/detection-review.md`, each with a named compensating rule.
