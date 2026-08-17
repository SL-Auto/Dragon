# Public-rule comparison: rubeus_lsa_ticket_mutation

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_lsa_ticket_mutation.yaral`
- Internal SHA-256: `e8a2e9830d7dd25bf11b35ae1472ba0f0a1afaebae4029bd371dcb401851a45d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-007`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `a4eb95afd079e1433cd4ec4cb5420d592edcd4f597fd85b3f0104b29555794ab`

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

- Candidate improvement: Separate submit and purge branches, enrich with target LUID/caller trust, and add optional post-submission service-use confirmation.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

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
