# Public-rule comparison: rubeus_lsa_ticket_cache_operations

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_lsa_ticket_cache_operations.yaral`
- Internal SHA-256: `06fc5d65d74bc376828146cda5c2abfaaa7981c16834e5f1248093ff375f9824`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-006`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_posh_kerb_ticket_dump.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_posh_kerb_ticket_dump.toml) - SHA-256 `e16587e2ac4f262ae22672c81f6acb76c6e66cc0af6ab59c0bdc036d64e300a9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Ticket cache enumerated | EDR LsaCallAuthenticationPackage plus query message | PowerShell script content names the same API/message families | Kerberos authentication-package message - strong | PowerShell 4104 content | complementary | Both cover the causal API; ours is process-language independent, public covers script telemetry. |
| Encoded ticket retrieved | EDR retrieve message | PowerShell rule includes retrieve/decrypt message constants | RetrieveEncodedTicket API - strong | File creation or later ticket use | equivalent | Both directly represent retrieval when their respective telemetry exists. |
| Monitoring/harvesting over time | Single API event only | Single script-content event only | Repeated API calls across LUIDs - strong | Subsequent ticket artifact creation | different_scope | Neither rule models periodic harvesting or breadth across sessions. |

## Missing detection branches

- Missing from ours: Repeated monitoring, number of LUIDs/tickets, caller signer/path, target-session sensitivity, direct memory access.
- Missing from public rule: Non-PowerShell implementations and API activity without script logging.
- Missing from both: Offline cache parsing and sensors that do not expose authentication-package calls.

## Detection edge cases and blind spots

Klist, SSO, EDR and IR tools legitimately call these APIs. One API call does not distinguish query from bulk extraction impact without message and result detail.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| RetrieveEncodedTicket message | strong | both | Direct causal operation for ticket retrieval. | Requires tenant-specific validation and collection-health monitoring. |
| QueryTicketCache message | moderate | both | Can be benign enumeration. | Requires tenant-specific validation and collection-health monitoring. |
| PowerShell literal strings | moderate | public | Specific but language/telemetry constrained. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

PowerShell-only visibility leaves compiled/native paths uncovered and script content may be absent.

## Internal-rule weaknesses

Treats one query like bulk extraction and does not use caller trust, result, ticket count, target LUID or repetition.

## Decision trail

- Candidate improvement: Split query from retrieval severity; add caller trust and cross-LUID/repetition branches. Use PowerShell content only as a complementary implementation-specific signal.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-006` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: High-risk ticket retrieval separated from lower-confidence cache enumeration.
- Required telemetry: EDR authentication-package API telemetry with caller process, Kerberos message type, target LUID, result and ticket count when available.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_lsa_encoded_ticket_retrieval {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-006"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    re.regex($e.additional.fields["kerberos_message_type"].value.string_value,
      `Kerb(RetrieveEncodedTicket|RetrieveTicket)`) nocase
    $e.security_result.action = "ALLOW"
  condition:
    $e
}
```

A separate retrieval rule preserves a strong causal signal without assigning the same severity to ordinary cache queries. A second lower-severity query/triage rule should add cross-LUID breadth and caller-trust context.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
