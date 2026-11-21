# Public-rule comparison: rubeus_lsa_ticket_cache_operations

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_lsa_ticket_cache_operations.yaral`
- Internal SHA-256: `06fc5d65d74bc376828146cda5c2abfaaa7981c16834e5f1248093ff375f9824`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-006`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_posh_kerb_ticket_dump.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_posh_kerb_ticket_dump.toml) - SHA-256 `c7aa4e8158b8ff85b9652e1a5d31baf2a8381ac30b2e840fb1e8fb027f9eedd3`

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

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/rubeus/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Replaced the invalid `re.regex(...) nocase` with inline `(?i)` and anchored the message-type pattern (REVIEW-006).
  - Aggregated per host and caller process with target-LUID outcomes, so many-session extraction is distinguishable from self-retrieval (REVIEW-007).
- Canonical result: `detections/rubeus/yaral/rubeus_lsa_encoded_ticket_retrieval.yaral`, SHA-256 `4ee967578b7bdd513ad75b4f56be10c8d8c9c8fa8f700140caee0e75b8a25baf`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
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

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `4ee967578b7bdd513ad75b4f56be10c8d8c9c8fa8f700140caee0e75b8a25baf`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_posh_kerb_ticket_dump.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Encoded TGT/TGS retrieval through the LSA Kerberos package | covered per caller process, with LUID breadth | `credential_access_posh_kerb_ticket_dump.toml`: PowerShell script content naming the API/message families | successful KerbRetrieveEncodedTicket API call - strong | PowerShell 4104 content - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/rubeus/detection-review.md`. |
| Retrieval implemented outside PowerShell (compiled tool) | covered | not covered (script-content dependent) | API telemetry - strong | none | ours_stronger | Revised canonical rule, re-pinned candidate, `reviews/rubeus/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule rubeus_lsa_encoded_ticket_retrieval {
  meta:
    author = "Detection Research Agent"
    description = "Detects a successful Kerberos encoded-ticket retrieval call through LsaCallAuthenticationPackage, separated from lower-confidence cache enumeration/query activity."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A successful retrieve-encoded-ticket call is the closest observable step to extracting reusable ticket material from the LSA cache; it is a stronger causal signal than a bare query and is kept as its own high-confidence rule rather than combined with query activity."
    procedure_ids = "PROC-006"
    log_source_prerequisites = "EDR must expose LsaCallAuthenticationPackage API calls with Kerberos message type and a success/failure result; process, user, host, and target LUID are required for triage."
    false_positives = "Klist, SSO components, credential-isolation and IR tooling that legitimately retrieve encoded tickets."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_cache_operations.md"
    validation_status = "needs_validation"
    validation_method = "Use benign API-call fixtures from approved ticket tooling (klist, SSO retrieval) to confirm expected volume before enabling at high severity; never execute Rubeus."
    review_status = "reviewed"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "EDR_API_CALL"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $process
    $e.additional.fields["api_name"].value.string_value = "LsaCallAuthenticationPackage"
    re.regex($e.additional.fields["kerberos_message_type"].value.string_value, `(?i)^Kerb(RetrieveEncodedTicket|RetrieveTicket)(Message)?$`)
    $e.security_result.action = "ALLOW"
  match:
    $host, $process over 10m
  outcome:
    $target_luids = array_distinct($e.additional.fields["target_luid"].value.string_value)
    $luid_count = count_distinct($e.additional.fields["target_luid"].value.string_value)
    $caller_paths = array_distinct($e.principal.process.file.full_path)
    $accounts = array_distinct($e.principal.user.userid)
  condition:
    $e
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/rubeus/detection-review.md`, each with a named compensating rule.
