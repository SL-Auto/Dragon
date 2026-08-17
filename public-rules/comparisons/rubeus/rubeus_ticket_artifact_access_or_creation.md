# Public-rule comparison: rubeus_ticket_artifact_access_or_creation

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_ticket_artifact_access_or_creation.yaral`
- Internal SHA-256: `1817caeb541fbad8f28d89e93f910e5d1fc68ef28bc97d307eba6c6fbb17759b`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-008,PROC-009,PROC-010,PROC-013`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_posh_kerb_ticket_dump.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_posh_kerb_ticket_dump.toml) - SHA-256 `e16587e2ac4f262ae22672c81f6acb76c6e66cc0af6ab59c0bdc036d64e300a9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Ticket extracted in memory | Not covered unless written | Public PowerShell rule detects retrieval API strings | Retrieve API/script content - strong | EDR authentication-package telemetry | public_stronger | Public covers an in-memory extraction branch. |
| Ticket artifact written or read | Extension/name regex | Not required by public rule | File create/read of ticket artifact - moderate | File content/type and process trust | ours_stronger | Ours covers cross-tool disk artifacts. |
| Ticket parsed/converted without expected extension | Only name-based match | Not covered | File content signature or process-context cluster - moderate | Subsequent ticket submission/use | insufficient_evidence | Both can miss renamed or memory-only conversion. |

## Missing detection branches

- Missing from ours: In-memory handling, content-aware artifact identification, archive/output directory context, signer/process trust, write-read-submit sequence.
- Missing from public rule: Non-PowerShell artifacts and disk conversion paths.
- Missing from both: Memory-only parsing or artifacts stored in telemetry-blind locations.

## Detection edge cases and blind spots

Extensions are mutable and .ccache is legitimate on Unix-like systems. File-read telemetry is uncommon and high volume. â€œasrepâ€ or â€œkerberoastâ€ substrings can occur in benign research files.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Authentication-package retrieval API | strong | public | Direct extraction operation within PowerShell coverage. | Requires tenant-specific validation and collection-health monitoring. |
| Known ticket extension create/read | moderate | ours | Effect artifact, but mutable and legitimate in labs/admin. | Requires tenant-specific validation and collection-health monitoring. |
| Filename substring only | weak | ours | Easy to collide with benign content and not causally specific. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

PowerShell-specific and does not cover resulting artifact handling.

## Internal-rule weaknesses

Relies on mutable names/extensions, groups four procedures, and misses memory-only behavior.

## Decision trail

- Candidate improvement: Keep artifact detection as compensation, lower substring-only confidence, add file-content/type and process-context branches, and link extraction-to-artifact-to-submit when telemetry permits.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-008,PROC-009,PROC-010,PROC-013` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Ticket artifact creation by an unapproved process, avoiding bare substring matches.
- Required telemetry: EDR file creation/read with extension, file type where available, caller signer/trust, and approved Kerberos-tool enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_ticket_artifact_from_unapproved_process {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-008,PROC-009,PROC-010,PROC-013"
  events:
    $e.metadata.event_type = "FILE_CREATION"
    re.regex($e.target.file.full_path, `\.(kirbi|ccache)$`) nocase
    $e.additional.fields["approved_kerberos_tool"].value.bool_value = false
    $e.principal.process.file.full_path != ""
  condition:
    $e
}
```

Removes weak â€œasrep/kerberoastâ€ substring matching and requires attributed creation by an unapproved process. It cannot cover memory-only handling; direct API and subsequent ticket-use rules remain required.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
