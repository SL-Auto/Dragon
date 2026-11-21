# Public-rule comparison: rubeus_ticket_artifact_access_or_creation

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_ticket_artifact_access_or_creation.yaral`
- Internal SHA-256: `1817caeb541fbad8f28d89e93f910e5d1fc68ef28bc97d307eba6c6fbb17759b`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-008,PROC-009,PROC-010,PROC-013`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_posh_kerb_ticket_dump.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_posh_kerb_ticket_dump.toml) - SHA-256 `c7aa4e8158b8ff85b9652e1a5d31baf2a8381ac30b2e840fb1e8fb027f9eedd3`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The 2026-08-16 rewrite adds FILE_READ to the proposal's creation-only branch and drops its process-path requirement.
  - Invalid `re.regex ... nocase` replaced with `(?i)` (REVIEW-010). Name-based artifact matching remains an accepted gap (REVIEW-005).
- Canonical result: `detections/rubeus/yaral/rubeus_ticket_artifact_access_or_creation.yaral`, SHA-256 `5c1923b64ce91f2ce4f93e8e9e9b90a3440ad7ba070f8fd67d1242606d64f46a`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_posh_kerb_ticket_dump.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Ticket file (.kirbi/.ccache) created or read | covered | not covered | artifact extension - weak (mutable) | LSA API rules - strong | ours_stronger |
| Ticket retrieval through PowerShell LSA package access | covered by `rubeus_lsa_encoded_ticket_retrieval` (compiled or scripted) | `credential_access_posh_kerb_ticket_dump.toml`: PowerShell 4104 content | LSA API success - strong | script-block content - moderate | complementary |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_ticket_artifact_access_or_creation.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_ticket_artifact_access_or_creation {
  meta:
    author = "Detection Research Agent"
    description = "Detects an unapproved process accessing or creating a Kerberos ticket-cache artifact file by extension."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Ticket artifacts support offline parsing, mutation, or reuse, but authorized IR and labs overlap."
    procedure_ids = "PROC-008,PROC-009,PROC-010,PROC-013"
    log_source_prerequisites = "Normalize EDR file read/create events with process, user, path, extension, and signer, plus an approved-Kerberos-tool process enrichment."
    false_positives = "Incident response, Kerberos troubleshooting, development, labs, and approved assessments where the approved-tool enrichment is stale or incomplete."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_ticket_artifact_access_or_creation.md; reviews/rubeus/detection-review.md#review-010"
    validation_status = "needs_validation"
    validation_method = "Replay benign ticket-file read/write fixtures and approved IR activity. The prior free-text \"asrep\"/\"kerberoast\" substring branch was removed because it could collide with benign filenames (research notes, downloaded tooling, documentation) without any causal link to actual ticket handling; only the extension-plus-unapproved-process branch remains. This narrows recall for renamed or extensionless artifacts, which stays an accepted gap pending file-content/type telemetry."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    ($e.metadata.event_type = "FILE_CREATION" or $e.metadata.event_type = "FILE_READ")
    re.regex($e.target.file.full_path, `(?i)\.(kirbi|ccache)$`)
    $e.additional.fields["approved_kerberos_tool"].value.bool_value = false
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
