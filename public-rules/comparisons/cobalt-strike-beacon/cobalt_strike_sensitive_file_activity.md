# Public-rule comparison: cobalt_strike_sensitive_file_activity

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_file_activity.yaral`
- Internal SHA-256: `f4fc5aecd904a818e6d0107e9da6b165c46b394cc741876c1531a44e4cbefc28`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-024,CSB-025`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules_building_block/collection_posh_compression.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules_building_block/collection_posh_compression.toml) - SHA-256 `425d1333010d080e7846291b6546195b89b0bafeb2536d46336866d6feb2de6e`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| sensitive file discovery/collection and ingress followed by egress | sensitive file operation to same-process network correlation | collection rules add archive creation and named sensitive locations | sensitive reads aggregated into a staging artifact - strong | ordered downstream security effect | complementary | Procedure `CSB-024,CSB-025` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: multi-process collection where one process stages and another transmits.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

backup, indexing, and synchronization tools cause legitimate collection-to-egress sequences. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| sensitive reads aggregated into a staging artifact | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but multi-process collection where one process stages and another transmits. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Event type `FILE_WRITE` widened to inventory `FILE_CREATION`/`FILE_MODIFICATION` (legacy alias kept) (DR-13).
  - Enforced first-event-before-second ordering (DR-15).
  - Distinct-file count moved to `outcome`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_file_activity_compensating_signal.yaral`, SHA-256 `9f1e9c1545f0d539b625d3ebd0d789c272bcf09c0f8d02f4e7c87ad5c872d6ed`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-024,CSB-025`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: multi-process collection where one process stages and another transmits.
- Required telemetry: normalized `FILE_READ` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_sensitive_file_activity_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-024,CSB-025"
  events:
    $read.metadata.event_type = "FILE_READ"
        $read.principal.hostname = $host
        $read.principal.user.userid = $user
        $read.target.file.full_path = $source_file
        $read.additional.fields["data_classification"].value.string_value = "SENSITIVE"
        $archive.metadata.event_type = "FILE_WRITE"
        $archive.principal.hostname = $host
        $archive.principal.user.userid = $user
        re.regex($archive.target.file.full_path, `(?i)\.(zip|7z|rar)$`)
  match:
    $host, $user over 30m
  condition:
    $read and $archive and #source_file >= 5
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `9f1e9c1545f0d539b625d3ebd0d789c272bcf09c0f8d02f4e7c87ad5c872d6ed`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules_building_block/collection_posh_compression.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Multi-process sensitive reads then archive creation | covered per user/host | `collection_posh_compression.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | classified reads then archive - moderate | base process-scoped rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_sensitive_file_activity_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Aggregates sensitive-file reads by user and host across processes and correlates them with archive creation by the same user/host, covering multi-process collection where one process stages files and another compresses or transmits them."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Several sensitive-file reads followed by an archive-file write from the same user/host is a strong staging-for-exfiltration signal, though backup, indexing and synchronization tools produce legitimate collection-to-archive sequences."
    procedure_ids = "CSB-024,CSB-025"
    log_source_prerequisites = "Normalize FILE_READ with sensitivity classification, and FILE_CREATION/FILE_MODIFICATION for archive-extension targets, joined on host and user within 30 minutes, at least one read before the archive write."
    false_positives = "Backup, synchronization, DLP, indexing, and document-management tools that read multiple sensitive files and then write compressed archives."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_sensitive_file_activity.md"
    validation_status = "needs_validation"
    validation_method = "Use non-sensitive test documents labelled as sensitive plus fabricated archive-write events representative of backup/sync tooling."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_sensitive_file_activity"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_sensitive_file_activity.md"
    modification_note = "Proposal accepted with a required change: replaced the invented additional.fields['data_classification']='SENSITIVE' with the base rule's existing target.file.sensitivity='HIGH' field so the two rules in this family share one sensitivity taxonomy instead of maintaining two parallel classification schemes."
  events:
    $read.metadata.event_type = "FILE_READ"
    $read.principal.hostname = $host
    $read.principal.user.userid = $user
    $read.target.file.full_path = $source_file
    $read.target.file.sensitivity = "HIGH"
    $archive.metadata.event_type = /^(FILE_CREATION|FILE_MODIFICATION|FILE_WRITE)$/
    $archive.principal.hostname = $host
    $archive.principal.user.userid = $user
    re.regex($archive.target.file.full_path, `(?i)\.(zip|7z|rar)$`)
    $read.metadata.event_timestamp.seconds <= $archive.metadata.event_timestamp.seconds
  match:
    $host, $user over 30m
  outcome:
    $files = count_distinct($source_file)
  condition:
    $read and $archive and $files >= 5
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
