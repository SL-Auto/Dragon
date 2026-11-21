# Public-rule comparison: cobalt_strike_service_or_integrity_transition

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_service_or_integrity_transition.yaral`
- Internal SHA-256: `67f4e031c20437fc9062da8199abd59d13aa71fa2e0398737631d992c872c48f`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-020`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_windows_service_via_unusual_client.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_windows_service_via_unusual_client.toml) - SHA-256 `b0ada81d946f4a8e38cf7e33c004eb3323acad26e960a6ce5852647c9bda2ef9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| service creation or medium-to-high/SYSTEM integrity transition | service/install or integrity transition with execution context | public rules add unusual client, service image path, and token-creation details | untrusted process causes child at SYSTEM integrity - strong | ordered downstream security effect | complementary | Procedure `CSB-020` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: causal parent/token relationship for integrity transition rather than any elevation.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

installers legitimately create services and UAC produces routine integrity changes. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted process causes child at SYSTEM integrity | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but causal parent/token relationship for integrity transition rather than any elevation. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Approval enrichment now fails open with `!= true`, so missing enrichment cannot silently suppress (DR-16).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_service_or_integrity_transition_compensating_signal.yaral`, SHA-256 `ac432f5971b73b3b8629fb8f80027a15a6a8019dcb5cbd5b91a83eecc79d465b`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-020`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: causal parent/token relationship for integrity transition rather than any elevation.
- Required telemetry: normalized `PROCESS_LAUNCH` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_service_or_integrity_transition_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-020"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
        $e.target.process.integrity_level = "SYSTEM"
        $e.principal.process.file.sha256 = $parent_hash
        $e.additional.fields["parent_prevalence"].value.string_value = "RARE"
        $e.additional.fields["parent_signed"].value.bool_value = false
        $e.additional.fields["approved_elevation_broker"].value.bool_value = false
  match:
    $parent_hash over 10m
  condition:
    $e
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `ac432f5971b73b3b8629fb8f80027a15a6a8019dcb5cbd5b91a83eecc79d465b`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/privilege_escalation_windows_service_via_unusual_client.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SYSTEM-integrity child of unsigned or rare parent | covered | `privilege_escalation_windows_service_via_unusual_client.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | unapproved parent to SYSTEM child - moderate | base 4697/7045 rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_service_or_integrity_transition_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Detects a process launch reaching SYSTEM integrity whose parent process is unsigned or rare and is not an approved elevation broker, providing the causal parent/child relationship that the base rule's standalone 4697/7045/integrity-transition signal does not require."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "An unsigned or rare parent causing a child process at SYSTEM integrity is a specific, dangerous elevation pattern, though installers and approved elevation brokers can legitimately do the same absent the enrichment gate."
    procedure_ids = "CSB-020"
    log_source_prerequisites = "Normalize PROCESS_LAUNCH with target integrity level, parent process signer and prevalence, and an approved-elevation-broker enrichment."
    false_positives = "Installers, driver-installation flows, and approved elevation-broker components not reflected in the enrichment allowlist."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_service_or_integrity_transition.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized UAC/elevation-broker and installer fixtures to confirm the allowlist enrichment suppresses expected benign elevation paths."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_service_or_integrity_transition"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_service_or_integrity_transition.md"
    modification_note = "Proposal accepted with required changes: replaced the invented additional.fields['parent_prevalence']/['parent_signed'] with the native principal.process.file.prevalence/is_signed fields already used elsewhere in this rule family, and removed an unused parent_hash match window — the proposal declared a match clause with no aggregation function referencing it in the condition, which is dead configuration."
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.integrity_level = "SYSTEM"
    ($e.principal.process.file.is_signed = false or $e.principal.process.file.prevalence = "RARE")
    $e.additional.fields["approved_elevation_broker"].value.bool_value != true
  condition:
    $e
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
