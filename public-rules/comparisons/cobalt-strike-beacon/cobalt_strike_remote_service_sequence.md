# Public-rule comparison: cobalt_strike_remote_service_sequence

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_service_sequence.yaral`
- Internal SHA-256: `9082f2835f8ada2d2ce243dad44d1ec0c0a26926ec751f42ad5e0aa843376edf`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-030`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_windows_service_via_unusual_client.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_windows_service_via_unusual_client.toml) - SHA-256 `b0ada81d946f4a8e38cf7e33c004eb3323acad26e960a6ce5852647c9bda2ef9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| admin-share staging followed by service installation on the remote target | 5140/5145 to 4697/7045 correlation by source/account/target | service rules add image path, signer, and unusual-client context | staged file path equals installed service image - strong | ordered downstream security effect | complementary | Procedure `CSB-030` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: service binary path should be joined to the staged share-relative file.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

DC share audit and target service logs use different host/account forms. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| staged file path equals installed service image | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but service binary path should be joined to the staged share-relative file. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Exact path equality replaced by a captured image file-name join, because UNC write paths and 7045 ImagePath forms differ (DR-19).
  - Event type `FILE_WRITE` widened to inventory `FILE_CREATION`/`FILE_MODIFICATION` (legacy alias kept) (DR-13).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_service_sequence_compensating_signal.yaral`, SHA-256 `4d2fd342e2da40eeb332b0c8a7a2b947355e78e3b29a7315bc8fbdac6987846d`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-030`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: service binary path should be joined to the staged share-relative file.
- Required telemetry: normalized `FILE_WRITE` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_remote_service_sequence_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-030"
  events:
    $file.metadata.event_type = "FILE_WRITE"
        $file.principal.hostname = $source
        $file.target.hostname = $target
        $file.target.file.full_path = $path
        $svc.metadata.product_event_type = "7045"
        $svc.principal.hostname = $target
        $svc.target.process.file.full_path = $path
  match:
    $source, $target, $path over 10m
  condition:
    $file and $svc
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `4d2fd342e2da40eeb332b0c8a7a2b947355e78e3b29a7315bc8fbdac6987846d`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/privilege_escalation_windows_service_via_unusual_client.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Admin-share staged binary then service install referencing it | covered via file-name join | `privilege_escalation_windows_service_via_unusual_client.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | staged name equals service image name - strong | base proximity rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_remote_service_sequence_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates a file staged to a remote target with a subsequent System 7045 service install on that target whose service image file name equals the staged file name, tightening the base rule's looser source/account/host proximity join; file-name matching tolerates UNC versus local path forms."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "An installed service image path that exactly matches a just-staged file path is very close to the PsExec-style remote-execution security effect and substantially reduces the deployment-tool overlap of the broader proximity-based base rule."
    procedure_ids = "CSB-030"
    log_source_prerequisites = "Normalize FILE_CREATION/FILE_MODIFICATION written to a remote target host (SMB/admin-share write with source and target host and full path), and System 7045 on that target with the installed service image path, joined on source host, target host and image file name within 10 minutes, write first."
    false_positives = "Software distribution and endpoint-management tools that stage an installer to a share and then register it as a service using the identical path."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_service_sequence.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized software-deployment sequences that stage and install from the identical path to confirm the expected benign hit rate before enabling."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_remote_service_sequence"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_service_sequence.md"
  events:
    $file.metadata.event_type = /^(FILE_CREATION|FILE_MODIFICATION|FILE_WRITE)$/
    $file.principal.hostname = $source
    $file.target.hostname = $target
    $name = re.capture($file.target.file.full_path, `(?i)([^\\/]+\.(?:exe|dll|bat|cmd|ps1))$`)
    $svc.metadata.product_event_type = "7045"
    $svc.principal.hostname = $target
    $name = re.capture($svc.target.process.file.full_path, `(?i)([^\\/"\s]+\.(?:exe|dll|bat|cmd|ps1))`)
    $file.metadata.event_timestamp.seconds <= $svc.metadata.event_timestamp.seconds
  match:
    $source, $target, $name over 10m
  outcome:
    $staged_paths = array_distinct($file.target.file.full_path)
    $service_paths = array_distinct($svc.target.process.file.full_path)
  condition:
    $file and $svc
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
