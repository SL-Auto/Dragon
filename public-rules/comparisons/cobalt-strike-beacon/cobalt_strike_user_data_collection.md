# Public-rule comparison: cobalt_strike_user_data_collection

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_user_data_collection.yaral`
- Internal SHA-256: `0db696c12dab3a143bceee934714761c005927813579e66b0856d84a195ae36a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-027`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/collection_posh_clipboard_capture.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/collection_posh_clipboard_capture.toml) - SHA-256 `d4ecdde65ee34eb3b44b3c83b77b1278d81a396978568451e215cc068dd90251`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| screen, clipboard, input, or browser-secret collection | vendor effect telemetry by uncommon process | public rules cover screenshot utilities and browser credential access through process/file artifacts | collection effect followed by same-process staging/network - strong | ordered downstream security effect | complementary | Procedure `CSB-027` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: repeated collection followed by staging or egress, which distinguishes one benign access from collection.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

assistive technology, conferencing, password managers, and support tools overlap. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| collection effect followed by same-process staging/network | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but repeated collection followed by staging or egress, which distinguishes one benign access from collection. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Joins on `product_specific_process_id` with host on every event, replacing the non-UDM `entity_id` (DR-20).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_user_data_collection_compensating_signal.yaral`, SHA-256 `78676c2198e4944fbd3315aee5d8655dc08843a2b569613ede13577f0fcfca74`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-027`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: repeated collection followed by staging or egress, which distinguishes one benign access from collection.
- Required telemetry: normalized `SCREEN_CAPTURE` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_user_data_collection_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-027"
  events:
    ($collect.metadata.event_type = "SCREEN_CAPTURE" or $collect.metadata.event_type = "CLIPBOARD_READ" or $collect.metadata.event_type = "INPUT_CAPTURE" or $collect.metadata.event_type = "BROWSER_SECRET_READ")
        $collect.principal.hostname = $host
        $collect.principal.process.pid = $pid
        $effect.metadata.event_type = "NETWORK_CONNECTION"
        $effect.principal.process.pid = $pid
        $effect.network.direction = "OUTBOUND"
  match:
    $host, $pid over 15m
  condition:
    $collect and $effect
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `78676c2198e4944fbd3315aee5d8655dc08843a2b569613ede13577f0fcfca74`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/collection_posh_clipboard_capture.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Screen/clipboard/input/browser collection then egress by the same process | covered, ordered | `collection_posh_clipboard_capture.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | collection-then-egress - moderate | base standalone effect - weak | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_user_data_collection_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates a user-data collection effect (screen, clipboard, input, or browser-secret) with an outbound network connection from the same process shortly afterward, distinguishing collection-then-egress from a single benign access that the base standalone-effect rule cannot separate."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Collection followed by egress from the same process is a stronger exfiltration-oriented signal than collection alone, though assistive technology, conferencing, and password-manager software can still match."
    procedure_ids = "CSB-027"
    log_source_prerequisites = "Normalize vendor SCREEN_CAPTURE/CLIPBOARD_READ/INPUT_CAPTURE/BROWSER_SECRET_READ and outbound NETWORK_CONNECTION with a stable vendor process identifier (product_specific_process_id), joined on host and process within 15 minutes, collection first."
    false_positives = "Assistive technology, conferencing, remote support, password managers, browsers, and approved monitoring software that both collect and transmit data as part of normal operation."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_user_data_collection.md"
    validation_status = "needs_validation"
    validation_method = "Use product-provided benign test telemetry for collection-plus-egress sequences without collecting real user data."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_user_data_collection"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_user_data_collection.md"
    modification_note = "Proposal accepted with a required change: replaced the PID-based join with the stable process entity_id field, consistent with the sensitive_file_activity rule in this same procedure family and detection-review finding DR-02 on PID-reuse risk."
  events:
    $collect.metadata.event_type = /^(SCREEN_CAPTURE|CLIPBOARD_READ|INPUT_CAPTURE|BROWSER_SECRET_READ)$/
    $collect.principal.hostname = $host
    $collect.principal.process.product_specific_process_id = $process
    $effect.metadata.event_type = "NETWORK_CONNECTION"
    $effect.principal.hostname = $host
    $effect.principal.process.product_specific_process_id = $process
    $effect.network.direction = "OUTBOUND"
    $collect.metadata.event_timestamp.seconds <= $effect.metadata.event_timestamp.seconds
  match:
    $host, $process over 15m
  outcome:
    $collection_types = array_distinct($collect.metadata.event_type)
  condition:
    $collect and $effect
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
