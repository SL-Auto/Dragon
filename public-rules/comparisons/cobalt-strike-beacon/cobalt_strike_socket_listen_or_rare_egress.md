# Public-rule comparison: cobalt_strike_socket_listen_or_rare_egress

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_listen_or_rare_egress.yaral`
- Internal SHA-256: `6b28f7860160c99d956c9dd303ab671d26940329b71f3ba18b33a8b391f843c8`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-008`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/execution_reverse_shell_via_named_pipe.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/execution_reverse_shell_via_named_pipe.toml) - SHA-256 `e85eed57d8a6943dffb712179bd7488070ff871d7cdb5308754e0489d2928c9f`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| bind listener or user-defined/External C2 egress | socket listen or rare unsigned process egress | listener and reverse-shell rules add inbound follow-on and shell ancestry | rare listener receives remote connection - strong | ordered downstream security effect | complementary | Procedure `CSB-008` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: listener followed by accepted inbound connection and child/process activity.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

development tools and local services legitimately listen from rare binaries. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| rare listener receives remote connection | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but listener followed by accepted inbound connection and child/process activity. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Joins on `product_specific_process_id` with host on every event, replacing the non-UDM `entity_id` (DR-20).
  - Enforced first-event-before-second ordering (DR-15).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_listen_or_rare_egress_compensating_signal.yaral`, SHA-256 `8988223919bc15421679b450577a8223dc61859240972c1d20b9cfdbe05b2680`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-008`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: listener followed by accepted inbound connection and child/process activity.
- Required telemetry: normalized `SOCKET_LISTEN` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_socket_listen_or_rare_egress_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-008"
  events:
    $listen.metadata.event_type = "SOCKET_LISTEN"
        $listen.principal.hostname = $host
        $listen.principal.process.pid = $pid
        $listen.target.port = $port
        $listen.additional.fields["process_prevalence"].value.string_value = "RARE"
        $accept.metadata.event_type = "NETWORK_CONNECTION"
        $accept.network.direction = "INBOUND"
        $accept.target.process.pid = $pid
        $accept.target.port = $port
  match:
    $host, $pid, $port over 30m
  condition:
    $listen and $accept
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `8988223919bc15421679b450577a8223dc61859240972c1d20b9cfdbe05b2680`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots with no content change in the referenced files.
- The pinned candidate lives under Elastic `_deprecated/` and is a weak comparator for this branch; a stronger public counterpart should be sought when this comparison is next refreshed.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Rare process listens then accepts on the same port | covered, ordered | `execution_reverse_shell_via_named_pipe.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | listen plus accepted inbound - moderate | base listen rule - weak | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_socket_listen_or_rare_egress_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates a rare-process socket listen with an accepted inbound connection on the same port and process, closing the gap between merely listening and actually receiving a connection that the base standalone-listen rule leaves open."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A rare/unsigned process that opens a listener and then receives an inbound connection is a much stronger bind-C2 signal than a listener alone, though development tools and local services can still match."
    procedure_ids = "CSB-008"
    log_source_prerequisites = "Normalize SOCKET_LISTEN and inbound NETWORK_CONNECTION with a stable vendor process identifier (product_specific_process_id), process signer/prevalence, and port, joined on host, process and port within 30 minutes, listen first."
    false_positives = "Development tools and local services that legitimately listen from rare binaries and receive local or authorized connections."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_listen_or_rare_egress.md"
    validation_status = "needs_validation"
    validation_method = "Use benign listener-plus-client fixtures representative of development and local-service tooling; do not start Beacon listeners."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_socket_listen_or_rare_egress"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_socket_listen_or_rare_egress.md"
    modification_note = "Proposal accepted with a required change: replaced the invented additional.fields['process_prevalence'] with the native principal.process.file.is_signed/prevalence fields already used by the base rule, and used the stable process entity_id rather than PID for the join."
  events:
    $listen.metadata.event_type = "SOCKET_LISTEN"
    $listen.principal.hostname = $host
    $listen.principal.process.product_specific_process_id = $proc
    $listen.target.port = $port
    ($listen.principal.process.file.is_signed = false or $listen.principal.process.file.prevalence = "RARE")
    $accept.metadata.event_type = "NETWORK_CONNECTION"
    $accept.principal.hostname = $host
    $accept.network.direction = "INBOUND"
    $accept.target.process.product_specific_process_id = $proc
    $accept.target.port = $port
    $listen.metadata.event_timestamp.seconds <= $accept.metadata.event_timestamp.seconds
  match:
    $host, $proc, $port over 30m
  condition:
    $listen and $accept
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
