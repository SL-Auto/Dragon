# Sliver adversarial detection-logic review

## Review scope

All one-rule-per-file detections under `detections/sliver/yaral/`, reconciled to all 26 procedures in the pinned report and coverage ledger. Review date: 2026-08-15. Revised rules were re-read branch by branch after changes.

## Overall assessment

- Decision: `acceptable_experimental`; no unresolved blocker.
- Telemetry confidence: low-to-medium until tenant UDM compilation and representative benign/adversary-emulation fixtures are supplied.
- The rules detect behavior, not Sliver attribution. Three procedures remain explicitly `not_observable`; server audit rules require an authorized server datasource.

## Findings

### REVIEW-001 — Mutable names and infrastructure cannot be a completeness strategy

- Severity: `high`
- Affected rules/procedures: C2, lifecycle and all implant procedures.
- Assumption challenged: static process/domain/certificate indicators identify configured implants.
- Gap or failure mode: builds and C2 profiles are configurable, so literals create systematic false negatives.
- Resolution: `fixed`
- Rule change or compensating signal: rules use process-linked behavior, recurrence, listener/egress, and action correlations; no Sliver filename or infrastructure gate remains.

### REVIEW-002 — PID reuse and normalization can create false joins

- Severity: `high`
- Affected rules/procedures: every multi-event endpoint rule.
- Assumption challenged: product-specific PID is stable and populated across event types.
- Gap or failure mode: reuse, sensor restart, parser differences, or missing PID can join unrelated events or suppress matches.
- Resolution: `compensating_signal`
- Rule change or compensating signal: joins also require host and short windows; prerequisites require tenant verification. Stable process entity/GUID should replace PID where the deployed parser exposes it.

### REVIEW-003 — Generic recurrence is noisy and misses low-volume/changing destinations

- Severity: `medium`
- Affected rules/procedures: PROC-002–004.
- Assumption challenged: five connections in 30 minutes is selective and complete.
- Gap or failure mode: agents match, while slow or destination-changing channels can miss.
- Resolution: `compensating_signal`
- Rule change or compensating signal: destination was deliberately removed from the match key to cover churn; lifecycle, DNS/UDP, listener, execution, collection and cleanup correlations provide independent signals. Tenant baselining remains required.

### REVIEW-004 — Discovery and in-memory runtimes lack standard audit events

- Severity: `high`
- Affected rules/procedures: PROC-006, PROC-013, PROC-025.
- Assumption challenged: every source procedure can honestly map to a portable rule.
- Gap or failure mode: native enumeration, in-memory WASM dispatch, and server-side orchestration can have no victim event.
- Resolution: `compensating_signal`
- Rule change or compensating signal: these are `not_observable`, with C2/resulting behavior or authenticated server audit/cross-host fan-out documented. They were not falsely marked detected.

### REVIEW-005 — Vendor semantic events are parser-dependent

- Severity: `high`
- Affected rules/procedures: PROC-011–015, PROC-018, PROC-023–024.
- Assumption challenged: module-load, screen-capture, registry and server-audit meanings map exactly to the proposed UDM fields.
- Gap or failure mode: a tenant may receive different event types/fields or none at all.
- Resolution: `compensating_signal`
- Rule change or compensating signal: each rule explicitly requires tenant-verified mapping, retains `needs_validation`, and correlates with a second durable signal where available. Server rules are isolated rather than mixed with victim telemetry.

### REVIEW-006 — File correlation was over-specific when split by operation

- Severity: `medium`
- Affected rules/procedures: PROC-007–009.
- Assumption challenged: all products distinguish read/create/modify/delete identically.
- Gap or failure mode: operation-specific rules leave parser gaps and timestamp/memfile operations may not generate file events.
- Resolution: `fixed`
- Rule change or compensating signal: a shared alternation covers normalized file operations and correlates to the same network process; report and ledger retain inherent read/memfile limitations.

### REVIEW-007 — Remote administration joins need more than timing

- Severity: `high`
- Affected rules/procedures: PROC-016–020.
- Assumption challenged: events on the same host in a window are causally related.
- Gap or failure mode: busy servers generate accidental joins.
- Resolution: `fixed`
- Rule change or compensating signal: joins require host plus account; prerequisites call for source IP/logon ID enrichment. No broad account exclusion was added because that would create avoidable bypass coverage gaps.

### REVIEW-008 — Event ordering is not guaranteed by collection pipelines

- Severity: `medium`
- Affected rules/procedures: all correlations.
- Assumption challenged: normalized arrival order reflects procedure order.
- Gap or failure mode: buffering and clock skew reorder events.
- Resolution: `fixed`
- Rule change or compensating signal: rules use bounded co-occurrence rather than brittle before/after constraints. Short windows limit unrelated joins.

### REVIEW-009 — Cleanup can occur after PID loss

- Severity: `medium`
- Affected rules/procedures: PROC-002, PROC-026.
- Assumption challenged: deletion is attributed to the same live process that made egress.
- Gap or failure mode: helper processes, delayed deletion, or missing initiator break the join.
- Resolution: `compensating_signal`
- Rule change or compensating signal: current high-confidence same-PID rule remains; service stop/delete and standalone EDR self-delete evidence are recommended compensating signals rather than a loose host-only join.

## Required follow-up

- Compile every rule in the target Chronicle tenant and replace assumed mappings with verified UDM fields.
- Test missing fields, PID reuse, event delay, high-volume servers, software deployment, VPN/proxy, browser automation, EDR and backup baselines.
- Measure recurrence and DNS thresholds per environment; maintain narrow contextual allowlists outside core logic.
- Do not promote any rule beyond experimental until validation evidence is recorded.

## Public-comparison backlog resolution (2026-08-16)

Thirteen `public-rules/comparisons/sliver/*.md` files had been left with the non-terminal `deferred_pending_rule_improvement_run` decision, which AGENTS.md no longer permits. Each comparison's "strong branch" proposal was adversarially re-reviewed against this review's existing findings, `coverage/sliver.yml`, `telemetry/sliver.md`, and the pinned source analysis, and resolved to `accept`, `reject`, or `modify`. Findings below are additive to REVIEW-001–009 above; none of the prior findings were reopened except where a proposal directly regressed a fix already recorded there.

### REVIEW-010 — Reintroducing strict event ordering was a recurring proposal defect

- Severity: `high`
- Affected rules/procedures: nearly every "strong branch" proposal (browser debugging, cleanup, DNS/UDP, identity/service, listener, interpreter, process access, process cluster, remote admin, screen capture).
- Assumption challenged: that a `<=` timestamp ordering predicate between correlated events is safe to add back into canonical logic.
- Gap or failure mode: REVIEW-008 already established that buffering, batching, and clock skew across collection pipelines make strict before/after ordering brittle and prone to false negatives; every proposal reintroduced this exact pattern.
- Resolution: `fixed`
- Rule change or compensating signal: every accepted/modified rule below keeps bounded co-occurrence over a match window instead of an ordering predicate. Ordering was the primary reason two proposals (`sliver_parent_egress_with_spawned_interpreter`, `sliver_screen_capture_process_egress`) were rejected outright rather than modified, because removing the ordering left no other closed gap in those two cases.

### REVIEW-011 — Optional enrichment fields were proposed as hard filters

- Severity: `high`
- Affected rules/procedures: DNS/UDP, listener, process-behavior-cluster, recurrent-egress proposals, all of which hard-required a `destination_prevalence = "rare"` label.
- Assumption challenged: that destination-prevalence/UEBA enrichment is a guaranteed field.
- Gap or failure mode: `telemetry/sliver.md`'s rule-by-rule table lists prevalence only under "Optional enrichment" for every rule, never under required fields; making it a hard `condition` predicate would silently zero out matches in any tenant without that enrichment, including for the flagship recurrence rule.
- Resolution: `fixed`
- Rule change or compensating signal: every accepted/modified rule below drops the hard prevalence requirement and substitutes a telemetry-confirmed alternative (same-destination/port grouping, minute-spread/periodicity counts, or signature-verification status) as the narrowing mechanism instead.

### REVIEW-012 — Full-replacement "split" proposals would have regressed coverage

- Severity: `high`
- Affected rules/procedures: file activity (PROC-007–009), identity/service (PROC-016,017,019), process access (PROC-011,012,015), listener (PROC-005,021), registry (PROC-018), process behavior cluster (PROC-001).
- Assumption challenged: that narrowing a shared rule's predicates to a single high-confidence sub-case is safe to ship as a straight replacement.
- Gap or failure mode: REVIEW-006 already recorded that an earlier by-operation split of the file-activity rule was tried and reversed specifically because it left parser gaps in normal collection coverage; several new proposals repeated the same mistake in a different dimension (path-specific, event-specific, or signal-specific narrowing) and, if adopted as replacements, would have dropped coverage for procedures that do not exhibit the narrower sub-case (e.g. non-credential file staging, non-lsass process access, signed implant builds, dormant pivot listeners with no accepted peer yet).
- Resolution: `compensating_signal`
- Rule change or compensating signal: every such proposal was accepted as an **additional** narrow, high-confidence rule alongside the existing broad rule, never as a replacement. `coverage/sliver.yml` now lists both rules against the affected procedures.

### REVIEW-013 — Two proposals did not address their own stated gap

- Severity: `medium`
- Affected rules/procedures: `sliver_parent_egress_with_spawned_interpreter` (PROC-010), `sliver_screen_capture_process_egress` (PROC-014).
- Assumption challenged: that a "strong branch" proposal necessarily closes the branch it names.
- Gap or failure mode: the interpreter proposal's stated gap was mutable interpreter naming and missing command provenance/token context, but the proposed code still matched on the same mutable `cmd|powershell|...` name list and added no provenance or token field — it only reintroduced ordering (REVIEW-010) over an existing rule that already correlates parent PID to egress without that fragility. The screen-capture proposal's stated gap was that capture telemetry cannot identify the captured desktop, artifact, session, or API provider — an inherent telemetry limitation already carried as `needs_validation` — and the proposed code did not add any field that would resolve it; it only swapped one unverified vendor event-type guess (`SCREEN_CAPTURE|DesktopDuplication|BitBlt`) for another and reintroduced ordering.
- Resolution: `rejected`
- Rule change or compensating signal: both comparisons were resolved `reject` with the reasoning above recorded in their Decision Trail. Canonical logic for both rules is unchanged; both proposed code blocks are preserved in the comparison files.

### REVIEW-014 — Genuine gaps that were accepted, with fixes

- Severity: `medium`
- Affected rules/procedures: browser debugging (PROC-022), recurrent egress (PROC-002,003), remote admin sequence (PROC-020) — rewritten in place; cleanup (PROC-002,026), DNS/UDP (PROC-004), file activity (PROC-007,008), identity/service (PROC-016,017,019), listener (PROC-005,021), process access (PROC-011,012,015), process behavior cluster (PROC-001), registry (PROC-018) — extended with a new compensating rule.
- Assumption challenged: that every proposal in this backlog was reflexive template output with nothing to accept.
- Gap or failure mode: several proposals identified real, evidenced weaknesses already implicit in this review's own findings (no listener/child-identity requirement for browser debugging; a bare five-connections-per-process-image threshold with no destination dimension for recurrent egress per REVIEW-003; host+user joins on the remote-admin sequence that can associate unrelated administration per REVIEW-007; unproven process/file identity between deletion and egress; a four-event-family conflation in the identity/service rule; an unusably broad any-registry-write predicate; a generic process-access predicate that does not distinguish credential-process targeting).
- Resolution: `fixed` (rewrites) / `compensating_signal` (new rules)
- Rule change or compensating signal: see per-rule Decision Trail entries in `public-rules/comparisons/sliver/*.md` for exact code and rationale. All new/changed rules retain `status = "experimental"` and `validation_status = "needs_validation"`.

## Implemented improvements and re-review result

- Expanded from four sampled rules to complete observable-procedure coverage with explicit shared-rule rationale.
- Removed mutable tool names/infrastructure and mandatory prevalence labels from implant behavior logic.
- Added independent transport, listener/relay, file, injection/dump, identity/service, registry, browser, server-control and cleanup signals.
- Strengthened correlations with host plus PID or account and bounded windows; avoided brittle ordering and broad exclusions.
- Kept genuinely unavailable signals as `not_observable` with compensation instead of inventing rules.
- Re-review found no unresolved blocker; residual schema and sensor limitations are accepted experimental gaps pending tenant validation.
