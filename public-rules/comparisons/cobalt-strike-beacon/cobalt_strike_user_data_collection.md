# Public-rule comparison: cobalt_strike_user_data_collection

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_user_data_collection.yaral`
- Internal SHA-256: `0db696c12dab3a143bceee934714761c005927813579e66b0856d84a195ae36a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-027`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/collection_posh_clipboard_capture.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/collection_posh_clipboard_capture.toml) - SHA-256 `76133bc1359dba0b7e893e9184de788a08691d078a12888ed5ddf312bfdac393`

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

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

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
