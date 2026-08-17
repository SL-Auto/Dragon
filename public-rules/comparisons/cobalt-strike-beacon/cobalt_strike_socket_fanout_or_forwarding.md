# Public-rule comparison: cobalt_strike_socket_fanout_or_forwarding

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_fanout_or_forwarding.yaral`
- Internal SHA-256: `460c62b248514121434ee905ccd18767f08240fc77c0ef651f5b2ade21efb844`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-009`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml) - SHA-256 `9d206ceb9c9ae2b0931af8f4384a2696703ac4ce620e3d51a2af6f3b119163d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| SOCKS, forwarding, and pivot traffic through a single process | many distinct destinations from uncommon process | proxy/tunnel rules add simultaneous inbound/outbound, byte ratios, and protocol context | same process accepts inbound and creates outbound fan-out - strong | ordered downstream security effect | complementary | Procedure `CSB-009` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: relay topology: inbound connection followed by multiple outbound connections from same process.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

browsers and agents create high destination fan-out without forwarding. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process accepts inbound and creates outbound fan-out | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but relay topology: inbound connection followed by multiple outbound connections from same process. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-009`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: relay topology: inbound connection followed by multiple outbound connections from same process.
- Required telemetry: normalized `NETWORK_CONNECTION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_socket_fanout_or_forwarding_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-009"
  events:
    $in.metadata.event_type = "NETWORK_CONNECTION"
        $in.principal.hostname = $host
        $in.network.direction = "INBOUND"
        $in.target.process.pid = $pid
        $out.metadata.event_type = "NETWORK_CONNECTION"
        $out.network.direction = "OUTBOUND"
        $out.principal.process.pid = $pid
        $out.target.ip = $destination
  match:
    $host, $pid over 15m
  condition:
    $in and $out and #destination >= 5
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
