# Public-rule comparison: chisel_proxy_destination_fanout

## Identity and independence gate

- Internal tool: `chisel`
- Internal canonical rule: `detections/chisel/yaral/chisel_proxy_destination_fanout.yaral`
- Internal SHA-256: `90d6b84ac1a5892ef54fc864fad915163065f870306c2ae14da5d1edf28bfe30`
- Internal review completed before public comparison: `yes`
- Public source/revision/path: `public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/command_and_control_proxy_port_activity_to_the_internet.toml`
- Public SHA-256: `9b790c65a317bbce2e679819e3dcbaf3ea267ba93ba177a2e97d2625f076a373`
- Scope mapping rationale: Both address dynamic SOCKS or proxy destination fanout, but mapping is based on observable behavior and T1572/T1090 effects rather than names or syntax.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process establishes tunnel-side network activity | Behavior-based process network event | internet proxy-port connection | Process-attributed network behavior â€” moderate | TLS/HTTP metadata | complementary | Pinned source report and public candidate |
| dynamic SOCKS or proxy destination fanout | Explicit causal/correlated branch | Partial or command-line-derived branch | Security effect correlation â€” strong | Process prevalence and approval inventory | ours_stronger | `reports/chisel/source-analysis.md` |
| Alternate implementation or renamed binary | Covered when effects are logged | Usually missed by mutable indicators | Effect rather than name â€” strong | Network flow analytics | ours_stronger | Internal adversarial review |
| Distributed, low-rate, or missing endpoint telemetry | Partial | Partial | Collection health â€” weak | Cross-host NDR and proxy logs | insufficient_evidence | Both depend on available telemetry |

## Missing detection branches

- Missing from ours: richer protocol/accepted-flow context and provider-tested process entity mapping.
- Missing from public rule: renamed/reimplemented behavior and non-command-line branches.
- Missing from both: reliable cross-host session linkage when reverse forwarding splits effects.

## Detection edge cases and blind spots

Single long-lived flows can evade recurrence counts; PID reuse can corrupt joins; UDP ownership and stdio semantics are provider-specific; encrypted WebSockets hide destinations; approved proxies, VPNs, developer tunnels and remote support overlap. Distributed reverse mode and partial collection need compensating NDR or proxy telemetry.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Same-process security effect correlation | strong | ours | Close to actual forwarding behavior and independent of branding | Approved tunnel software overlaps |
| Product command-line or filename | weak | public | Easy to collect but mutable and implementation-specific | Packaging and wrappers change it |
| Protocol/accepted-flow context | moderate | proposal | Confirms the listener is used rather than merely open | Provider mapping and encryption vary |

## Public-rule weaknesses

The public candidate is narrower, depends heavily on process arguments, names, ports, or platform-specific fields, and does not comprehensively cover forward, reverse, UDP, SOCKS, stdio, and proxy-chain branches.

## Internal-rule weaknesses

The internal rule is non-attributive, depends on stable process entity mapping, and needs additional accepted-flow or protocol context to reduce benign listener/network overlap.

## Decision trail

- Candidate improvement: Require inbound listener use and distinct outbound destination fanout on one process entity.
- Independent verification: pinned Chisel source behavior, telemetry requirements, and `reviews/chisel/detection-review.md`.
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: Adversarial review of the proposal (2026-08-16) found it unsound as written. The added event variable `$i` is declared in `events` and shares the match key `$host, $pid`, but `$i` never binds `$pid` (only `$i.metadata.product_event_type` and `$i.network.direction` are set), and `condition` only tests `$n and #n >= 2` -- `$i` is never referenced in `condition`. Per this rule's own repository convention (see `detections/chisel/yaral/chisel_listener_with_tunnel_egress.yaral`, `condition: $l and $n`), every declared event variable must appear in `condition` for its join to be enforced. As written the proposal is behaviorally identical to a bare `#n >= 2` outbound-connection threshold: the claimed inbound-listener-use correlation is not enforced at all. Even a corrected version that referenced `$i` in `condition` would still only bind on `$host` (not `$pid`), producing a host-level coincidence signal rather than a process-level causal correlation to the actual proxy/fanout process. The branch matrix shows the core branches are already `ours_stronger`; this proposal does not close a genuine coverage gap.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It adds no branch beyond the canonical rule's existing same-process fanout correlation and is not internally consistent (unbound join variable, unenforced condition). Rejecting it introduces no new false-negative path because canonical logic is unchanged.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

Our inventory covers the complete pinned multi-platform behavior family. The public candidate covers one adjacent platform or command-line slice and is not treated as comprehensive.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Require inbound listener use and distinct outbound destination fanout on one process entity.
- Required telemetry: process-attributed endpoint network, listener/UDP/stdio semantics as applicable, stable process entity, direction, destinations, timestamps, prevalence and collection health.
- Validation status: `unvalidated_proposal`

```yaral
rule proposed_chisel_proxy_destination_fanout {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
    $i.metadata.product_event_type = "NETWORK_CONNECTION"
    $i.network.direction = "INBOUND"
  match:
    $host, $pid over 15m
  condition:
    $n and #n >= 2
}
```

This proposal adds procedure-specific causal context while retaining behavior-first logic. It still needs provider field binding, benign-baseline testing, and reverse-mode cross-host assessment before canonical adoption.

## Snapshot refresh (2026-11-21)

- Candidate re-pinned from elastic-security `7e91c15` to `9d792a8`. The decision trail above is unchanged.
- `rules/_deprecated/command_and_control_proxy_port_activity_to_the_internet.toml` is identical apart from line endings.
