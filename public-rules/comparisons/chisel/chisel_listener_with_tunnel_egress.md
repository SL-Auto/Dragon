# Public-rule comparison: chisel_listener_with_tunnel_egress

## Identity and independence gate

- Internal tool: `chisel`
- Internal canonical rule: `detections/chisel/yaral/chisel_listener_with_tunnel_egress.yaral`
- Internal SHA-256: `f1b10d5e64891c1631a4efa168a7f6eea85af368aae988fe61b8a0bc0e551810`
- Internal review completed before public comparison: `yes`
- Public source/revision/path: `public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml`
- Public SHA-256: `9d206ceb9c9ae2b0931af8f4384a2696703ac4ce620e3d51a2af6f3b119163d2`
- Scope mapping rationale: Both address listener and bidirectional forwarding, but mapping is based on observable behavior and T1572/T1090 effects rather than names or syntax.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process establishes tunnel-side network activity | Behavior-based process network event | server command-line then accepted connection | Process-attributed network behavior â€” moderate | TLS/HTTP metadata | complementary | Pinned source report and public candidate |
| listener and bidirectional forwarding | Explicit causal/correlated branch | Partial or command-line-derived branch | Security effect correlation â€” strong | Process prevalence and approval inventory | ours_stronger | `reports/chisel/source-analysis.md` |
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

- Candidate improvement: Add an inbound accepted-flow branch before same-process egress.
- Independent verification: pinned Chisel source behavior, telemetry requirements, and `reviews/chisel/detection-review.md`.
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found it unsound as written. The added event variable `$i` is declared in `events` and shares the match key `$host, $pid`, but `$i` never binds `$pid` (only `$i.metadata.product_event_type` and `$i.network.direction` are set), and `condition` only tests `$n and #n >= 2` -- `$i` is never referenced in `condition`. Per this rule's own repository convention (see `detections/chisel/yaral/chisel_listener_with_tunnel_egress.yaral`, `condition: $l and $n`), every declared event variable must appear in `condition` for its join to be enforced. As written the proposal is behaviorally identical to a bare `#n >= 2` outbound-connection threshold: the claimed inbound-acceptance correlation is not enforced at all. Even a corrected version that referenced `$i` in `condition` would still only bind on `$host` (not `$pid`), so it would assert host-level coincidence ("some inbound connection happened somewhere on this host") rather than the process-level causal correlation the existing canonical rule already provides via `$l and $n` (listen and egress on the same process). The branch matrix shows the core branches are already `ours_stronger`; this proposal does not close a genuine coverage gap and would weaken specificity if adopted.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It adds no branch beyond the canonical rule's existing `$l`/`$n` same-process correlation and is not internally consistent (unbound join variable, unenforced condition). Rejecting it introduces no new false-negative path because canonical logic is unchanged.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

Our inventory covers the complete pinned multi-platform behavior family. The public candidate covers one adjacent platform or command-line slice and is not treated as comprehensive.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Add an inbound accepted-flow branch before same-process egress.
- Required telemetry: process-attributed endpoint network, listener/UDP/stdio semantics as applicable, stable process entity, direction, destinations, timestamps, prevalence and collection health.
- Validation status: `unvalidated_proposal`

```yaral
rule proposed_chisel_listener_with_tunnel_egress {
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
