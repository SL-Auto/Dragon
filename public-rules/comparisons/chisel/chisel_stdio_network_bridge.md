# Public-rule comparison: chisel_stdio_network_bridge

## Identity and independence gate

- Internal tool: `chisel`
- Internal canonical rule: `detections/chisel/yaral/chisel_stdio_network_bridge.yaral`
- Internal SHA-256: `96c4cea2b69a31c5c94a7c5d61dba6ba2fe270d2f75f1e96ddc073c05fcf97f0`
- Internal review completed before public comparison: `yes`
- Public source/revision/path: `public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/command_and_control_cat_network_activity.toml`
- Public SHA-256: `5e08f4ddecc43d1b71e8ffc93f0432a05ffd6b936eda5bd693bdad08388bf39c`
- Scope mapping rationale: Both address stdio-to-network bridge, but mapping is based on observable behavior and T1572/T1090 effects rather than names or syntax.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process establishes tunnel-side network activity | Behavior-based process network event | named utility network activity | Process-attributed network behavior â€” moderate | TLS/HTTP metadata | complementary | Pinned source report and public candidate |
| stdio-to-network bridge | Explicit causal/correlated branch | Partial or command-line-derived branch | Security effect correlation â€” strong | Process prevalence and approval inventory | ours_stronger | `reports/chisel/source-analysis.md` |
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

- Candidate improvement: Correlate redirected standard handles with a pipe/handle connection and outbound flow.
- Independent verification: pinned Chisel source behavior, telemetry requirements, and `reviews/chisel/detection-review.md`.
- Decision: `reject`
- Label normalized (2026-11-21): the earlier token `rejected` is replaced by the contract's terminal value `reject`; the decision and its reasoning are unchanged.
- Reason: Adversarial review of the proposal (2026-08-16) found it unsound as written. The added event variable `$p` is declared in `events` and shares the match key `$host, $pid`, but `$p` never binds `$pid`, and `condition` only tests `$n and #n >= 2` -- `$p` is never referenced in `condition`. Per this rule's own repository convention (see `detections/chisel/yaral/chisel_listener_with_tunnel_egress.yaral`, `condition: $l and $n`), every declared event variable must appear in `condition` for its join to be enforced. As written the proposal is behaviorally identical to a bare `#n >= 2` outbound-connection threshold: the claimed pipe/handle correlation is not enforced at all. Even a corrected version that referenced `$p` in `condition` would still only bind on `$host` (not `$pid`), so it would assert that some pipe/handle event happened somewhere on the host rather than confirming the specific redirected-stdio process. The branch matrix shows the core branches are already `ours_stronger`; this proposal does not close a genuine coverage gap.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It adds no enforceable branch beyond the canonical rule's existing stdio-bridge logic and is not internally consistent (unbound join variable, unenforced condition). Rejecting it introduces no new false-negative path because canonical logic is unchanged.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

Our inventory covers the complete pinned multi-platform behavior family. The public candidate covers one adjacent platform or command-line slice and is not treated as comprehensive.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Correlate redirected standard handles with a pipe/handle connection and outbound flow.
- Required telemetry: process-attributed endpoint network, listener/UDP/stdio semantics as applicable, stable process entity, direction, destinations, timestamps, prevalence and collection health.
- Validation status: `unvalidated_proposal`

```yaral
rule proposed_chisel_stdio_network_bridge {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $n.metadata.event_type = "NETWORK_CONNECTION"
    $n.principal.hostname = $host
    $n.principal.process.product_specific_process_id = $pid
    $p.metadata.product_event_type = /PROCESS_PIPE_CONNECT|PROCESS_HANDLE_DUPLICATE/
  match:
    $host, $pid over 15m
  condition:
    $n and #n >= 2
}
```

This proposal adds procedure-specific causal context while retaining behavior-first logic. It still needs provider field binding, benign-baseline testing, and reverse-mode cross-host assessment before canonical adoption.

## Snapshot refresh (2026-11-21)

- Candidate re-pinned from elastic-security `7e91c15` to `9d792a8`. The decision trail above is unchanged.
- `rules/linux/command_and_control_cat_network_activity.toml` changed only in `updated_date` and classification tags; the query is identical.
