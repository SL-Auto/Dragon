# Public-rule comparison: ligolo_bind_listener_internal_fanout

## Identity and independence gate

- Internal tool: `ligolo-ng` (revision `e543732f4be6dc899096ae322ae620bf010bfbfc`)
- Internal canonical rule: `detections/ligolo-ng/yaral/ligolo_bind_listener_internal_fanout.yaral`
- Internal SHA-256: `e6cb07a9f58eaa22e554ed3f71bab6aa9a152e4b8e9f61ce260989c35db1b81e`
- Internal review completed before public comparison: `yes` (`reviews/ligolo-ng/detection-review.md`, LG-DR-01 to LG-DR-09)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/discovery_potential_network_sweep_detected.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/discovery_potential_network_sweep_detected.toml) - SHA-256 `d1a2e89943a49f762e67ed54edff925588e31072ea2d1fc83fe4e9f97f9d34d4`
- Scope mapping rationale: Both address internal access from a pivot host. In bind mode the operator connects inbound and the agent fans out internally; the Elastic rule sees the resulting sweep in flows.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| External inbound session followed by internal fan-out from the same process | covered (>= 10 internal IPs or ports) | not covered | inbound accept plus fan-out - strong | admin-port sweep rule - moderate | ours_stronger |
| Bind-mode sweep where the parser orients inbound fields differently (LG-DR-03) | not covered | covered for large flow sweeps | flow cardinality - moderate | `ligolo_process_internal_admin_port_sweep` - moderate | public_stronger |
| Operator inbound from an internal host | not covered (inbound must be non-internal) | covered for large sweeps | flow cardinality - moderate | admin-port sweep rule - moderate | complementary |

## Missing detection branches

- Bind-mode activity under a parser that places the local process in `target` (LG-DR-03).
- An operator who connects from an already-compromised internal host.

## Detection edge cases and blind spots

- Accepted connections may be logged only by the network layer, not per process.
- Bind mode with little internal activity stays under the threshold.

## Signal-quality assessment

- Ours: inbound accept plus internal fan-out from one process - strong.
- Public: flow cardinality - moderate.

## Public-rule weaknesses

- No process attribution; fixed port set; a high threshold.

## Internal-rule weaknesses

- Depends on inbound field orientation (LG-DR-03) and a non-internal operator source.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/ligolo-ng/source-analysis.md`, `telemetry/ligolo-ng.md` and `reviews/ligolo-ng/detection-review.md`.
- Decision: `accept`.
- Reason: the proposal is adopted as written:
  - The proposal is the same process-attributed sweep compensating rule adopted for `ligolo_tunnel_process_internal_fanout`. It does not depend on inbound orientation, so it closes the LG-DR-03 branch for scan-type activity.
  - The adopted rule lists LG-P02 in its procedures. Its logic is the shared rule recorded in that comparison.
- Canonical result: `detections/ligolo-ng/yaral/ligolo_process_internal_admin_port_sweep.yaral`, SHA-256 `f269328add65e345b73fc2e3669ea265cba8b536a512815c11328cf074578bd4`.
- Regeneration: new canonical rule `ligolo_process_internal_admin_port_sweep`. Detection review (LG-DR-10), coverage, `telemetry/ligolo-ng.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison were produced in the same run.

## Unmatched scope

The public rule does not address the inbound session itself. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Bind-mode internal sweep independent of inbound field orientation (LG-DR-03).
- Required telemetry: Process-attributed OUTBOUND NETWORK_CONNECTION with destination IP and integer port, host and process ID.
- Validation status: `unvalidated_proposal`

```yaral
rule ligolo_process_internal_admin_port_sweep {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "LG-P02,LG-P04"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.direction = "OUTBOUND"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    ($e.target.port = 22 or $e.target.port = 135 or $e.target.port = 445 or $e.target.port = 3389 or $e.target.port = 5985)
    net.ip_in_range_cidr($e.target.ip, "10.0.0.0/8")
  match:
    $host, $pid over 10m
  outcome:
    $hosts = count_distinct($e.target.ip)
  condition:
    $e and $hosts >= 30
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/ligolo-ng/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule ligolo_process_internal_admin_port_sweep {
  meta:
    author = "Detection Research Agent"
    description = "Detects one unverified process connecting to many distinct internal hosts on administrative service ports within 10 minutes, without requiring a visible tunnel leg. It compensates for pivots whose upstream is an internal proxy, a chained agent or an inbound session that the parser cannot orient."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "A tunnelled sweep is completed by the agent process itself, so it appears as one process reaching many internal hosts on remote-administration ports. Without the tunnel leg this also matches unapproved scanners, hence medium."
    procedure_ids = "LG-P02,LG-P04"
    log_source_prerequisites = "Process-attributed OUTBOUND NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with destination IP and port, host and stable process ID; optional signature verification status."
    false_positives = "Unapproved or unsigned inventory, vulnerability and monitoring scanners and custom administration scripts; approve scanner images and hosts."
    references = "reports/ligolo-ng/source-analysis.md#procedure-analysis; public-rules/comparisons/ligolo-ng/ligolo_tunnel_process_internal_fanout.md; reviews/ligolo-ng/detection-review.md#lg-dr-10"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized flow fixtures of one process reaching 30 or more internal hosts on administrative ports, and baseline approved scanners before enabling."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/ligolo-ng/detection-review.md"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.network.direction = "OUTBOUND"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    (
      $e.target.port = 21 or $e.target.port = 22 or $e.target.port = 23 or $e.target.port = 135 or
      $e.target.port = 139 or $e.target.port = 445 or $e.target.port = 3389 or $e.target.port = 5985 or
      $e.target.port = 5986
    )
    (
      net.ip_in_range_cidr($e.target.ip, "10.0.0.0/8") or
      net.ip_in_range_cidr($e.target.ip, "172.16.0.0/12") or
      net.ip_in_range_cidr($e.target.ip, "192.168.0.0/16") or
      net.ip_in_range_cidr($e.target.ip, "fc00::/7")
    )
    $e.principal.process.file.signature_info.verification_status != "VERIFIED"
  match:
    $host, $pid over 10m
  outcome:
    $internal_hosts = count_distinct($e.target.ip)
    $ports = array_distinct($e.target.port)
    $process = array_distinct($e.principal.process.file.full_path)
  condition:
    $e and $internal_hosts >= 30
}
```
