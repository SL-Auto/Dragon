# Public-rule comparison: ligolo_tunnel_process_internal_fanout

## Identity and independence gate

- Internal tool: `ligolo-ng` (revision `e543732f4be6dc899096ae322ae620bf010bfbfc`)
- Internal canonical rule: `detections/ligolo-ng/yaral/ligolo_tunnel_process_internal_fanout.yaral`
- Internal SHA-256: `ea49c324ec74172123956c8573e684bafb2a43154a91591bc2bfea4cb3118814`
- Internal review completed before public comparison: `yes` (`reviews/ligolo-ng/detection-review.md`, LG-DR-01 to LG-DR-09)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/discovery_potential_network_sweep_detected.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/discovery_potential_network_sweep_detected.toml) - SHA-256 `d1a2e89943a49f762e67ed54edff925588e31072ea2d1fc83fe4e9f97f9d34d4`
- Public candidate: [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/AVTarrask.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/AVTarrask.yaml) - SHA-256 `f54b76fc892ac9e6b8e6b9bc2a5ced39dd0746babb3be5d4c875511d05cc990c`
- Scope mapping rationale: Both address internal reconnaissance and access from a pivot host (T1046, T1090.001). The Elastic rule sees the sweep in network flows; the Sentinel rule fires on a Defender antivirus verdict naming the Ligolo hack tool. The mapping is by observable effect, not names.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Tunnelled access or scan from the agent process plus external tunnel egress | covered (per process, >= 10 internal IPs or ports) | not covered (no process, no tunnel leg) | process fan-out plus external egress - strong | flow sweep - moderate | ours_stronger |
| Large horizontal sweep of admin ports seen in flows | covered only when the tunnel leg is visible | covered (>= 100 destination IPs per source IP in 9 minutes) | flow cardinality - moderate | `ligolo_process_internal_admin_port_sweep` - moderate | complementary |
| Upstream through an internal proxy or chained agent (LG-DR-01) | not covered by this rule | covered for large sweeps | flow cardinality - moderate | new admin-port sweep rule - moderate | public_stronger |
| Agent binary present on disk or in memory | not targeted | covered when Defender names `HackTool:Win64/Ligolo!MSR` | AV verdict - moderate (signature-dependent) | none | different_scope |

## Missing detection branches

- Tunnelled sweeps where the tunnel leg is hidden by an internal proxy or a chained agent (LG-DR-01).
- Interactive single-service pivots below any fan-out threshold (LG-DR-06).

## Detection edge cases and blind spots

- The public flow rule cannot attribute the sweep to a process, so it cannot distinguish an approved scanner on the same host.
- A threshold of 100 destinations in 9 minutes misses most operator-paced sweeps through a tunnel.
- The AV-name rule depends on an unmodified, signatured binary.

## Signal-quality assessment

- Ours: per-process join of external egress and internal fan-out is close to the pivot effect - strong; signature exclusion fails open.
- Public sweep: flow cardinality by source IP - moderate; network-only, no process.
- Public Tarrask/Ligolo AV verdict: signature-dependent - moderate when present, absent for modified builds.

## Public-rule weaknesses

- The flow rule has no process attribution and counts only destination IPs on nine fixed ports.
- The Defender rule depends on a vendor signature name.

## Internal-rule weaknesses

- The external `$up` leg fails for an internal proxy or a chained agent (LG-DR-01).
- A ten-destination threshold misses single-service pivots (LG-DR-06).

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/ligolo-ng/source-analysis.md`, `telemetry/ligolo-ng.md` and `reviews/ligolo-ng/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The branch the public rule covers (a sweep without the tunnel leg) is real and closes part of LG-DR-01.
  - The adopted rule keeps process attribution, which the public rule lacks, so approved scanners can be separated by image.
  - The threshold is lowered from 100 to 30 internal hosts in 10 minutes, for operator-paced sweeps, and the fail-open signature exclusion is added.
  - Ports 135 (RPC) is added and 25 (SMTP) dropped, matching remote-administration services; the private ranges are extended to all RFC 1918 blocks and ULA IPv6.
  - The direction is restricted to OUTBOUND.
- Canonical result: `detections/ligolo-ng/yaral/ligolo_process_internal_admin_port_sweep.yaral`, SHA-256 `f269328add65e345b73fc2e3669ea265cba8b536a512815c11328cf074578bd4`.
- Regeneration: new canonical rule `ligolo_process_internal_admin_port_sweep`. Detection review (LG-DR-10), coverage, `telemetry/ligolo-ng.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison were produced in the same run.

## Unmatched scope

The public rules do not cover the per-process tunnel correlation, loopback access (LG-P05) or UDP relays. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Internal admin-port sweep from one process when the tunnel leg is not visible (LG-DR-01, LG-DR-03).
- Required telemetry: Process-attributed OUTBOUND NETWORK_CONNECTION with destination IP and integer port, host and process ID; optional signature status.
- Validation status: `unvalidated_proposal`

```yaral
rule ligolo_process_internal_sweep_no_tunnel_leg {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "LG-P04"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    ($e.target.port = 21 or $e.target.port = 22 or $e.target.port = 23 or $e.target.port = 25 or
     $e.target.port = 139 or $e.target.port = 445 or $e.target.port = 3389 or $e.target.port = 5985 or $e.target.port = 5986)
    net.ip_in_range_cidr($e.target.ip, "10.0.0.0/8")
  match:
    $host, $pid over 10m
  outcome:
    $hosts = count_distinct($e.target.ip)
  condition:
    $e and $hosts >= 100
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
