# Public-rule comparison: nmap_network_scan_flow_pattern

## Identity and independence gate

- Internal tool: `nmap` (revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`)
- Internal canonical rule: `detections/nmap/yaral/nmap_network_scan_flow_pattern.yaral`
- Internal SHA-256: `65539cb0c6a05db07ca29fb630164ae9ecd6e00e7619a2dd0219bc50d3be783e`
- Internal review completed before public comparison: `yes` (`reviews/nmap/detection-review.md`, NM-DR-01 to NM-DR-07)
- Public candidate: [`public-rules/snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/internal_horizontal_port_scan.yml`](../../snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/internal_horizontal_port_scan.yml) - SHA-256 `09e390e97ad1ae537ee72b15ca6b04072efd76d53732e23e00ab48e93d59c263`
- Public candidate: [`public-rules/snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/internal_vertical_port_scan.yml`](../../snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/internal_vertical_port_scan.yml) - SHA-256 `7ced815ac26bebdaf2afee7aa1128e03f95b966c9880d7a997033f4e6d7e16e6`
- Scope mapping rationale: All detect internal port scanning in network flows (T1046): Splunk's horizontal (many hosts on one port) and vertical (many ports on one host) rules, and our combined breadth rule.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Horizontal sweep from an internal source | covered (>= 100 hosts in 5 minutes) | covered (horizontal rule) | flow breadth - moderate | connect fan-out rule - moderate | equivalent |
| Vertical scan of one host | covered (>= 100 ports in 5 minutes) | covered (vertical rule) | flow breadth - moderate | none | equivalent |
| Scan attributed to a process | not in this rule (see connect fan-out) | not covered | process breadth - moderate | connect fan-out rule | complementary |

## Missing detection branches

- Slow scans spread beyond 5 minutes.

## Detection edge cases and blind spots

- NAT and shared sources; sampled flows.

## Signal-quality assessment

- All: flow cardinality - moderate.

## Public-rule weaknesses

- Separate rules per direction; Splunk data-model dependent.

## Internal-rule weaknesses

- One combined threshold for both directions.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/nmap/source-analysis.md`, `telemetry/nmap.md` and `reviews/nmap/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would split our rule into separate horizontal and vertical rules with per-port grouping. Our single rule already counts both cardinalities from one source, so splitting closes no branch and doubles the alert sources.
  - The public rules are equivalent in coverage.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Separate horizontal and vertical scans.
- Required telemetry: Network flows.
- Validation status: `unvalidated_proposal`

```yaral
rule nmap_horizontal_scan_flow {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "NM-P03"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_FLOW"
    $e.principal.ip = $source
    $e.target.port = $port
  match:
    $source, $port over 5m
  outcome:
    $hosts = count_distinct($e.target.ip)
  condition:
    $e and $hosts >= 250
}
```
