# Public-rule comparison: nmap_process_connect_scan_fanout

## Identity and independence gate

- Internal tool: `nmap` (revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`)
- Internal canonical rule: `detections/nmap/yaral/nmap_process_connect_scan_fanout.yaral`
- Internal SHA-256: `73563f563c8c802f3d635057888d229f6ba0cb60f4a732a728a30dad7b6e7092`
- Internal review completed before public comparison: `yes` (`reviews/nmap/detection-review.md`, NM-DR-01 to NM-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/discovery_port_scanning_activity_from_compromised_host.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/linux/discovery_port_scanning_activity_from_compromised_host.toml) - SHA-256 `59dc08498a40b0c6d8327550da2ee8a11a9e990b59fa07d345949df6ade96ddf`
- Scope mapping rationale: Both detect a host process attempting connections to many ports (T1046) from endpoint network telemetry.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| One process connecting to many ports or hosts | covered (all OS, >= 50 hosts or ports in 5 minutes) | covered (Linux, connection attempts to many ports) | process-attributed breadth - moderate | flow rule - moderate | complementary |
| Windows connect scans | covered | not covered (Linux only) | process breadth - moderate | none | ours_stronger |

## Missing detection branches

- Slow scans below the threshold (NM-DR-03).

## Detection edge cases and blind spots

- Raw scans are not attributed (NM-DR-01).

## Signal-quality assessment

- Both: process-attributed breadth - moderate.

## Public-rule weaknesses

- Linux-only; excludes java, node and python by name.

## Internal-rule weaknesses

- Scanner overlap (NM-DR-03).

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/nmap/source-analysis.md`, `telemetry/nmap.md` and `reviews/nmap/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would add name-based exclusions for interpreters (java, node, python) like the public rule. That opens a false-negative path, because scanners and NSE-like tooling written in Python would be excluded. Our fail-open signature exclusion already reduces benign volume.
  - No other branch is missing.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The public rule's Linux-specific exclusions do not apply to Windows. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Interpreter exclusions.
- Required telemetry: Process network events.
- Validation status: `unvalidated_proposal`

```yaral
rule nmap_process_connect_scan_fanout_interpreter_excluded {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "NM-P02"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.process.product_specific_process_id = $pid
    not re.regex($e.principal.process.file.full_path, `(?i)/(java|node|python[0-9.]*)$`)
  match:
    $pid over 5m
  outcome:
    $ports = count_distinct($e.target.port)
  condition:
    $e and $ports >= 50
}
```
