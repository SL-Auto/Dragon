# Public-rule comparison: nmap_cli_option_grammar

## Identity and independence gate

- Internal tool: `nmap` (revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`)
- Internal canonical rule: `detections/nmap/yaral/nmap_cli_option_grammar.yaral`
- Internal SHA-256: `3b8f5f1449d472b5d346d0a003d42c44994835312fe4a80ed059d9a4f6d438ab`
- Internal review completed before public comparison: `yes` (`reviews/nmap/detection-review.md`, NM-DR-01 to NM-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/linux_nmap_activity.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/linux_nmap_activity.toml) - SHA-256 `18b67a214e6be34cce89735ae81e0e60a9120605e0250b0ba947505d35dabdfb`
- Scope mapping rationale: Both detect Nmap execution on a host (T1046). The public rule (now under Elastic `_deprecated`) matches the Linux process name `nmap`; ours matches compiled option grammar.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Nmap launched with scan options | covered (grammar, name-independent) | covered only when named nmap (Linux) | option grammar - strong | binary identity - moderate | ours_stronger |
| Default invocation `nmap <target>` without options | not covered before this comparison | covered by name | process name - weak | new binary-identity rule | public_stronger |
| Renamed binary | covered | not covered | grammar or PE OriginalFileName - strong | none | ours_stronger |

## Missing detection branches

- Default invocations without option grammar (NM-DR-08).

## Detection edge cases and blind spots

- Linux binaries carry no PE metadata, so renamed default invocations are only seen by network rules.

## Signal-quality assessment

- Ours: grammar - strong.
- Public: process name - weak, and deprecated upstream.

## Public-rule weaknesses

- Name-only, Linux-only, deprecated.

## Internal-rule weaknesses

- Missed default invocations before this comparison.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/nmap/source-analysis.md`, `telemetry/nmap.md` and `reviews/nmap/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The default-invocation branch is real. It is adopted as `nmap_binary_identity_execution` using the PE `OriginalFilename` `nmap.exe` (`mswin32/nmap.rc` L37), which survives renaming on Windows, plus the image name on other platforms (NM-DR-08).
  - A pure name match is not used on Windows.
- Canonical result: `detections/nmap/yaral/nmap_binary_identity_execution.yaral`, SHA-256 `8a27e891ae1692dae2de2c8fc4c86546f06a66453eb3871fdf7c08956576dec2`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/nmap.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

The public rule covers only Linux. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Default Nmap invocation without option grammar.
- Required telemetry: Process creation with image path and PE OriginalFileName.
- Validation status: `unvalidated_proposal`

```yaral
rule nmap_process_name_execution {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "NM-P02"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.file.full_path, `(?i)/nmap$`)
  condition:
    $p
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/nmap/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule nmap_binary_identity_execution {
  meta:
    author = "Detection Research Agent"
    description = "Detects execution of the Nmap binary identified by its PE OriginalFileName (nmap.exe), which survives renaming on Windows, or by an image named nmap on other platforms. It covers default invocations such as nmap <target> that carry no option grammar."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Binary identity is reliable on Windows through PE version information; on Linux the name is mutable. Administrators also run Nmap."
    procedure_ids = "NM-P01,NM-P02,NM-P03,NM-P05,NM-P06,NM-P07,NM-P08"
    log_source_prerequisites = "PROCESS_LAUNCH telemetry with image path and PE OriginalFileName (Sysmon Event ID 1 OriginalFileName mapped to target.process.file.pe_file.original_file_name, or EDR equivalent)."
    false_positives = "Authorized administrators and vulnerability-management hosts running Nmap; approve by host."
    references = "reports/nmap/source-analysis.md#procedure-analysis; public-rules/comparisons/nmap/nmap_cli_option_grammar.md; reviews/nmap/detection-review.md#nm-dr-08"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized Sysmon Event ID 1 fixtures for renamed nmap.exe and Linux nmap; confirm OriginalFileName mapping."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/nmap/detection-review.md"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    (
      re.regex($p.target.process.file.pe_file.original_file_name, `(?i)^nmap\.exe$`) or
      re.regex($p.target.process.file.full_path, `(?i)(\\nmap\.exe|/nmap)$`)
    )
    $p.target.process.file.full_path = $image
  match:
    $host, $image over 1h
  outcome:
    $command_lines = array_distinct($p.target.process.command_line)
    $users = array_distinct($p.principal.user.userid)
  condition:
    $p
}
```
