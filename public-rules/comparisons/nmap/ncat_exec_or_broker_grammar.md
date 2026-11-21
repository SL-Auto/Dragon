# Public-rule comparison: ncat_exec_or_broker_grammar

## Identity and independence gate

- Internal tool: `nmap` (revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`)
- Internal canonical rule: `detections/nmap/yaral/ncat_exec_or_broker_grammar.yaral`
- Internal SHA-256: `624f6200f342cd479e470472cb3770746638e90f88c42a8d7f21199667a11201`
- Internal review completed before public comparison: `yes` (`reviews/nmap/detection-review.md`, NM-DR-01 to NM-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_revshell_cmd_via_netcat.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/execution_revshell_cmd_via_netcat.toml) - SHA-256 `b6ab0ee2a5b13ebd82a5bc94f98bbe90dc8258e780bdb9b04bba51d3c864bc40`
- Scope mapping rationale: Both detect netcat-family command execution bound to a socket (T1059, T1090). The public rule detects the cmd or PowerShell child of a parent with `-e` arguments; ours detects the Ncat launch grammar.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Ncat launched with exec, broker or listen-plus-exec options | covered | not covered (requires the child) | launch grammar - strong | shell-child rule - strong | ours_stronger |
| Shell spawned by a socket-bound parent | not covered before this comparison | covered (Windows; cmd or PowerShell child) | child of a socket-bound parent - strong | new shell-child rule | public_stronger |
| Renamed netcat variant with different long options | not covered by grammar | covered via the child | child shell - strong | new shell-child rule | public_stronger |

## Missing detection branches

- The shell-child effect was missing (NM-DR-09).

## Detection edge cases and blind spots

- Parent command line is required in telemetry.

## Signal-quality assessment

- Ours: launch grammar - strong.
- Public: child-of-socket-bound-parent - strong.

## Public-rule weaknesses

- Windows-only; it requires a parent argument count of exactly five, or specific flag shapes.

## Internal-rule weaknesses

- Launch-only coverage before this comparison.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/nmap/source-analysis.md`, `telemetry/nmap.md` and `reviews/nmap/detection-review.md`.
- Decision: `modify`.
- Reason: the branch is real; the adopted rule diverges from the proposal as follows:
  - The child-shell branch is adopted as `ncat_socket_bound_shell_child`. It is cross-platform (cmd, PowerShell and POSIX shells), drops the public rule's exact argument-count heuristic, and requires a bind flag plus listen mode or an IP address and port (NM-DR-09).
- Canonical result: `detections/nmap/yaral/ncat_socket_bound_shell_child.yaral`, SHA-256 `5447e2fcf0c2377be61f86a8c2acd1ecc7f8c5b72763c3da274358a43b3b2245`.
- Regeneration: new canonical rule; regenerated in the same run: detection review, coverage, `telemetry/nmap.md`, `telemetry/MASTER.md` counts, native translations, dependency and manifest hashes, and this re-comparison.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `new_rule`
- Addresses branches: Shell spawned by a socket-bound netcat-family parent.
- Required telemetry: Process creation with parent command line.
- Validation status: `unvalidated_proposal`

```yaral
rule ncat_shell_child_windows {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "NM-P15"
    source_comparison = "unvalidated_proposal"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($p.target.process.file.full_path, `(?i)\\(cmd|powershell)\.exe$`)
    re.regex($p.principal.process.command_line, `\s-e\s`)
  condition:
    $p
}
```

## Re-comparison against revised canonical rule

- The adopted rule was re-run against the branch matrix above on 2026-11-21. It closes the targeted branch within declared telemetry; the residual limits are in `reviews/nmap/detection-review.md`.
- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule ncat_socket_bound_shell_child {
  meta:
    author = "Detection Research Agent"
    description = "Detects a command shell started by a parent process whose command line binds a program to a socket (-e, --exec, -c or --sh-exec) together with listen mode or an IP address and port. This is the effect of an Ncat or netcat bind or reverse shell, regardless of the parent's name."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A shell whose parent bound it to a network socket is a remote-shell effect, close to the security impact."
    procedure_ids = "NM-P15"
    log_source_prerequisites = "PROCESS_LAUNCH telemetry with child image path and the parent command line (Sysmon Event ID 1 ParentCommandLine mapped to principal.process.command_line, or EDR equivalent)."
    false_positives = "Administrators using Ncat for authorized troubleshooting with command execution."
    references = "reports/nmap/source-analysis.md#procedure-analysis; public-rules/comparisons/nmap/ncat_exec_or_broker_grammar.md; reviews/nmap/detection-review.md#nm-dr-09"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized bind and reverse shell process trees; confirm bash -c and similar wrappers without listen mode or an address do not match."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/nmap/detection-review.md"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    re.regex($p.target.process.file.full_path, `(?i)(\\(cmd|powershell|pwsh)\.exe|/(ba|z|da|k)?sh)$`)
    re.regex($p.principal.process.command_line, `(^|\s)(-e|--exec|-c|--sh-exec)(\s|=)\S+`)
    (
      re.regex($p.principal.process.command_line, `(^|\s)(-[nvk]*l[nvkp]*|--listen)(\s|$)`) or
      re.regex($p.principal.process.command_line, `(\d{1,3}\.){3}\d{1,3}\s+\d{2,5}(\s|$)`)
    )
    $p.principal.process.file.full_path = $parent
  match:
    $host, $parent over 1h
  outcome:
    $parent_command_lines = array_distinct($p.principal.process.command_line)
    $shells = array_distinct($p.target.process.file.full_path)
  condition:
    $p
}
```
