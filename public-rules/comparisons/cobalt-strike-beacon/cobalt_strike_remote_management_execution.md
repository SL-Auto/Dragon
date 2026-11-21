# Public-rule comparison: cobalt_strike_remote_management_execution

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution.yaral`
- Internal SHA-256: `70a7a94468b3a41641d89393c9c9881ceb59f71737efdf33de505f2bfdd671cd`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-031,CSB-032,CSB-033`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_remote_powershell_session_initiated.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_remote_powershell_session_initiated.yaral) - SHA-256 `844a5013e68868eeb3691c397b4c40ed7b0ec64f9db701e75e892baa71b867fd`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| WinRM, WMI, or SSH session followed by target-side child execution | ordered session-to-process correlation across three protocols | public rules provide protocol-specific ancestry, logon, and command branches | remote session followed by target child - strong | ordered downstream security effect | complementary | Procedure `CSB-031,CSB-032,CSB-033` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: source-side initiation joined to target session and child process.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

session identifiers differ across sources and WMI may not expose a stable session key. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| remote session followed by target child | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but source-side initiation joined to target session and child process. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The proposal read the parent from `principal.process.parent_process`, which in UDM PROCESS_LAUNCH is the grandparent. The adopted rule uses `principal.process.file.full_path`, the launcher (DR-23).
  - The non-inventory `REMOTE_SESSION` type is replaced with the base's target-side WINRM_SESSION, WMI_REMOTE_OPERATION and SSH_AUTH types. The source-side requirement is dropped, so an unmonitored operator host does not hide the activity.
  - The parent-path regex is anchored, and Linux `/sshd` is included. Session-first ordering is kept, consistent with the other Cobalt Strike sequences.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution.yaral`, SHA-256 `d1ed45ff088141537f5201883e50607991c1aea1084b179632bd38d5258c5daf`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution_compensating_signal.yaral`, SHA-256 `79a26523202d6118b5ac34c21280381b309882a1650d60f3e97b08cb350f427a`.
- Regeneration: new canonical rule on 2026-11-21; detection review (DR-23), coverage, `telemetry/cobalt-strike-beacon.md`, `telemetry/MASTER.md` counts, native translations (`scripts/native_translations/specs_csb.py`), dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The public candidate does not cover all branches in `CSB-031,CSB-032,CSB-033`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: source-side initiation joined to target session and child process.
- Required telemetry: normalized `REMOTE_SESSION` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_remote_management_execution_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-031,CSB-032,CSB-033"
  events:
    $src.metadata.event_type = "REMOTE_SESSION"
        $src.principal.hostname = $source
        $src.target.hostname = $target
        $src.principal.user.userid = $user
        $child.metadata.event_type = "PROCESS_LAUNCH"
        $child.principal.hostname = $target
        $child.principal.user.userid = $user
        re.regex($child.principal.process.parent_process.file.full_path, `(?i)\\(wsmprovhost|wmiprvse|sshd)\.exe$`)
  match:
    $source, $target, $user over 10m
  condition:
    $src and $child
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/potential_remote_powershell_session_initiated.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Remote session followed by a child of the remote-management host process | covered by the compensating signal | `potential_remote_powershell_session_initiated.yaral`: source-side process connecting to 5985/5986 from a non-network-service account | session + wsmprovhost/wmiprvse/sshd lineage - strong | base same-account join - weak | complementary |
| Source-side WinRM initiation | not covered (target-side rules) | covered | outbound 5985/5986 by process - moderate | none | public_stronger |
| WMI and SSH channels | covered | not covered (WinRM only) | lineage from wmiprvse/sshd - strong | none | ours_stronger |

- Current canonical YARA-L `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution.yaral` (`experimental` / `needs_validation`):

```yaral
rule cobalt_strike_remote_management_execution {
  meta:
    author = "Detection Research Agent"
    description = "Detects WinRM, WMI or SSH remote-management session activity followed by a child process on the target."
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Remote management execution enables lateral movement but is widely used for legitimate administration."
    procedure_ids = "CSB-031,CSB-032,CSB-033"
    log_source_prerequisites = "Normalize WinRM Operational, WMI-Activity 5857-5861, SSH_AUTH/session and EDR PROCESS_LAUNCH with account, source, target/session and child process."
    false_positives = "Configuration management, helpdesk, orchestration, monitoring and approved remote administration."
    references = "reports/cobalt-strike-beacon/source-analysis.md"
    validation_status = "needs_validation"
    validation_method = "Use sanitized legitimate remote-management logs and synthetic process correlation."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
  events:
    ($remote.metadata.event_type = "WINRM_SESSION" or $remote.metadata.event_type = "WMI_REMOTE_OPERATION" or $remote.metadata.event_type = "SSH_AUTH")
    $remote.target.hostname = $host
    $remote.principal.user.userid = $user
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.principal.hostname = $host
    $proc.principal.user.userid = $user
  match:
    $host, $user over 10m
  condition:
    $remote and $proc
}
```

- Current canonical YARA-L `detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_management_execution_compensating_signal.yaral` (`experimental` / `needs_validation`):

```yaral
rule cobalt_strike_remote_management_execution_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates a WinRM, remote WMI or SSH session on a target with a subsequent process launched by the matching remote-management host process (wsmprovhost.exe, wmiprvse.exe or sshd) as the same account. This replaces the base rule's any-process-by-the-same-user join with process lineage that ties the child to the remote-management channel."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Lineage from the remote-management host process is a much closer link between the remote session and the executed command than account co-occurrence, but administrators routinely run commands this way."
    procedure_ids = "CSB-031,CSB-032,CSB-033"
    log_source_prerequisites = "Target-side WINRM_SESSION, WMI_REMOTE_OPERATION or SSH_AUTH events with target host and account, plus PROCESS_LAUNCH on the same host where principal.process is the launching (parent) process, joined on host and account within 10 minutes, session first."
    false_positives = "Remote administration, configuration management (DSC, Ansible over WinRM/SSH), monitoring and patching that run commands through WinRM, WMI or SSH."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_management_execution.md; reviews/cobalt-strike-beacon/detection-review.md#dr-23"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized remote-management fixtures (WinRM command, WMI process create, SSH command) and ordinary interactive logons; confirm only children of the remote-management host process match, and baseline administrative volume before enabling."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_remote_management_execution"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_management_execution.md"
  events:
    ($remote.metadata.event_type = "WINRM_SESSION" or $remote.metadata.event_type = "WMI_REMOTE_OPERATION" or $remote.metadata.event_type = "SSH_AUTH")
    $remote.target.hostname = $host
    $remote.principal.user.userid = $user

    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.principal.hostname = $host
    $proc.principal.user.userid = $user
    re.regex($proc.principal.process.file.full_path, `(?i)(\\(wsmprovhost|wmiprvse|sshd)\.exe|/sshd)$`)

    $remote.metadata.event_timestamp.seconds <= $proc.metadata.event_timestamp.seconds
  match:
    $host, $user over 10m
  outcome:
    $children = array_distinct($proc.target.process.file.full_path)
    $sources = array_distinct($remote.principal.ip)
    $channels = array_distinct($remote.metadata.event_type)
  condition:
    $remote and $proc
}
```

- Re-comparison outcome: the adopted rule closes the target-side lineage branch; source-side initiation remains a recorded public_stronger gap.
