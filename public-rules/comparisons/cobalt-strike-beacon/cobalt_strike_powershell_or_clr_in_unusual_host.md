# Public-rule comparison: cobalt_strike_powershell_or_clr_in_unusual_host

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_powershell_or_clr_in_unusual_host.yaral`
- Internal SHA-256: `f71d27760edbdf9e66752e21ce05e9640727f28252cec917b8d57249b6ac1962`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-015,CSB-017`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/base64_encoded_powershell_command_detected.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/base64_encoded_powershell_command_detected.yaral) - SHA-256 `9d5911d5aa2803b1ee3765ac1e2ba7c3a84591b6473b3a6c6d7d97aeadf25529`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| PowerShell or CLR runtime hosted in an unusual process | runtime/script telemetry keyed to unusual host identity | PowerShell rules add script-content and encoded/download branches, while CLR rules add module-load ancestry | runtime initialization in rare unsigned process - strong | ordered downstream security effect | complementary | Procedure `CSB-015,CSB-017` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

legitimate automation embeds CLR or PowerShell; runtime telemetry can be absent. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| runtime initialization in rare unsigned process | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Added a native Windows host-binary branch for the sacrificial-process pattern; the unsigned/rare OR became AND (DR-18).
  - `msiexec` excluded because managed installer custom actions load the CLR.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal.yaral`, SHA-256 `dca5a4ce3836fd4bcc4aeb8422c302d23205749e37aa763427fb84494a3d0515`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-015,CSB-017`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: CLR initialization in unsigned network-facing processes and PowerShell without script-block telemetry.
- Required telemetry: normalized `MODULE_LOAD` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-015,CSB-017"
  events:
    $e.metadata.event_type = "MODULE_LOAD"
        $e.principal.process.file.sha256 = $process_hash
        re.regex($e.target.file.full_path, `(?i)\\(clr|coreclr)\.dll$`)
        $e.additional.fields["process_signed"].value.bool_value = false
        $e.additional.fields["process_prevalence"].value.string_value = "RARE"
  match:
    $process_hash over 10m
  condition:
    $e
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `dca5a4ce3836fd4bcc4aeb8422c302d23205749e37aa763427fb84494a3d0515`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/community/microsoft/windows/base64_encoded_powershell_command_detected.yaral` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| CLR loaded into a spawned native signed host binary | covered by host-binary branch | `base64_encoded_powershell_command_detected.yaral`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | CLR in non-.NET native host - strong | runtime telemetry base rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |
| CLR loaded into an unsigned, rare custom host | covered when both enrichments agree | `base64_encoded_powershell_command_detected.yaral`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | unsigned and rare CLR host - moderate | base rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Detects CLR/CoreCLR module load either into a native Windows host binary that is not a .NET application (the sacrificial-process pattern used for in-memory assembly execution) or into a process that is both unsigned and rare, providing an alternate detection path when runtime-expected/CLR_RUNTIME_LOAD telemetry is unavailable."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "CLR loading into an unsigned or rare host process is a strong unmanaged-assembly-execution signal, though legitimate custom .NET hosts and management agents can match."
    procedure_ids = "CSB-015,CSB-017"
    log_source_prerequisites = "Normalize MODULE_LOAD (Sysmon 7 or EDR image load) for clr.dll/coreclr.dll with loading process image path, signer and prevalence."
    false_positives = "Custom .NET hosts, IDEs, installers, and management agents that legitimately embed the CLR in an uncommon or unsigned process."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_powershell_or_clr_in_unusual_host.md"
    validation_status = "needs_validation"
    validation_method = "Use sanitized approved custom-CLR-host fixtures to confirm the signer/prevalence gate against known-legitimate embedders."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_powershell_or_clr_in_unusual_host"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_powershell_or_clr_in_unusual_host.md"
    modification_note = "Proposal accepted with required changes: replaced the invented additional.fields['process_signed']/['process_prevalence'] pair with the native principal.process.file.is_signed/prevalence fields already used by every other signer/rarity check in this rule family, and dropped an unused process_hash match window that had no aggregation function referencing it in the condition."
  events:
    $e.metadata.event_type = "MODULE_LOAD"
    $e.principal.hostname = $host
    re.regex($e.target.file.full_path, `(?i)\\(clr|coreclr)\.dll$`)
    (
      re.regex($e.principal.process.file.full_path, `(?i)\\(rundll32|dllhost|regsvr32|werfault|searchprotocolhost|gpupdate|spoolsv|notepad|svchost|wuauclt|mstsc)\.exe$`) or
      ($e.principal.process.file.is_signed = false and $e.principal.process.file.prevalence = "RARE")
    )
  match:
    $host over 10m
  outcome:
    $host_processes = array_distinct($e.principal.process.file.full_path)
  condition:
    $e
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
