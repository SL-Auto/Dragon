# Public-rule comparison: impacket_remote_wmi_activity

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_remote_wmi_activity.yaral`
- Internal SHA-256: `7ba7192d0f9f6e80d27035b32e27e51357ba5c77a51b1a4ea8e547fb27e0f4bd`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-05`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/impacket_wmiexec_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/impacket_wmiexec_cisa_report.yaral) - SHA-256 `f58e8a176873a313463e9f196ef0ee3ea287cf603a772f386032c41511c70d19`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-05` inventory and cited public rule. |
| remote WMI method execution and provider-spawned process | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | WMI-Activity method invocation from a remote source followed by provider child - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Provider child detection misses processless methods, remote caller attribution, and failed attempts.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| WMI-Activity method invocation from a remote source followed by provider child | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Provider child detection misses processless methods, remote caller attribution, and failed attempts. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/impacket/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although a rule implementing the proposal's branch had been added on 2026-08-16 and revised on 2026-11-21 (REVIEW-010 to REVIEW-012) without the decision being recorded here.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Adopted as additive `impacket_wmi_activity_operational_class_signal`, with anchored IDs and a `Win32_Process` class filter instead of every WMI-Activity event.
  - WMI-Activity does not log successful method execution; the provider limit is an accepted gap, compensated by the WmiPrvSE lineage base rule (REVIEW-012).
- Canonical result: `detections/impacket/yaral/impacket_remote_wmi_activity.yaral`, SHA-256 `db22f6407666dabf6b1499636be53a5e64102c8907ce56f9fdc7d11fd2380f5f`.
- Canonical result: `detections/impacket/yaral/impacket_wmi_activity_operational_class_signal.yaral`, SHA-256 `db9d3389c2b25fcae08c9b618480a20b10767b04f1241535d4a6cd0cd151621f`.
- Regeneration: the adopted rule was reviewed and regenerated earlier on 2026-11-21 (see review reference); re-verified current.

## Unmatched scope

The public candidate does not cover all of `IMP-05`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Provider child detection misses processless methods, remote caller attribution, and failed attempts.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_remote_wmi_activity_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-05"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(5857|5858|5860|5861)/
    $e.principal.hostname = $host
    $e.principal.ip = $source
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| WmiPrvSE spawns a child process | covered by base rule | `impacket_wmiexec_cisa_report.yaral`: wmiexec.py artifacts (command-line and output-file patterns) | WmiPrvSE child - moderate | WMI-Activity class signal - weak | complementary |
| WMI provider errors or operations naming Win32_Process | covered by the class-signal rule | not covered | 5857-5861 with class - weak | lineage rule - moderate | ours_stronger |
| Default tool output-file artifacts | not targeted (mutable) | covered | artifact pattern - weak | none | different_scope |

- Current canonical YARA-L `detections/impacket/yaral/impacket_remote_wmi_activity.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_remote_wmi_activity {
  meta:
    author = "Detection Research Agent"
    description = "Detects a command interpreter created by the WMI provider; SMB output activity is optional enrichment rather than a required event."
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Remote WMI command execution is powerful and merits review when outside approved management sources."
    procedure_ids = "IMP-05"
    log_source_prerequisites = "Normalize WMI Activity or EDR process creation with host, account, parent process, child process, and command line."
    false_positives = "Endpoint management, inventory, remediation, and authorized WMI administration."
    references = "reports/impacket/source-analysis.md"
    validation_status = "needs_validation"
    validation_method = "Replay approved WMI administration and synthetic correlated file events; never execute Impacket."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/impacket/detection-review.md"

  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($process.principal.process.file.full_path, `(?i)\\WmiPrvSE\.exe$`)

  condition:
    $process
}
```

- Current canonical YARA-L `detections/impacket/yaral/impacket_wmi_activity_operational_class_signal.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_wmi_activity_operational_class_signal {
  meta:
    author = "Detection Research Agent"
    description = "Detects a remote WMI method invocation against the Win32_Process class observed directly in the WMI-Activity Operational log, independent of whether a WmiPrvSE child process was collected."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "The operational-log signal captures processless or failed-child-collection WMI process-creation attempts that the process-lineage rule can miss, but by itself it is not proximate enough to the effect to warrant HIGH without tenant baselining."
    procedure_ids = "IMP-05"
    log_source_prerequisites = "WMI-Activity Operational 5857/5858/5860/5861 with the operation text parsed into a class label and the caller (ClientMachine) normalized to principal.hostname. Successful Win32_Process.Create calls are not logged by WMI-Activity; this rule sees mainly 5858 failures and 5860/5861 subscription records (review REVIEW-012)."namespace/query/class/parent/source\")."
    false_positives = "Endpoint management, inventory, remediation, monitoring agents and any authorized WMI administration that creates or queries Win32_Process; this event family is high-volume and requires tenant baselining before enforcement."
    references = "reports/impacket/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed"
    review_reference = "reviews/impacket/detection-review.md"
    source_comparison = "public-rules/comparisons/impacket/impacket_remote_wmi_activity.md"
    comparison_decision = "modify"
  events:
    $e.metadata.product_event_type = /^(5857|5858|5860|5861)$/
    $e.principal.hostname = $host
    re.regex($e.target.resource.attribute.labels["class"], `(?i)Win32_Process`)
  match:
    $host over 10m
  outcome:
    $sources = array_distinct($e.principal.ip)
    $event_ids = array_distinct($e.metadata.product_event_type)
  condition:
    $e
}
```

- Re-comparison outcome: The adopted pair closes the processless-provider branch to the extent the provider logs it.
