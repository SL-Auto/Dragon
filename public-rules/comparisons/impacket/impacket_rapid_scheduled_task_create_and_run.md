# Public-rule comparison: impacket_rapid_scheduled_task_create_and_run

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_rapid_scheduled_task_create_and_run.yaral`
- Internal SHA-256: `24636e3eb5743ab5f3b52231dedc9feadd049974e2ac86e1a9da6a95306c4ad3`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-04`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/mitre_attack_T1053_005_windows_creation_of_scheduled_task.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/mitre_attack_T1053_005_windows_creation_of_scheduled_task.yaral) - SHA-256 `2eb44b846b6b7f7c6cb3e9cf2d371e11bb8fe956c84edc6bacd2b7a94711c637`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-04` inventory and cited public rule. |
| task registration followed by execution | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | 4698/106 task creation with risky action and remote logon attribution - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Task updates, remote registration identity, XML action risk, and execution without a collected run event.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4698/106 task creation with risky action and remote logon attribution | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Task updates, remote registration identity, XML action risk, and execution without a collected run event. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-04, `reports/impacket/source-analysis.md`), `telemetry/impacket.md` TEL-002, `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the proposed predicate `target.resource.attribute.labels["task_action_risk"] = "high"` has no defined derivation in `schemas/chronicle-udm.yml` or in any of the 20 canonical rules — no XML task action is parsed or scored anywhere in this rule set, so nothing would ever populate this label and the rule would silently never match. The claimed missing branches ("task updates, remote registration identity, XML action risk, and execution without a collected run event") are not implemented by the code either: it inspects only the creation event (4698/106) with no join to remote-logon identity, no update-event coverage, and no accommodation for a missing run event — it is a strict subset of the existing two-event `impacket_rapid_scheduled_task_create_and_run` rule's `$create`/`$run` correlation, not an addition to it. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-04`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Task updates, remote registration identity, XML action risk, and execution without a collected run event.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_rapid_scheduled_task_create_and_run_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-04"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(4698|106)/
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["task_action_risk"] = "high"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/community/microsoft/windows/mitre_attack_T1053_005_windows_creation_of_scheduled_task.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.
