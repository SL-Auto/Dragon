# Public-rule comparison: impacket_wmi_subscription_change

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_wmi_subscription_change.yaral`
- Internal SHA-256: `a552ad69e460526b0d4b64c89da92a42e3cb6c0588b2e2df40ac90d8a1170fae`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-06`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/impacket_wmiexec_cisa_report.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/impacket_wmiexec_cisa_report.yaral) - SHA-256 `f58e8a176873a313463e9f196ef0ee3ea287cf603a772f386032c41511c70d19`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-06` inventory and cited public rule. |
| WMI filter, consumer, and binding creation | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Filter-consumer-binding triad joined by subscription identity - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Single events do not prove a complete subscription and permanent repository changes may lack Sysmon.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Filter-consumer-binding triad joined by subscription identity | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Single events do not prove a complete subscription and permanent repository changes may lack Sysmon. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-06, `reports/impacket/source-analysis.md`), `telemetry/impacket.md`, `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the `$a` predicate (`product_event_type` in `19|20|21|5861`) is grounded and matches the existing rule's event family, but the `$b` join requires `$b.metadata.event_type = "STATUS_UPDATE"` and `$b.target.resource.attribute.labels["sensitive_effect"] = "true"`, neither of which is defined anywhere in `schemas/chronicle-udm.yml` or the 20 canonical rules. `$b` can never bind, so the two-event condition is permanently false regardless of how sound `$a` is. The named gap ("single events do not prove a complete subscription") is legitimate — a genuine filter-consumer-binding triad correlation by subscription/CLSID identity across Sysmon 19/20/21 would be a real improvement — but this proposal does not implement that triad join; it substitutes an unresolvable placeholder for the second event instead of a second real Sysmon WMI event ID. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-06`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Single events do not prove a complete subscription and permanent repository changes may lack Sysmon.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_wmi_subscription_change_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-06"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = /(19|20|21|5861)/
    $a.principal.hostname = $host
    $a.target.resource.name = $subscription
    $a.principal.user.userid = $actor
    $b.principal.hostname = $host
    $b.principal.user.userid = $actor
    $b.metadata.event_type = "STATUS_UPDATE"
    $b.target.resource.attribute.labels["sensitive_effect"] = "true"
    $a.metadata.event_timestamp.seconds <= $b.metadata.event_timestamp.seconds
  match:
    $host, $actor over 15m
  condition:
    $a and $b
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/community/microsoft/windows/impacket_wmiexec_cisa_report.yaral` differs between 234e922 and dbc9beb only in line endings (snapshot path moved where applicable); content is identical.
