# Public-rule comparison: impacket_suspicious_service_control

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_suspicious_service_control.yaral`
- Internal SHA-256: `2de5824c92741e143d3a7cbff5a7d25200095146a4c1a431a6e1beed70d4440e`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-03`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral`](../../public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/win_susp_or_malicious_service_created.yaral) - SHA-256 `ffca062a76c08fcc3917a87424760bba8042c956275b072e962943ac5f3803f7`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-03` inventory and cited public rule. |
| remote logon followed by service creation or configuration | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Remote logon session joined by logon ID to service mutation - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: The events are joined only by host and may associate unrelated administrators; service change/start/delete paths are absent.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Remote logon session joined by logon ID to service mutation | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

The events are joined only by host and may associate unrelated administrators; service change/start/delete paths are absent. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-03, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the `$b.metadata.event_type = "STATUS_UPDATE"` / `$b.target.resource.attribute.labels["sensitive_effect"] = "true"` join is undefined anywhere in `schemas/chronicle-udm.yml` or the 20 canonical rules, so `$b` can never bind and the condition is permanently false. The existing `impacket_suspicious_service_control` rule already joins a `4624` remote logon to a `4697`/`7045` service-mutation event on the same `$host`/`$user`, which is the identical procedure branch this proposal targets, using grounded fields (`$a.extensions.auth.mechanism` in the proposal is a real UDM field, but it is attached to the unusable `$b` join, so the rule as a whole cannot fire). Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-03`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: The events are joined only by host and may associate unrelated administrators; service change/start/delete paths are absent.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_suspicious_service_control_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-03"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "4624"
    $a.principal.hostname = $host
    $a.extensions.auth.mechanism = /NTLM|KERBEROS/
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
