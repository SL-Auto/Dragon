# Public-rule comparison: impacket_remote_registry_activity

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_remote_registry_activity.yaral`
- Internal SHA-256: `b8506e0ac72a3a38ca220c02197c44d8952e44a08e4beb782c7a063e4e347b61`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-14`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral`](../../public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral) - SHA-256 `e79650f8b000e49753626aa7b858cf0363e069455be9bc5735e869be62c78abd`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-14` inventory and cited public rule. |
| RemoteRegistry activation or sensitive value mutation | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | RemoteRegistry start followed by remote sensitive-key write - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Service activation and registry mutation are broad alternatives with no remote caller or sensitive-key requirement.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| RemoteRegistry start followed by remote sensitive-key write | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Service activation and registry mutation are broad alternatives with no remote caller or sensitive-key requirement. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-14, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the join requires `$b.metadata.event_type = "STATUS_UPDATE"` and `$b.target.resource.attribute.labels["sensitive_effect"] = "true"`. Neither value is used, defined, or derivable anywhere in `schemas/chronicle-udm.yml` or any of the 20 canonical rules in this repository; `STATUS_UPDATE` is not a UDM event-type value produced by any cited parser and `sensitive_effect` has no enrichment source. As written, `$b` can never bind to a real event, so the two-event condition can never be satisfied and the rule would silently never fire — false operational confidence rather than added coverage. The underlying gap named in `Internal-rule weaknesses` ("service activation and registry mutation are broad alternatives with no remote caller or sensitive-key requirement") is a legitimate observation, but this specific proposal does not resolve it with any grounded telemetry. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-14`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Service activation and registry mutation are broad alternatives with no remote caller or sensitive-key requirement.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_remote_registry_activity_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-14"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = /(4657|12|13|14)/
    $a.principal.hostname = $host
    $a.target.registry.registry_key = /(?i)(SAM|SECURITY|SYSTEM|Terminal Server|Run)/
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
