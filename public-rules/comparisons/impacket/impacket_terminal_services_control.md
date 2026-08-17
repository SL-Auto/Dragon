# Public-rule comparison: impacket_terminal_services_control

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_terminal_services_control.yaral`
- Internal SHA-256: `23db18c5d1914e2cc062d7ff5c48a12a5528f51f76375dafa328d6803200ceeb`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-18`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral`](../../public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral) - SHA-256 `e79650f8b000e49753626aa7b858cf0363e069455be9bc5735e869be62c78abd`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-18` inventory and cited public rule. |
| Terminal Services session connect, disconnect, reconnect, or logoff control | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Session-control event where actor differs from target session user - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Common session lifecycle events lack caller-to-target-session attribution and administrative control semantics.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Session-control event where actor differs from target session user | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Common session lifecycle events lack caller-to-target-session attribution and administrative control semantics. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: required against pinned Impacket source analysis, provider documentation, local schema mappings, and authorized fixtures.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: public logic is comparative evidence, not authority; this proposal has not passed internal adversarial review.
- Required regeneration: canonical review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, then this comparison.

## Unmatched scope

The public candidate does not cover all of `IMP-18`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Common session lifecycle events lack caller-to-target-session attribution and administrative control semantics.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_terminal_services_control_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-18"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(4778|4779|23|24|25)/
    $e.principal.hostname = $host
    $e.principal.user.userid != $e.target.user.userid
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.
