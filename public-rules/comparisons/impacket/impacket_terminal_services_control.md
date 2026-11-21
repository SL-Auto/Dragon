# Public-rule comparison: impacket_terminal_services_control

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_terminal_services_control.yaral`
- Internal SHA-256: `23db18c5d1914e2cc062d7ff5c48a12a5528f51f76375dafa328d6803200ceeb`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-18`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral`](../../snapshots/chronicle-community/dbc9beb79597b519be086fce082214494d75b6a8/rules/community/microsoft/windows/potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral) - SHA-256 `e79650f8b000e49753626aa7b858cf0363e069455be9bc5735e869be62c78abd`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/impacket/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although a rule implementing the proposal's branch had been added on 2026-08-16 and revised on 2026-11-21 (REVIEW-010 to REVIEW-012) without the decision being recorded here.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Adopted as additive `impacket_terminal_services_session_control_by_other_actor`. It requires both identities to be non-empty before comparing them, because an empty-versus-populated comparison would otherwise match every event (REVIEW-011).
  - IDs anchored (`^(4778|4779|23|24|25)$`); aggregation per host over 10m.
  - Actor identity is often absent in session events; this is an accepted gap with the base lifecycle rule as compensation.
- Canonical result: `detections/impacket/yaral/impacket_terminal_services_control.yaral`, SHA-256 `60bbc59d9f72f780557a5609d5da0202fcf24683a20d0dd972658b622353a4d3`.
- Canonical result: `detections/impacket/yaral/impacket_terminal_services_session_control_by_other_actor.yaral`, SHA-256 `92d0a4bd4849fe08c77dff4872faa57a3d3eaebe3b004d0121c23a790894a7f5`.
- Regeneration: the adopted rule was reviewed and regenerated earlier on 2026-11-21 (see review reference); re-verified current.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Session connect/disconnect/reconnect events | covered by base rule | `potential_tampering_with_rdp_related_registry_keys_via_reg_exe.yaral`: reg.exe changing Terminal Server keys | session lifecycle - weak | other-actor rule - moderate | different_scope |
| One actor controlling another user's session | covered by the other-actor rule when both identities exist | not covered | actor differs from session owner - moderate | none | ours_stronger |
| RDP enablement through registry tampering | not targeted by these rules | covered | reg.exe Terminal Server key change - moderate | none | public_stronger |

- Current canonical YARA-L `detections/impacket/yaral/impacket_terminal_services_control.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_terminal_services_control {
 meta:
  author = "Detection Research Agent"
  description = "Detects unusual Terminal Services session connect, disconnect or logoff activity."
  date = "2026-08-15"
  status = "experimental"
  severity = "MEDIUM"
  severity_rationale = "Remote session manipulation may disrupt or hijack user activity."
  procedure_ids = "IMP-18"
  log_source_prerequisites = "Terminal Services Operational and Security session events with actor and session."
  false_positives = "Helpdesk and session administration."
  references = "reports/impacket/source-analysis.md"
  validation_status = "needs_validation"
  review_status = "reviewed_with_gaps"
  review_reference = "reviews/impacket/detection-review.md"
 events:
  $e.metadata.product_event_type = /^(4778|4779|23|24|25)$/
 condition: $e
}
```

- Current canonical YARA-L `detections/impacket/yaral/impacket_terminal_services_session_control_by_other_actor.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_terminal_services_session_control_by_other_actor {
  meta:
    author = "Detection Research Agent"
    description = "Detects a Terminal Services session connect, disconnect, reconnect or logoff control action performed by a principal different from the session's own target user, consistent with remote session hijack or tscon-style session takeover."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Controlling another user's interactive session can expose that user's authenticated desktop context and is a known RDP session-hijack primitive."
    procedure_ids = "IMP-18"
    log_source_prerequisites = "Terminal Services Operational and Security session events (4778/4779/23/24/25) with both a populated principal (acting) and target (session-owning) user identity."
    false_positives = "Helpdesk-initiated session shadowing/takeover, session broker or load-balancer service accounts, and RDS farm reconnection performed under a management service identity."
    references = "reports/impacket/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed"
    review_reference = "reviews/impacket/detection-review.md"
    source_comparison = "public-rules/comparisons/impacket/impacket_terminal_services_control.md"
    comparison_decision = "modify"
  events:
    $e.metadata.product_event_type = /^(4778|4779|23|24|25)$/
    $e.principal.user.userid != ""
    $e.target.user.userid != ""
    $e.principal.user.userid != $e.target.user.userid
    $e.principal.hostname = $host
  match:
    $host over 10m
  outcome:
    $actors = array_distinct($e.principal.user.userid)
    $session_owners = array_distinct($e.target.user.userid)
  condition:
    $e
}
```

- Re-comparison outcome: The adopted rule closes the caller-to-session attribution branch where the provider supplies both identities.
