# Public-rule comparison: impacket_cross_source_ntlm_relay

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_cross_source_ntlm_relay.yaral`
- Internal SHA-256: `0018e80b82a43728146e9e8640dc1b86b2899b58b520564138f57884a88b76c7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-21`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml) - SHA-256 `3e78aa4fae6e9c216368f412c301512c30698baffaec39a9da33f6f3c47c35d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-21` inventory and cited public rule. |
| inbound NTLM authentication followed by a privileged target-side effect | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | NTLM authentication causally joined to a privileged change on the same target and account - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: The current rule detects source inconsistency but never requires a target effect and therefore conflates relay with proxies.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| NTLM authentication causally joined to a privileged change on the same target and account | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

The current rule detects source inconsistency but never requires a target effect and therefore conflates relay with proxies. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/impacket/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although a rule implementing the proposal's branch had been added on 2026-08-16 and revised on 2026-11-21 (REVIEW-010 to REVIEW-012) without the decision being recorded here.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The branch is implemented as additive `impacket_ntlm_relay_with_privileged_effect`, not as a rewrite: the base cross-source rule keeps relay-origin context.
  - The proposal's `STATUS_UPDATE` event carrying a `sensitive_effect` label is replaced with concrete effect events: 4697/7045 service install, the 4720-4757 account/group family, and DC 5136/5137, joined on target host and account (REVIEW-010).
  - The first leg requires 4624 LogonType 3 with AuthenticationPackageName NTLM; severity is CRITICAL.
- Canonical result: `detections/impacket/yaral/impacket_cross_source_ntlm_relay.yaral`, SHA-256 `e73d159dda1a495d4775f00fa5b0909d16374e4b88a3f8334f3bcd9c811a14e9`.
- Canonical result: `detections/impacket/yaral/impacket_ntlm_relay_with_privileged_effect.yaral`, SHA-256 `26c3992b137c51bad1d44cd77871d2b535bd5e22b642029d668574b8669fa21e`.
- Regeneration: the adopted rule was reviewed and regenerated earlier on 2026-11-21 (see review reference); re-verified current.

## Unmatched scope

The public candidate does not cover all of `IMP-21`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: The current rule detects source inconsistency but never requires a target effect and therefore conflates relay with proxies.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_cross_source_ntlm_relay_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-21"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = /(4624|4776)/
    $a.principal.hostname = $host
    $a.security_result.authentication.type = "NTLM"
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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| NTLM network logon followed by a privileged effect as the same account on the same host | covered by `impacket_ntlm_relay_with_privileged_effect` | `privilege_escalation_krbrelayup_suspicious_logon.toml` (now under `_deprecated`): local Kerberos logon from localhost as built-in Administrator | 4624 NTLM type 3 + effect - strong | cross-source NTLM - moderate | different_scope |
| Same account authenticating from two sources within 2 minutes | covered by base rule | not covered | cross-source 4624/4776 - moderate | none | ours_stronger |
| Local Kerberos relay to SYSTEM (KrbRelayUp variant) | not targeted (not an Impacket procedure) | covered by a deprecated rule only | localhost Kerberos logon - moderate | none | different_scope |

- Current canonical YARA-L `detections/impacket/yaral/impacket_cross_source_ntlm_relay.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_cross_source_ntlm_relay {
 meta:
  author = "Detection Research Agent"
  description = "Correlates NTLM authentication for one account across different sources and a target effect."
  date = "2026-08-15"
  status = "experimental"
  severity = "HIGH"
  severity_rationale = "Cross-source authentication inconsistency can indicate relay."
  procedure_ids = "IMP-21"
  log_source_prerequisites = "Normalized NTLM authentication with account, source, destination and result."
  false_positives = "NAT, proxies, clustered services and multi-hop authentication."
  references = "reports/impacket/source-analysis.md"
  validation_status = "needs_validation"
  review_status = "reviewed_with_gaps"
  review_reference = "reviews/impacket/detection-review.md"
 events:
  $a.metadata.product_event_type = /(4624|4776)/
  $a.principal.user.userid = $user
  $a.principal.ip = $src1
  $b.metadata.product_event_type = /(4624|4776)/
  $b.principal.user.userid = $user
  $b.principal.ip = $src2
  $src1 != $src2
 match: $user over 2m
 condition: $a and $b
}
```

- Current canonical YARA-L `detections/impacket/yaral/impacket_ntlm_relay_with_privileged_effect.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_ntlm_relay_with_privileged_effect {
  meta:
    author = "Detection Research Agent"
    description = "Correlates NTLM authentication (4624/4776) with a privileged target-side effect (service install, account/group change, or AD authorization change) by the same account on the same host, requiring the target-side effect that the base cross-source relay rule does not."
    date = "2026-11-21"
    status = "experimental"
    severity = "CRITICAL"
    severity_rationale = "A privileged change immediately following NTLM authentication is a stronger relay/abuse indicator than source inconsistency alone, and it narrows the base rule's proxy and NAT false-positive class by requiring proof of causal effect."
    procedure_ids = "IMP-21"
    log_source_prerequisites = "Normalized Windows Security 4624 network logons (LogonType 3) with AuthenticationPackageName, target host, target account and source IP, correlated on the same host and acting account with service (4697/7045), account/group (4720-4757 family) or AD-authorization change (5136/5137) events. 4776 is DC-side credential validation and is not used because its host is the validating DC, not the relay target."
    false_positives = "Administrators who authenticate and then immediately perform routine privileged administration on the same host within the correlation window."
    references = "reports/impacket/source-analysis.md"
    validation_status = "needs_validation"
    review_status = "reviewed"
    review_reference = "reviews/impacket/detection-review.md"
    source_comparison = "public-rules/comparisons/impacket/impacket_cross_source_ntlm_relay.md"
    comparison_decision = "modify"
  events:
    $auth.metadata.product_event_type = "4624"
    $auth.additional.fields["LogonType"].value.string_value = "3"
    re.regex($auth.additional.fields["AuthenticationPackageName"].value.string_value, `(?i)^NTLM$`)
    $auth.target.hostname = $host
    $auth.target.user.userid = $user
    $effect.metadata.product_event_type = /^(4697|7045|4720|4722|4723|4724|4725|4726|4738|4741|4742|4743|4728|4729|4732|4733|4756|4757|5136|5137)$/
    $effect.target.hostname = $host
    $effect.principal.user.userid = $user
    $auth.metadata.event_timestamp.seconds <= $effect.metadata.event_timestamp.seconds
  match:
    $host, $user over 5m
  outcome:
    $source_ips = array_distinct($auth.principal.ip)
    $effect_events = array_distinct($effect.metadata.product_event_type)
  condition:
    $auth and $effect
}
```

- Re-comparison outcome: The public candidate has moved to Elastic's `_deprecated` folder and addresses a different relay variant; it gives no evidence against the adopted rule.
