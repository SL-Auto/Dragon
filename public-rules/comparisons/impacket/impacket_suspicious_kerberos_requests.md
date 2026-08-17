# Public-rule comparison: impacket_suspicious_kerberos_requests

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_suspicious_kerberos_requests.yaral`
- Internal SHA-256: `fd694c6c9ac3071d9dc5098bc06ded27202e96e15c97d6b458aba380672750e9`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-11`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml`](../../public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml) - SHA-256 `3e78aa4fae6e9c216368f412c301512c30698baffaec39a9da33f6f3c47c35d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-11` inventory and cited public rule. |
| uncommon or high-volume AS/TGS request behavior | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Risky ticket properties or rare requester-to-service relationship - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: A count-only threshold misses targeted single requests and does not inspect encryption, options, preauthentication, SPN or outcome.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Risky ticket properties or rare requester-to-service relationship | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

A count-only threshold misses targeted single requests and does not inspect encryption, options, preauthentication, SPN or outcome. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-11, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: `$a.target.resource.attribute.labels["kerberos_request_risk"] = "high"` and the `$b.metadata.event_type = "STATUS_UPDATE"` / `$b.target.resource.attribute.labels["sensitive_effect"] = "true"` join are both undefined anywhere in `schemas/chronicle-udm.yml` or the 20 canonical rules; `$b` can never bind to a real event so the two-event condition is permanently false. The named gap ("does not inspect encryption, options, preauthentication, SPN or outcome") is real, but the proposal does not inspect any of those fields either — it substitutes an unresolvable risk label rather than concrete ticket-option predicates (e.g. `security_result.detection_fields` for encryption type or preauth flags), so it does not close the gap it names. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-11`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: A count-only threshold misses targeted single requests and does not inspect encryption, options, preauthentication, SPN or outcome.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_suspicious_kerberos_requests_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-11"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = /(4768|4769|4771)/
    $a.principal.hostname = $host
    $a.target.resource.attribute.labels["kerberos_request_risk"] = "high"
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
