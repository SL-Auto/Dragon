# Public-rule comparison: impacket_unusual_service_authentication

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_unusual_service_authentication.yaral`
- Internal SHA-256: `e7acc902acfabcc541a59d0911bb78b549b914195ecf3ec0c17c4e37293dec5b`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-15`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate assessment:
- No credible public counterpart was found in the pinned corpus for this exact procedure branch. Public coverage is `insufficient_evidence`; adjacent account, SMB, or service rules are not treated as equivalents.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | No credible pinned public counterpart | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | insufficient_evidence | Internal `IMP-15` inventory and cited public rule. |
| failed or unusual authentication to SQL, MQTT, RDP, or SMB | Canonical rule covers the principal event family | No credible pinned public counterpart | Successful authentication on a first-seen account-service-host relationship - strong | Process, network-session, and resulting-object correlation - moderate | insufficient_evidence | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | No credible pinned public counterpart | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | insufficient_evidence | No public rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Ten failures is generic and misses successful first-seen protocol/account pairs and distributed attempts.
- Missing from the pinned public corpus: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Successful authentication on a first-seen account-service-host relationship | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

No behaviorally credible public counterpart was identified. An adjacent account-lifecycle, SMB-ingress, or service rule would not establish this procedure, so public coverage is `insufficient_evidence` and no external predicate is proposed for adoption.

## Internal-rule weaknesses

Ten failures is generic and misses successful first-seen protocol/account pairs and distributed attempts. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-15, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: `$e.metadata.product_event_type = "AUTHENTICATION"` is not a value produced by any cited parser and does not appear in `schemas/chronicle-udm.yml` or the 20 canonical rules; the existing rule instead uses the grounded generic `metadata.event_type = "USER_LOGIN"`. As written the predicate would not match real telemetry. The proposal also does not implement the branch it claims ("misses successful first-seen protocol/account pairs") — there is no first-seen/baseline construct, just a bare `ALLOW` filter with a dedup window, which by itself would be indistinguishable from ordinary successful authentication across the estate. Canonical rule is unchanged.

## Unmatched scope

No credible public counterpart was identified for `IMP-15`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Ten failures is generic and misses successful first-seen protocol/account pairs and distributed attempts.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_unusual_service_authentication_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-15"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "AUTHENTICATION"
    $e.principal.hostname = $host
    $e.security_result.action = "ALLOW"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.
