# Public-rule comparison: impacket_ad_authorization_change

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_ad_authorization_change.yaral`
- Internal SHA-256: `b055926dc484d138e9025e1386bf7e210ff2c418424721e4e7a692874c094d98`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-10`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate assessment:
- No credible public counterpart was found in the pinned corpus for this exact procedure branch. Public coverage is `insufficient_evidence`; adjacent account, SMB, or service rules are not treated as equivalents.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | No credible pinned public counterpart | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | insufficient_evidence | Internal `IMP-10` inventory and pinned-corpus search. |
| security-descriptor, ownership, delegation and dMSA authorization mutation | Canonical rule covers the principal event family | No credible pinned public counterpart | 5136/5137 on a protected object with a security-sensitive attribute - strong | Process, network-session, and resulting-object correlation - moderate | insufficient_evidence | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | No credible pinned public counterpart | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | insufficient_evidence | No public rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Attribute-specific before/after interpretation and correlation to the initiating network session.
- Missing from the pinned public corpus: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 5136/5137 on a protected object with a security-sensitive attribute | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

No behaviorally credible public counterpart was identified. An adjacent account-lifecycle, SMB-ingress, or service rule would not establish this procedure, so public coverage is `insufficient_evidence` and no external predicate is proposed for adoption.

## Internal-rule weaknesses

Attribute-specific before/after interpretation and correlation to the initiating network session. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-10, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the 20 existing canonical rules under `detections/impacket/yaral/`.
- Decision: `reject`
- Reason: the proposed predicate `target.resource.attribute.labels["sensitive_ad_attribute"] = "true"` has no defined derivation anywhere in `schemas/chronicle-udm.yml` (whose declared `identity_fields` do not include any such enrichment label) or in any of the 20 existing canonical rules, none of which populate or depend on a boolean `sensitive_ad_attribute` label. No parser mapping, enrichment pipeline, or precedent for this field is established by any cited evidence, so the rule as written would either silently never match (false operational confidence) or require an unscoped enrichment step this comparison never specifies. The proposal also does not implement the branch it claims to close: it adds no before/after attribute-value comparison and no join to an initiating network-logon session, which is exactly the gap `Internal-rule weaknesses` describes. The existing rule's `re.regex($e.target.resource.attribute.labels["attribute"], ...)` against real attribute names (`nTSecurityDescriptor`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-ManagedAccountPrecededByLink`, `msDS-DelegatedMSAState`) already covers the same 5136/5137 event family with a grounded predicate; the proposal adds no verifiable new coverage. Canonical rule is unchanged.

## Unmatched scope

No credible public counterpart was identified for `IMP-10`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Attribute-specific before/after interpretation and correlation to the initiating network session.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_ad_authorization_change_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-10"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(5136|5137)/
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["sensitive_ad_attribute"] = "true"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.
