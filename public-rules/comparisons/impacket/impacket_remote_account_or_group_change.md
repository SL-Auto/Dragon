# Public-rule comparison: impacket_remote_account_or_group_change

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_remote_account_or_group_change.yaral`
- Internal SHA-256: `1269cf9dbdd73d9e5041e8ffd220a0403a8d664a534516a721d076e3805dd86e`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-07`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/Persistence/LocalAdminGroupChanges.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/Persistence/LocalAdminGroupChanges.yaml) - SHA-256 `a69b713c78006b4acf935295e2ec0dfc61c3fe36fcd2fdbbb8e3f1177c24e359`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-07` inventory and cited public rule. |
| remote account, computer, or group membership mutation | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Privileged membership change with actor/source attribution - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: The rule does not distinguish privileged groups, created-then-deleted accounts, or bind the change to a remote logon.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Privileged membership change with actor/source attribution | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

The rule does not distinguish privileged groups, created-then-deleted accounts, or bind the change to a remote logon. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-07, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the proposed predicate `target.group.attribute.labels["privileged"] = "true"` has no defined derivation anywhere in `schemas/chronicle-udm.yml` or the 20 canonical rules — no privileged-group membership list or lookup is established by any cited evidence, so this label would never be populated by a real parser. The proposal also narrows rather than extends observability: it drops most of the existing rule's event family (it keeps only 4728/4732/4756 of the existing `/(4720|4722|4723|4724|4725|4726|4738|4741|4742|4743|4728|4729|4732|4733|4756|4757)/` set) while adding an unresolvable label filter, so as written it would match strictly fewer real events than today, not more. It also does not implement the claimed "bind the change to a remote logon" branch — there is no join to a 4624 or other logon event. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-07`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: The rule does not distinguish privileged groups, created-then-deleted accounts, or bind the change to a remote logon.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_remote_account_or_group_change_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-07"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(4728|4732|4756)/
    $e.principal.hostname = $host
    $e.target.group.attribute.labels["privileged"] = "true"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- No referenced candidate changed content.
