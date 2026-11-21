# Public-rule comparison: impacket_sensitive_ldap_search

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_sensitive_ldap_search.yaral`
- Internal SHA-256: `6cba4d140bd1bdae141eedd9f2d688d7e3e950bd63d820deefbb50075d145e5d`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-09`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/discovery_high_number_ad_properties.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/discovery_high_number_ad_properties.toml) - SHA-256 `2a697272b6a7c4d634efc11afad58394b7ef80398bb692aab25ed1123afdc81e`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-09` inventory and cited public rule. |
| LDAP search for credential, delegation, or authorization attributes | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | 1644 sensitive-attribute query by an unusual caller - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Single sensitive filters, result volume, paged searches, and identity baselines are not separately assessed.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 1644 sensitive-attribute query by an unusual caller | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Single sensitive filters, result volume, paged searches, and identity baselines are not separately assessed. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-09, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: `target.resource.attribute.labels["sensitive_ldap_filter"] = "true"` has no defined derivation in `schemas/chronicle-udm.yml` or any canonical rule. The existing `impacket_sensitive_ldap_search` rule already matches the same `1644` event with `re.regex($e.additional.fields["filter"], ...)` against concrete sensitive attributes (`ms-Mcs-AdmPwd`, `msLAPS-Password`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `servicePrincipalName`, `userAccountControl`); the proposal replaces that grounded, inspectable regex with an unresolvable boolean label and adds no new information. It also does not implement the branch it claims to close — "result volume, paged searches, and identity baselines" require cardinality/threshold logic that is absent from the proposed single-event predicate. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-09`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Single sensitive filters, result volume, paged searches, and identity baselines are not separately assessed.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_sensitive_ldap_search_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-09"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "1644"
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["sensitive_ldap_filter"] = "true"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/discovery_high_number_ad_properties.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.
