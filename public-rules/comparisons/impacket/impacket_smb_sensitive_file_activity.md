# Public-rule comparison: impacket_smb_sensitive_file_activity

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_smb_sensitive_file_activity.yaral`
- Internal SHA-256: `8ef9066a332bc412708b63acfc9fa730d3ebb70fccae57824aeee90a43080a70`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-01,IMP-13`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/network/initial_access_smb_windows_file_sharing_activity_from_the_internet.toml`](../../public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/network/initial_access_smb_windows_file_sharing_activity_from_the_internet.toml) - SHA-256 `30d44b68bd7c830a90c78fcf56c68570e841d86e0340cd2b60ec75cd3b228539`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-01,IMP-13` inventory and cited public rule. |
| remote SMB access to credential-bearing or administrative paths | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Successful read of credential-store file by a non-management source - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Share authorization checks, read/write direction, object sensitivity, and source baseline are conflated.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Successful read of credential-store file by a non-management source | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Share authorization checks, read/write direction, object sensitivity, and source baseline are conflated. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-01/IMP-13, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the proposed standalone rule matches `product_event_type = "5145"` with `security_result.action = "ALLOW"` on any host, but — unlike the existing `impacket_smb_sensitive_file_activity` rule — it drops the `re.regex($e.target.resource.name, ...)` constraint that scopes matches to credential-bearing or administrative paths (`SYSVOL...Groups.xml`, `\SECURITY`, `\SAM`, `\SYSTEM`, `NTDS.dit`, `Microsoft\Protect`, `CCM\`). As written it would match essentially every successful SMB file read in the environment, which is a severe regression in signal quality, not the "close to the sensitive operation" branch the comparison claims — it is a materially broader, noisier standalone rule. It also does not implement any of the branches it claims to add (share authorization checks, read/write direction, object sensitivity, or source baseline); none of those constructs appear in the predicate. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-01,IMP-13`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Share authorization checks, read/write direction, object sensitivity, and source baseline are conflated.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_smb_sensitive_file_activity_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-01,IMP-13"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "5145"
    $e.principal.hostname = $host
    $e.security_result.action = "ALLOW"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.
