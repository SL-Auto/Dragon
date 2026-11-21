# Public-rule comparison: impacket_packet_capture_or_raw_socket

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_packet_capture_or_raw_socket.yaral`
- Internal SHA-256: `c2d9e461b861cbaecbcb721cf3b9944d7428797aace64c37fc0f2dcdeac44cfc`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-19`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_network_full_network_packet_capture_detected.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/credential_access_network_full_network_packet_capture_detected.toml) - SHA-256 `bcd3098157af89929a75f40da581af84546f3303d7fafaa0e2501dda51383724`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-19` inventory and cited public rule. |
| packet-capture driver, raw socket, or capture API activation | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Unexpected capture driver load by an unapproved process - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Kernel driver load, capture-filter creation, and process attribution are not separate branches.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Unexpected capture driver load by an unapproved process | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Kernel driver load, capture-filter creation, and process attribution are not separate branches. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-19, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the proposal writes `$e.metadata.product_event_type = /(6|DRIVER_LOAD|NETWORK_CAPTURE_STARTED)/`, mixing raw vendor event-ID values (the existing rule's own convention for `product_event_type`, e.g. `"5145"`, `/(7045|4697)/` elsewhere in this rule set) with generic constant-style strings. `DRIVER_LOAD` is the existing rule's `metadata.event_type` value, not a `product_event_type` value, and `NETWORK_CAPTURE_STARTED` is not a value used anywhere in `schemas/chronicle-udm.yml` or any of the 20 canonical rules — it has no defined parser mapping. The predicate as written targets the wrong field for two of its three alternatives and would not match real telemetry. The claimed missing branches ("Kernel driver load, capture-filter creation, and process attribution") are also not implemented by the code: there is no capture-filter object reference and no process-attribution join beyond the host. The existing rule's `$e.metadata.event_type = /(PROCESS_LAUNCH|DRIVER_LOAD|NETWORK_CONNECTION)/` combined with a description regex over `security_result.description` already covers the same driver-load/raw-socket family with grounded fields. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-19`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Kernel driver load, capture-filter creation, and process attribution are not separate branches.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_packet_capture_or_raw_socket_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-19"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = /(6|DRIVER_LOAD|NETWORK_CAPTURE_STARTED)/
    $e.principal.hostname = $host
    $e.target.file.full_path = /(?i)(npcap|npf|packet)/
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/integrations/azure/credential_access_network_full_network_packet_capture_detected.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: only the tags block was restructured; the query is identical. The comparison conclusions and decision are unaffected.
