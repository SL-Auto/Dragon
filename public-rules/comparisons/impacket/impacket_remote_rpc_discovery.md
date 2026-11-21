# Public-rule comparison: impacket_remote_rpc_discovery

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_remote_rpc_discovery.yaral`
- Internal SHA-256: `3f6688c38d2dd7d3c07dd16845558a34f05d79359250809501868d36eb14f123`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-08,IMP-16`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/initial_access_rpc_remote_procedure_call_from_the_internet.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/network/initial_access_rpc_remote_procedure_call_from_the_internet.toml) - SHA-256 `94b480a85b0dbeca709ba453008e7e01e786390ed6275786d0eb1e9fa13f6265`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-08,IMP-16` inventory and cited public rule. |
| remote RPC endpoint/interface discovery | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | First-seen source invoking a sensitive RPC interface UUID - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: A fixed count ignores rare sensitive interfaces, distributed discovery, and per-host baselines.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| First-seen source invoking a sensitive RPC interface UUID | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

A fixed count ignores rare sensitive interfaces, distributed discovery, and per-host baselines. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently add the strong branch below, retaining the existing rule until sanitized telemetry proves whether a split or replacement is appropriate.
- Independent verification: performed against pinned Impacket source analysis (`coverage/impacket.yml` IMP-08/IMP-16, `reports/impacket/source-analysis.md`), `schemas/chronicle-udm.yml`, and the existing canonical rule.
- Decision: `reject`
- Reason: the proposal sets `$e.metadata.product_event_type = "RPC_CALL"`. This value is not produced by any cited parser and appears nowhere in `schemas/chronicle-udm.yml` or the 20 canonical rules; the existing rule instead uses the grounded generic `metadata.event_type = "NETWORK_CONNECTION"` with `target.port = /(135|445)/`. The companion predicate `target.resource.attribute.labels["sensitive_rpc_interface"] = "true"` is likewise undefined — no interface-UUID-to-sensitivity mapping is established anywhere in this repository. As written the rule would never match real telemetry. The claimed gap ("a fixed count ignores rare sensitive interfaces, distributed discovery, and per-host baselines") is a legitimate design critique of the existing `#e > 20` threshold, but this proposal does not implement interface-UUID decoding, baselining, or distributed-source correlation — it only wraps an unmatchable predicate in a single-event dedup window. Canonical rule is unchanged.

## Unmatched scope

The public candidate does not cover all of `IMP-08,IMP-16`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: A fixed count ignores rare sensitive interfaces, distributed discovery, and per-host baselines.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_remote_rpc_discovery_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-08,IMP-16"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "RPC_CALL"
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["sensitive_rpc_interface"] = "true"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/network/initial_access_rpc_remote_procedure_call_from_the_internet.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: Fortinet FortiGate was added as a data source; the internet-to-internal RPC predicate is unchanged in scope. The comparison conclusions and decision are unaffected.
