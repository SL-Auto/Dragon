# Public-rule comparison: mimikatz_directory_network_discovery

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_directory_network_discovery.yaral`
- Internal SHA-256: `18b03eab891413987e552affeb5241884a989f6e6e1d1ffb169462f1ad8a9346`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P30`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Closest public rule examined and rejected as a counterpart: [directory replication-right access](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_dcsync_replication_rights.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `377bfc1f0d8db80de055524492e581dceddb326b4248640258186854f8756c83`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| domain, DC, trust and network topology are enumerated | directory/network discovery breadth | No credible public counterpart in the pinned corpus; the examined directory replication-right access rule is adjacent only and is rejected as a procedure comparator | same process combines DC/trust discovery with sensitive follow-on operation - strong | ordinary LDAP or DNS lookup - weak | insufficient_evidence | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: single-category deep discovery, DNS/SRV queries, trust enumeration and slow activity.
- Missing from public rule: complete coverage of `P30` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| same process combines DC/trust discovery with sensitive follow-on operation | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| ordinary LDAP or DNS lookup | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

No credible public counterpart was found in the pinned corpus. The cited rule was inspected because it is adjacent in the attack chain, but it does not observe the same procedure or security effect and supplies no authority for changing our logic.

## Internal-rule weaknesses

single-category deep discovery, DNS/SRV queries, trust enumeration and slow activity. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: Both matrix rows conclude `insufficient_evidence`; the examined replication-right-access rule was explicitly rejected as a non-comparator. The proposed compensating rule depends on fabricated `LDAP_SEARCH`/`DNS_QUERY`/`DOMAIN_DISCOVERY` event types and `target.resource.attribute.labels["discovery_family"]`/`["security_sensitive"]` fields undocumented anywhere in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`. Evidence resolved via `coverage/mimikatz.yml` (P30) and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_directory_network_discovery.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `insufficient_evidence` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: single-category deep discovery, DNS/SRV queries, trust enumeration and slow activity.
- Required telemetry: process-attributed DNS/LDAP/domain discovery plus sensitive process/directory/registry access.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_domain_discovery_to_sensitive_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P30"
  events:
    $d.metadata.product_event_type = /(LDAP_SEARCH|DNS_QUERY|DOMAIN_DISCOVERY)/
    $d.principal.process.product_specific_process_id = $pid
    $d.target.resource.attribute.labels["discovery_family"] = $family
    $s.metadata.product_event_type = /(PROCESS_OPEN|DIRECTORY_REPLICATION_ACCESS|REGISTRY_READ)/
    $s.principal.process.product_specific_process_id = $pid
    $s.target.resource.attribute.labels["security_sensitive"] = "true"
  match:
    $pid over 30m
  outcome:
    $families = count_distinct($family)
  condition:
    $families >= 2 and $s
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_dcsync_replication_rights.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the new-terms history window grew from 12h to 30h, so the rule alerts on fewer repeat principals; the replication-GUID predicate is identical. The comparison conclusions and decision are unaffected.
