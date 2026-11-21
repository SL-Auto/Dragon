# Public-rule comparison: mimikatz_token_process_control

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_token_process_control.yaral`
- Internal SHA-256: `1f2f3c41afee357bd18c39bbc527887fed47a0d148b4264aaf5057ad52938086`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P02,P03,P04,P05`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [SeDebugPrivilege enablement](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_tokenmanip_sedebugpriv_enabled.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `6e8f7a7fb4ce7a4c2dd84b21d8be310b5dfb5a8c3c216bb4d4458e6f9f946735`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| privileges, tokens and process state are enumerated or manipulated | privilege/token/process control correlation | SeDebugPrivilege enablement | SeDebug enablement or token impersonation followed by sensitive process access - strong | privilege enablement alone - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: token duplication/impersonation, target user, result, handle rights and subsequent sensitive access.
- Missing from public rule: complete coverage of `P02,P03,P04,P05` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| SeDebug enablement or token impersonation followed by sensitive process access | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| privilege enablement alone | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

token duplication/impersonation, target user, result, handle rights and subsequent sensitive access. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The public SeDebugPrivilege rule is genuine (`complementary`), but the proposed join depends on fabricated `PRIVILEGE_ENABLE`/`TOKEN_DUPLICATE`/`TOKEN_IMPERSONATE`/`PROCESS_ACCESS`/`CREDENTIAL_STORE_ACCESS` event types and a fabricated `target.resource.attribute.labels["security_sensitive"]` field, none documented in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`. The existing `re.regex($e.security_result.description, ...)` rule already provides equivalent conceptual, recall-favoring coverage of token/process control per the atomic-signal design decision recorded in `reviews/mimikatz/detection-review.md` REVIEW-008, and no validated telemetry mapping exists for the proposed structured fields. Evidence resolved via `coverage/mimikatz.yml` (P02,P03,P04,P05), the canonical rule, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_token_process_control.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: token duplication/impersonation, target user, result, handle rights and subsequent sensitive access.
- Required telemetry: token/privilege operations and sensitive follow-on access tied by stable process entity.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_token_manipulation_to_sensitive_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P02,P03,P04,P05"
  events:
    $t.metadata.product_event_type = /(PRIVILEGE_ENABLE|TOKEN_DUPLICATE|TOKEN_IMPERSONATE)/
    $t.principal.hostname = $host
    $t.principal.process.product_specific_process_id = $pid
    $t.target.resource.attribute.labels["privilege_or_action"] = /(?i)(SeDebugPrivilege|duplicate|impersonate)/
    $a.metadata.product_event_type = /(PROCESS_ACCESS|CREDENTIAL_STORE_ACCESS)/
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $a.target.resource.attribute.labels["security_sensitive"] = "true"
  match:
    $host, $pid over 10m
  outcome:
    $actions = count_distinct($t.target.resource.attribute.labels["privilege_or_action"])
  condition:
    $t and $a
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/privilege_escalation_tokenmanip_sedebugpriv_enabled.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: 12 process-path exclusions were added (dllhost, w3wp, netsh, netstat, RuntimeBroker, taskkill, tasklist under System32 and SysWOW64). This narrows the public rule's privilege-enable branch, which strengthens any `ours_stronger` conclusion on that branch. The comparison conclusions and decision are unaffected.
