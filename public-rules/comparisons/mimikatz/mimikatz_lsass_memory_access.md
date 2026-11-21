# Public-rule comparison: mimikatz_lsass_memory_access

## Identity and independence gate

- Internal tool: `mimikatz`
- Internal canonical rule: `detections/mimikatz/yaral/mimikatz_lsass_memory_access.yaral`
- Internal SHA-256: `377dd7ac7c08e3bf0e66bb0b28149eab7f36f4cc5141035c98321396f048ab67`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `P07,P09,P13`
- Scope mapping rationale: mapped by security effect, ordered procedure and required telemetry; names and syntax were not mapping criteria.

Public evidence:
- Behaviorally relevant public candidate: [LSASS OpenProcess API access](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_lsass_openprocess_api.toml) - pinned Elastic revision `7e91c156324cdc64cda27f7fec7067b1148074ef`; SHA-256 `708a6e458747459ce31e73de4812ae0e2f57b05dd7bacc4ed899af13aa97bd1d`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| LSASS is opened/read/dumped or modified for credentials/authentication state | LSASS handle/API access and access rights | OpenProcess API access with suspicious caller/access | untrusted caller obtains read/write access to LSASS with result and call stack - strong | PROCESS_OPEN without granted access/result - weak | complementary | Canonical rule, pinned candidate, `coverage/mimikatz.yml` and pinned source report. |
| Same effect split across processes, hosts or windows | Current joins/thresholds may fail | Public candidate is also bounded by its source | stable entity plus resulting security effect - moderate | longer-window rare relationship - moderate | insufficient_evidence | Analytical inference requiring local telemetry testing. |

## Missing detection branches

- Missing from ours: direct syscalls, PPL bypass, cloned/snapshot LSASS, read versus write distinction and downstream dump/use.
- Missing from public rule: complete coverage of `P07,P09,P13` and alternate implementations outside its telemetry assumptions.
- Missing from both: intent attribution and reliable detection when the necessary provider is disabled or fields are dropped.

## Detection edge cases and blind spots

Low-and-slow and distributed activity may fall outside fixed windows. Identity, process and host entities can change representation between providers. Collection loss can suppress cardinality or break ordering. Legitimate administration and security products require evidence-based trust enrichment rather than path-only exclusions.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| untrusted caller obtains read/write access to LSASS with result and call stack | strong | proposed/internal | Close to the security effect and incorporates caller/result context. | Requires detailed provider fields and local baselining. |
| procedure-specific correlation | moderate | ours | Adds ordered context but depends on stable joins and windows. | Partial telemetry creates false negatives. |
| PROCESS_OPEN without granted access/result | weak | public/current branch | Useful triage lead but insufficient proof by itself. | Common, mutable or implementation-specific. |

## Public-rule weaknesses

The public candidate is a scoped compensating signal, not a full Mimikatz procedure model. Its fixed field assumptions and implementation focus can miss the same effect produced through a different API or telemetry path.

## Internal-rule weaknesses

direct syscalls, PPL bypass, cloned/snapshot LSASS, read versus write distinction and downstream dump/use. Existing thresholds and normalized fields remain unvalidated hypotheses and require collection-health monitoring.

## Decision trail

- Candidate improvement: independently implement and validate the missing branch below; no upstream predicate is copied blindly.
- Independent verification: pinned source behavior, provider semantics, sanitized fixtures, benign baselines and adversarial detection review.
- Decision: `reject`.
- Reason: The public LSASS OpenProcess rule is genuine (`complementary`), but the existing canonical rule already checks the granted-access distinction the proposal targets via `re.regex($e.security_result.description, "(0x0*10|PROCESS_VM_READ|VM_READ)")`. The proposed rewrite substitutes a fabricated `target.process.attribute.labels["granted_access"]` structured field and a fabricated `principal.process.file.labels["trusted_lsass_accessor"]` field, neither documented in `schemas/chronicle-udm.yml` or `telemetry/mimikatz.md`, for a join that adds no discriminating power over the existing single-event check. The remaining gaps (direct syscalls, PPL bypass, cloned/snapshot LSASS) are evasion-adjacent and already recorded as `accepted_gap` in `reviews/mimikatz/detection-review.md` REVIEW-007/REVIEW-009; AGENTS.md prohibits documenting operational evasion detail, so they cannot be closed by this proposal or a substitute. Evidence resolved via `coverage/mimikatz.yml` (P07,P09,P13), the canonical rule, and the detection review.
- Regeneration performed: none. The canonical rule `detections/mimikatz/yaral/mimikatz_lsass_memory_access.yaral`, coverage, telemetry and translations are unchanged; only this comparison's decision trail was updated.

## Unmatched scope

The candidate does not cover every procedure branch. Conclusions are branch-scoped as `complementary` or `insufficient_evidence`; neither rule is claimed globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: direct syscalls, PPL bypass, cloned/snapshot LSASS, read versus write distinction and downstream dump/use.
- Required telemetry: EDR process access with granted rights, success, source/target process entity, signer and call-stack/trust enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule mimikatz_lsass_sensitive_granted_access {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "P07,P09,P13"
  events:
    $e.metadata.product_event_type = /(PROCESS_OPEN|PROCESS_ACCESS)/
    $e.target.process.file.full_path = /(?i)\\lsass\.exe$/
    $e.principal.process.file.labels["trusted_lsass_accessor"] = "false"
    $e.security_result.action = "ALLOW"
    $e.target.process.attribute.labels["granted_access"] = /(?i)(VM_READ|VM_WRITE|VM_OPERATION|CREATE_THREAD)/
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 5m
  outcome:
    $rights = count_distinct($e.target.process.attribute.labels["granted_access"])
  condition:
    $e and $rights >= 1
}
```

Remaining gaps: thresholds, fields, ordering and trust enrichment need authorized telemetry validation; absence of required collection cannot be interpreted as benign activity.

If accepted or modified, update canonical YARA-L and every downstream artifact, re-run adversarial review, and compare the revised final rule again.

## Snapshot refresh (2026-11-21)

- Candidate links re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`. The decision trail above is unchanged.
- `rules/windows/credential_access_lsass_openprocess_api.toml` changed between 7e91c15 and 9d792a8; re-read on 2026-11-21: the ES|QL now uses `mv_contains(event.category, "api")` and `host.os.type` and needs stack 9.4; the semantics are equivalent. The comparison conclusions and decision are unaffected.
