# Public-rule comparison: bloodhound_recurrent_collection_activity

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_recurrent_collection_activity.yaral`
- Internal SHA-256: `2bbaf30528c1bf35b6f43ee4463b29864f79f0dc0071e1656ffaf75d4d41185e`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-014`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic high-volume AD property access rule](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/discovery_high_number_ad_properties.toml) - pinned revision and SHA-256 `260d763e6cc776634fb023e536f32c6fdd6b4cb8ce889726aa0b16cb2c41aa95`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| the same collector entity repeats directory or host-enumeration bursts | 100 events and five targets within one four-hour bucket | point-in-time AD property threshold only | two or more independently suspicious collection bursts tied to stable signer/user/host identity - strong | large four-hour raw event count - weak | public_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: separate burst detection, recurrence across process restarts, host/user correlation, jitter spanning windows and cloud activity.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

A flat event count does not prove recurrence and PID reuse can correlate unrelated activity. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| two or more independently suspicious collection bursts tied to stable signer/user/host identity | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| large four-hour raw event count | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

separate burst detection, recurrence across process restarts, host/user correlation, jitter spanning windows and cloud activity. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `public_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: separate burst detection, recurrence across process restarts, host/user correlation, jitter spanning windows and cloud activity.
- Required telemetry: upstream normalized collection-burst detections with stable host/user identity and unique burst ID.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_recurrent_collection_bursts {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-014"
  events:
    $e.metadata.product_event_type = "DETECTION"
    $e.about.labels["detection_family"] = /(?i)bloodhound_collection_burst/
    $e.principal.hostname = $host
    $e.principal.user.userid = $user
    $e.metadata.id = $burst
  match:
    $host, $user over 24h
  outcome:
    $bursts = count_distinct($burst)
  condition:
    $e and $bursts >= 2
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
