# Public-rule comparison: bloodhound_ldap_directory_discovery_fanout

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_ldap_directory_discovery_fanout.yaral`
- Internal SHA-256: `1832fae8e6508a654846027dc347f20e273fb1aae0a21548bb6d8fbfc9aa618a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-002,BH-004`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic high-volume AD property access rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/discovery_high_number_ad_properties.toml) - pinned revision and SHA-256 `2a697272b6a7c4d634efc11afad58394b7ef80398bb692aab25ed1123afdc81e`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one identity enumerates multiple AD object categories and topology relationships | five normalized object categories in 15 minutes | many distinct AD properties accessed by one process | process-attributed multi-category LDAP searches with sensitive topology attributes - strong | raw query count without category or caller context - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: single-category deep pagination, multi-DC distribution, slow collection, and category-normalization failure.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

1644 is selective and expensive; identity forms and source attribution differ by DC; legitimate identity governance has similar breadth. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed multi-category LDAP searches with sensitive topology attributes | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| raw query count without category or caller context | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

single-category deep pagination, multi-DC distribution, slow collection, and category-normalization failure. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned collector source, provider field semantics and the adversarial review `reviews/bloodhound/detection-review.md` (BH-DR-10 to BH-DR-25).
- Prior state: the proposal was copied into `detections/bloodhound/yaral/bloodhound_ldap_deep_single_category_enumeration.yaral` on 2026-08-16 while this trail still read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow now prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real and worth a compensating rule, but the proposal as written had defects found in adversarial review. The adopted rule diverges as follows:
  - Match window widened from 30m to 4h, because the proposal claimed slow-collection coverage that a 30m window cannot provide (BH-DR-11).
  - Event-type regex anchored; `$domain_controllers` outcome added to show multi-DC distribution.
  - Prerequisites now state that per-result object expansion is mandatory; summary-only 1644/LDAP events are an `accepted_gap` (BH-DR-10).
- Canonical result: `detections/bloodhound/yaral/bloodhound_ldap_deep_single_category_enumeration.yaral`, SHA-256 `76478a1dc5591af5edffbcd983dd547a417cbc85f2c29214578b5bf3a1848709`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: single-category deep pagination, multi-DC distribution, slow collection, and category-normalization failure.
- Required telemetry: LDAP search result cardinality or result-object identifiers, caller identity and naming context.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_ldap_deep_single_category_enumeration {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-002,BH-004"
  events:
    $e.metadata.product_event_type = /(LDAP_SEARCH|1644)/
    $e.principal.user.userid = $user
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["naming_context"] = $nc
    $e.target.resource.attribute.labels["result_object_id"] = $object
  match:
    $host, $user, $nc over 30m
  outcome:
    $objects = count_distinct($object)
  condition:
    $e and $objects >= 500
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Revised rule: `bloodhound_ldap_deep_single_category_enumeration` (SHA-256 `76478a1dc5591af5edffbcd983dd547a417cbc85f2c29214578b5bf3a1848709`), compared on 2026-11-21 with the public candidate(s) re-pinned to the refreshed snapshots: elastic-security `9d792a8f6731542935156db61eaba88bf337e819`, chronicle-community `dbc9beb79597b519be086fce082214494d75b6a8`. Between revisions, the existing candidates changed only in metadata tags or path, with no query-logic change.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Single-category deep pagination | covered when per-result identity exists | high-property-count process rule | distinct result objects per host/user/NC - strong when expansion exists | category fanout rule - moderate | complementary | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Throttled or slow collection (<500 objects per 30m) | covered up to 4h | not covered | 4h distinct-object volume - moderate | recurrence rule - moderate | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Summary-only LDAP telemetry | not covered (accepted_gap BH-DR-10) | covered where Windows 4662 property access is enabled | 4662 property-access breadth - moderate | category fanout - moderate | public_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule bloodhound_ldap_deep_single_category_enumeration {
  meta:
    author = "Detection Research Agent"
    description = "Detects a single identity on one client host retrieving a high volume of distinct directory objects within one naming context over a four-hour window, compensating for single-category or throttled collection that stays under the multi-category fanout threshold of bloodhound_ldap_directory_discovery_fanout."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "High-volume single-category object enumeration still exposes bulk directory data suitable for attack-path analysis even without category diversity."
    procedure_ids = "BH-002,BH-004"
    log_source_prerequisites = "Directory-side or EDR LDAP_SEARCH/1644 events expanded to per-result object identity (result_object_id label), with client host, account and naming context; summary-only query events cannot satisfy this rule (see reviews/bloodhound/detection-review.md#bh-dr-10)."
    false_positives = "Identity governance, directory synchronization, migration tooling and authorized security assessment performing bulk single-category export."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_ldap_directory_discovery_fanout.md, reviews/bloodhound/detection-review.md#bh-dr-10"
    validation_status = "needs_validation"
    validation_method = "Test single-purpose bulk-export tooling and sanitized deep single-category enumeration fixtures, including throttled delivery spread across four hours and across multiple domain controllers."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = /^(LDAP_SEARCH|1644)$/
    $e.principal.user.userid = $user
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["naming_context"] = $nc
    $e.target.resource.attribute.labels["result_object_id"] = $object
  match:
    $host, $user, $nc over 4h
  outcome:
    $objects = count_distinct($object)
    $domain_controllers = array_distinct($e.target.hostname)
  condition:
    $e and $objects >= 500
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. The remaining gaps are the accepted gaps listed in the detection review, each with a named compensating rule. No further change is proposed from this comparison.
