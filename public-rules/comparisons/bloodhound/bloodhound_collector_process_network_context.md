# Public-rule comparison: bloodhound_collector_process_network_context

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_collector_process_network_context.yaral`
- Internal SHA-256: `41b68e8a22f6baba8eb54e87f010ef0a83a130c44ab9267f6ac1bc5e7b962dd5`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-001`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic BloodHound user-agent detection](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_bloodhound_user_agents_detected.toml) - pinned revision and SHA-256 `23a2c98500bd2c50247d9d802f3681598a9844e77779b0c82682d5a85773826c`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| collector process starts and establishes directory or cloud-management connections | rare process plus five process-attributed LDAP/Graph/ARM connections | high-volume AD property access, without process/network sequence | process-attributed sensitive-service connection followed by confirmed enumeration - strong | rare executable path alone - weak | complementary | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Process paths are mutable, prevalence can lag, NAT can blur cloud sources, and process/network joins may break across sensors. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed sensitive-service connection followed by confirmed enumeration | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| rare executable path alone | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned collector source, provider field semantics and the adversarial review `reviews/bloodhound/detection-review.md` (BH-DR-10 to BH-DR-25).
- Prior state: the proposal was copied into `detections/bloodhound/yaral/bloodhound_process_to_directory_effect.yaral` on 2026-08-16 while this trail still read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow now prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real and worth a compensating rule, but the proposal as written had defects found in adversarial review. The adopted rule diverges as follows:
  - Removed the PROCESS_LAUNCH join, because it excluded collectors started earlier or hosted in long-lived processes — the branch the proposal was meant to close (BH-DR-18).
  - Removed the Graph/ARM branches, because cloud audit logs carry no endpoint PID and could never join (BH-DR-17).
  - Fixed an uncompilable condition: `$q` had not been referenced (BH-DR-16, blocker).
  - Window widened from 20m to 30m; process path and account kept as outcomes.
- Canonical result: `detections/bloodhound/yaral/bloodhound_process_to_directory_effect.yaral`, SHA-256 `14892613f472f068979cc0b750456a992fe827008455317d7d7ecd9718be801a`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `complementary` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: signed-but-new collectors; common host processes loading collector code; single-protocol or slow activity.
- Required telemetry: stable process entity on process launch and LDAP/Graph/ARM read events.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_process_to_directory_effect {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-001"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.hostname = $host
    $p.target.process.product_specific_process_id = $pid
    $q.metadata.product_event_type = /(LDAP_SEARCH|MicrosoftGraphActivityLogs|AZURE_RESOURCE_READ)/
    $q.principal.hostname = $host
    $q.principal.process.product_specific_process_id = $pid
    $q.target.resource.name = $object
  match:
    $host, $pid over 20m
  outcome:
    $objects = count_distinct($object)
  condition:
    $p and $objects >= 25
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Revised rule: `bloodhound_process_to_directory_effect` (SHA-256 `14892613f472f068979cc0b750456a992fe827008455317d7d7ecd9718be801a`), compared on 2026-11-21 with the public candidate(s) re-pinned to the refreshed snapshots: elastic-security `9d792a8f6731542935156db61eaba88bf337e819`, chronicle-community `dbc9beb79597b519be086fce082214494d75b6a8`. Between revisions, the existing candidates changed only in metadata tags or path, with no query-logic change.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Signed or prevalent collector, or collector code inside a long-lived host process | covered via per-process distinct LDAP objects | covered only when the AzureHound user agent is present (cloud only) | process-attributed LDAP object breadth - strong | process network context rule - moderate | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Cloud-only collection from a workstation | not covered by this rule (accepted_gap BH-DR-17) | user-agent rule covers default AzureHound UA | process-attributed Graph/ARM connections - moderate | cloud collection output rule - moderate | complementary | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Renamed or forged user agent | unaffected (behavioral) | not covered | object breadth - strong | none | ours_stronger | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule bloodhound_process_to_directory_effect {
  meta:
    author = "Detection Research Agent"
    description = "Detects one endpoint process entity issuing LDAP searches against many distinct directory objects or search bases, independent of process prevalence, signer, executable path or a preceding launch event, compensating for bloodhound_collector_process_network_context's dependence on rarity and connection count."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Process-attributed object-level directory enumeration is a stronger effect signal than connection count and survives signed, prevalent or long-lived host processes, but overlaps legitimate identity and management tooling."
    procedure_ids = "BH-001"
    log_source_prerequisites = "Endpoint-attributed LDAP_SEARCH telemetry (EDR LDAP query events) with host, stable process entity identifier, process path, account, and search base DN or per-result object identity normalized to target.resource.name. Cloud audit logs are not process-attributed and are out of scope for this rule."
    false_positives = "Identity inventory, endpoint management, directory administration consoles, backup and migration tooling, including signed and prevalent software; domain-joined services resolving many group or SID references."
    references = "reports/bloodhound/source-analysis.md#bh-001, public-rules/comparisons/bloodhound/bloodhound_collector_process_network_context.md, reviews/bloodhound/detection-review.md#bh-dr-16"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized EDR LDAP fixtures for a newly launched process, a long-running process, and approved directory tooling at the 25-object boundary; confirm PID-reuse handling with the vendor's stable process entity identifier."
    review_status = "reviewed"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $q.metadata.product_event_type = /^LDAP_SEARCH$/
    $q.principal.hostname = $host
    $q.principal.process.product_specific_process_id = $process
    $q.target.resource.name = $object
  match:
    $host, $process over 30m
  outcome:
    $objects = count_distinct($object)
    $process_paths = array_distinct($q.principal.process.file.full_path)
    $accounts = array_distinct($q.principal.user.userid)
  condition:
    $q and $objects >= 25
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. The remaining gaps are the accepted gaps listed in the detection review, each with a named compensating rule. No further change is proposed from this comparison.
