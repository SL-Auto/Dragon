# Public-rule comparison: bloodhound_sensitive_directory_attribute_reads

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_sensitive_directory_attribute_reads.yaral`
- Internal SHA-256: `bd7ae5a1f88b883690054912bc562d22b2bb489d5fc05d5a25747cc311fb33a6`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-003,BH-005`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Elastic high-volume AD property access rule](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/discovery_high_number_ad_properties.toml) - pinned revision and SHA-256 `2a697272b6a7c4d634efc11afad58394b7ef80398bb692aab25ed1123afdc81e`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| LDAP reads request security descriptors or AD CS relationship attributes | single requested-attribute match | unusually high number of AD properties | caller-attributed LDAP control/attribute request for security descriptors or certificate topology - strong | a lone 4662 without operation/property resolution - weak | ours_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: control-only security-descriptor reads, attribute aliases, and low-volume targeted reads.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

4662 usually records access rather than the full LDAP projection; requested-attribute fields require uncommon directory or EDR instrumentation. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| caller-attributed LDAP control/attribute request for security descriptors or certificate topology | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| a lone 4662 without operation/property resolution | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

control-only security-descriptor reads, attribute aliases, and low-volume targeted reads. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/bloodhound/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had been copied, with divergences, into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The adoption alerts per event rather than the proposal's at least 10 objects per user, which closes the targeted low-volume branch at the cost of benign volume from directory tools. It adds 4662.
- Canonical result: `detections/bloodhound/yaral/bloodhound_sensitive_directory_attribute_reads.yaral`, SHA-256 `22731dca59be7028bbe691704f90c62cf9c699ad7538e560ca2fc71fd15d4355`.
- Regeneration: the 2026-08-16 adoption's translations, telemetry and hashes were re-verified current on 2026-11-21; no canonical change in this run.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: control-only security-descriptor reads, attribute aliases, and low-volume targeted reads.
- Required telemetry: LDAP requested attributes and controls, resolved target object, and caller identity.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_sensitive_directory_relationship_reads {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-003,BH-005"
  events:
    $e.metadata.product_event_type = /(LDAP_SEARCH|1644)/
    $e.principal.user.userid = $user
    ($e.target.resource.attribute.labels["sd_flags_control"] = "true" or re.regex($e.target.resource.attribute.labels["requested_attributes"], `(?i)(nTSecurityDescriptor|msPKI-|pKIEnrollmentService|certificateTemplates)`))
    $e.target.resource.name = $object
  match:
    $user over 20m
  outcome:
    $objects = count_distinct($object)
  condition:
    $e and $objects >= 10
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/discovery_high_number_ad_properties.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Security-descriptor or PKI attribute reads | covered per event | `discovery_high_number_ad_properties.toml`: 4662 reads of many attributes | SD-flags control or PKI attributes - moderate | public attribute-volume rule - moderate | complementary |
| High attribute-count reads without sensitive attributes | not covered | covered | attribute volume - weak | LDAP fan-out rule - moderate | public_stronger |

- Current canonical YARA-L `detections/bloodhound/yaral/bloodhound_sensitive_directory_attribute_reads.yaral` (`experimental` / `needs_validation`):

```yaral
rule bloodhound_sensitive_directory_attribute_reads {
  meta:
    author = "Detection Research Agent"
    description = "Detects LDAP searches requesting security descriptors (by named attribute or SD_FLAGS control) or AD CS relationship attributes."
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Security descriptor and PKI relationship reads are high-value attack-path discovery signals."
    procedure_ids = "BH-003,BH-005"
    log_source_prerequisites = "LDAP query telemetry containing requested attributes or controls (including SD_FLAGS control usage), source identity/process and naming context."
    false_positives = "Directory permissions auditing, PKI administration and identity governance."
    references = "reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_sensitive_directory_attribute_reads.md"
    validation_status = "needs_validation"
    validation_method = "Use sanitized LDAP query records with and without sensitive attributes or SD_FLAGS control usage."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = /(LDAP_SEARCH|1644|4662)/
    ($e.target.resource.attribute.labels["sd_flags_control"] = "true" or re.regex($e.target.resource.attribute.labels["requested_attributes"], `(?i)(ntsecuritydescriptor|pkienrollmentservice|pkicertificatetemplate|msPKI-|certificateTemplates)`))
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule closes the branch the proposal targeted, within declared telemetry; remaining gaps are recorded in `reviews/bloodhound/detection-review.md`.
