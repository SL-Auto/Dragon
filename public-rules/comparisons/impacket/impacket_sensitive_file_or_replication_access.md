# Public-rule comparison: impacket_sensitive_file_or_replication_access

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_sensitive_file_or_replication_access.yaral`
- Internal SHA-256: `a3fc4b235440d6416cb25958d0d474ab341c4fdccfd8dd9568a8b40ac0e68e14`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-13`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Windows Security Events/Analytic Rules/NonDCActiveDirectoryReplication.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Windows Security Events/Analytic Rules/NonDCActiveDirectoryReplication.yaml) - SHA-256 `48d83e06b41062488ccaa3369ecd08bd89e0158ed533d4b34e6dce25c0d8c1f9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-13` inventory and cited public rule. |
| directory replication rights use or credential-store file access | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | 4662 replication extended right by a non-DC principal - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: Replication and file access are materially different signals and should not share one broad predicate.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4662 replication extended right by a non-DC principal | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

Replication and file access are materially different signals and should not share one broad predicate. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/impacket/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the 2026-08-16 split had removed 4662 from the rule without adding the replication rule the proposal described.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The split is adopted, but the replication branch it removed is restored as new `impacket_directory_replication_rights_use` (REVIEW-013, blocker resolved in this run).
  - The proposal's `replication_extended_right` label is replaced by the documented 4662 property GUIDs and names, and an approved-replication-principal enrichment that fails open is added. Machine accounts are not excluded.
  - The Sentinel candidate link was moved from a migration stub to its new location under `Solutions/Windows Security Events/`.
- Canonical result: `detections/impacket/yaral/impacket_sensitive_file_or_replication_access.yaral`, SHA-256 `3f63a43e5e1a825f4a623bb36e8f4c2e692b5cef45382b64989155a94448ea94`.
- Canonical result: `detections/impacket/yaral/impacket_directory_replication_rights_use.yaral`, SHA-256 `6a3cc33e2a97cd345f04f4383cd3ebcd1ac17d1ef660829fd40448d56178a82a`.
- Regeneration: new canonical rule on 2026-11-21; detection review, coverage, `telemetry/impacket.md`, `telemetry/MASTER.md` (new 4741 row and counts), native translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The public candidate does not cover all of `IMP-13`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: Replication and file access are materially different signals and should not share one broad predicate.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_sensitive_file_or_replication_access_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-13"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "4662"
    $e.principal.hostname = $host
    $e.target.resource.attribute.labels["replication_extended_right"] = "true"
  match:
    $host over 15m
  condition:
    $e
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Replication rights used by a non-approved principal | covered by `impacket_directory_replication_rights_use` | `NonDCActiveDirectoryReplication.yaml`: 4662 replication GUIDs where AccountType is not Machine | 4662 replication GUID - strong | NDR DRSUAPI from non-DC - moderate | complementary |
| Replication through a compromised machine account | covered (no `$` exclusion) | not covered (machine accounts excluded) | 4662 + approval enrichment - strong | none | ours_stronger |
| Remote SAM/SECURITY hive or NTDS.dit file access | covered by base file rule (5145/4663) | not covered | object path - moderate | EDR file read - moderate | ours_stronger |

- Current canonical YARA-L `detections/impacket/yaral/impacket_sensitive_file_or_replication_access.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_sensitive_file_or_replication_access {
 meta:
  author = "Detection Research Agent"
  description = "Detects sensitive remote credential-store file or registry reads (SAM/SECURITY hive access, NTDS.dit) via SMB or object events. Split from directory-replication-rights use on 2026-08-16 because the two signals are materially different security effects with different actors, prerequisites and false-positive profiles; see reviews/impacket/detection-review.md and public-rules/comparisons/impacket/impacket_sensitive_file_or_replication_access.md."
  date = "2026-08-16"
  status = "experimental"
  severity = "CRITICAL"
  severity_rationale = "Credential-store file/registry access can directly expose domain credentials."
  procedure_ids = "IMP-13"
  log_source_prerequisites = "SMB/object events 5145/4663 with access description and path."
  false_positives = "Backup, migration, domain administration and security scanning that legitimately reads hive-adjacent paths."
  references = "reports/impacket/source-analysis.md"
  validation_status = "needs_validation"
  review_status = "reviewed_with_gaps"
  review_reference = "reviews/impacket/detection-review.md"
  source_comparison = "public-rules/comparisons/impacket/impacket_sensitive_file_or_replication_access.md"
  comparison_decision = "modify"
 events:
  $e.metadata.product_event_type = /(5145|4663)/
  re.regex($e.security_result.description, `(?i)(NTDS\.dit|\\SAM$|\\SECURITY$)`)
 condition: $e
}
```

- Current canonical YARA-L `detections/impacket/yaral/impacket_directory_replication_rights_use.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_directory_replication_rights_use {
  meta:
    author = "Detection Research Agent"
    description = "Detects use of directory replication extended rights (DS-Replication-Get-Changes, -All, -In-Filtered-Set) by a principal not approved for replication, the domain-controller effect of DRSUAPI replication-based secret retrieval. Restores the replication branch removed from impacket_sensitive_file_or_replication_access by the 2026-08-16 split."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Replication of secret attributes discloses domain credential material; DC-to-DC and approved synchronization accounts must be distinguished by enrichment, not by mutable account names."
    procedure_ids = "IMP-13"
    log_source_prerequisites = "Domain-controller Security 4662 (Directory Service Access auditing with a SACL on the domain naming context) with subject account, logging DC, and the replication right GUID in the properties/description; optional approved-replication-principal enrichment (additional.fields[approved_replication_principal])."
    false_positives = "Domain controllers replicating with each other, Entra Connect and other identity synchronization, migration and directory-backup products; mark them with the approved-replication-principal enrichment."
    references = "reports/impacket/source-analysis.md#imp-13; public-rules/comparisons/impacket/impacket_sensitive_file_or_replication_access.md; reviews/impacket/detection-review.md#review-013; https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized 4662 fixtures for DC-to-DC replication with enrichment, approved sync accounts, and a non-approved workstation account requesting Get-Changes-All; confirm only the last matches."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/impacket/detection-review.md"
  events:
    $e.metadata.product_event_type = "4662"
    re.regex($e.security_result.description, `(?i)(DS-Replication-Get-Changes|Replicating Directory Changes|1131f6a[a-d]-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c)`)
    $e.additional.fields["approved_replication_principal"].value.bool_value != true
    $e.principal.user.userid = $actor
  match:
    $actor over 10m
  outcome:
    $domain_controllers = array_distinct($e.principal.hostname)
    $events = count($e.metadata.id)
  condition:
    $e
}
```

- Re-comparison outcome: The restored replication rule and the file rule together cover both IMP-13 branches; benign DC replication depends on the approval enrichment.
