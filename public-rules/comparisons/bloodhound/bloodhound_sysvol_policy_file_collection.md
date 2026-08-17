# Public-rule comparison: bloodhound_sysvol_policy_file_collection

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_sysvol_policy_file_collection.yaral`
- Internal SHA-256: `9b983d3ae579e392ad2316a1db8389430daf41c6d1a907150bc909917fc36bb6`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-011`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate:
- [Chronicle administrative-share/SYSVOL transfer rule](../../snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/copy_from_or_to_admin_share_or_sysvol_folder.yaral) - pinned revision and SHA-256 `946ddcae11a6b37746335cc252b049205afa129f38dcf1b3d39c56945caadeec`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| one source reads multiple attack-path-relevant Group Policy artifacts from SYSVOL | three distinct named policy paths | copy to or from administrative shares/SYSVOL using process and share context | non-GPSVC process reading multiple sensitive policy types across GPOs - strong | any SYSVOL share access - weak | ours_stronger | Canonical rule, pinned public candidate, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | Public candidate also lacks complete distributed correlation | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: FILE_READ paths using UNC normalization variants, single sensitive file, DFS referral paths, and slow reads.
- Missing from public rule: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

Normal Group Policy refresh is extremely common and service accounts may legitimately inventory all policies. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| non-GPSVC process reading multiple sensitive policy types across GPOs | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| any SYSVOL share access | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

The public candidate covers only its declared observable and does not establish the complete BloodHound collection procedure. Its implementation-specific or single-source signal can be absent while the same security effect remains observable elsewhere. It is valuable as independent compensating evidence, not authority.

## Internal-rule weaknesses

FILE_READ paths using UNC normalization variants, single sensitive file, DFS referral paths, and slow reads. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: FILE_READ paths using UNC normalization variants, single sensitive file, DFS referral paths, and slow reads.
- Required telemetry: 5145 or EDR file reads with normalized UNC path and process/service attribution.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_sysvol_policy_file_collection_process_attributed {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-011"
  events:
    $e.metadata.product_event_type = /(5145|FILE_READ)/
    $e.principal.hostname = $source
    $e.principal.process.file.full_path = $process
    $e.principal.process.file.labels["is_group_policy_service"] = "false"
    re.regex($e.target.file.full_path, `(?i)\\\\SYSVOL\\.*\\Policies\\.*(Groups.xml|GptTmpl.inf|Registry.pol)$`)
    $e.target.file.full_path = $path
  match:
    $source, $process over 30m
  outcome:
    $paths = count_distinct($path)
  condition:
    $e and $paths >= 3
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
