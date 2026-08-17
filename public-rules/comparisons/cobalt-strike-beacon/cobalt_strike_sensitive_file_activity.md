# Public-rule comparison: cobalt_strike_sensitive_file_activity

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_file_activity.yaral`
- Internal SHA-256: `f4fc5aecd904a818e6d0107e9da6b165c46b394cc741876c1531a44e4cbefc28`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-024,CSB-025`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/collection_posh_compression.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/collection_posh_compression.toml) - SHA-256 `e1393ea2bfc404db1a32e2ca4b1deda3d907371d53f9477ac168d98942ddd5ed`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| sensitive file discovery/collection and ingress followed by egress | sensitive file operation to same-process network correlation | collection rules add archive creation and named sensitive locations | sensitive reads aggregated into a staging artifact - strong | ordered downstream security effect | complementary | Procedure `CSB-024,CSB-025` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: multi-process collection where one process stages and another transmits.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

backup, indexing, and synchronization tools cause legitimate collection-to-egress sequences. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| sensitive reads aggregated into a staging artifact | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but multi-process collection where one process stages and another transmits. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the branch below, using public coverage only as evidence that the observable is useful.
- Independent verification: required against the Cobalt Strike procedure report, provider semantics, local schema mappings, and sanitized authorized telemetry.
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The proposal is detection-engineering input, not accepted canonical logic.`
- Required regeneration: `canonical adversarial review, coverage, telemetry and master counts, all five translations, dependencies/manifests/hashes, and this comparison.`

## Unmatched scope

The public candidate does not cover all branches in `CSB-024,CSB-025`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: multi-process collection where one process stages and another transmits.
- Required telemetry: normalized `FILE_READ` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_sensitive_file_activity_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-024,CSB-025"
  events:
    $read.metadata.event_type = "FILE_READ"
        $read.principal.hostname = $host
        $read.principal.user.userid = $user
        $read.target.file.full_path = $source_file
        $read.additional.fields["data_classification"].value.string_value = "SENSITIVE"
        $archive.metadata.event_type = "FILE_WRITE"
        $archive.principal.hostname = $host
        $archive.principal.user.userid = $user
        re.regex($archive.target.file.full_path, `(?i)\.(zip|7z|rar)$`)
  match:
    $host, $user over 30m
  condition:
    $read and $archive and #source_file >= 5
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.
