# Public-rule comparison: cobalt_strike_sensitive_registry_read

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_registry_read.yaral`
- Internal SHA-256: `a76d3807c31c0247e77123714f6ab09408f0ccfc7e149776f96951d5cb62b6ee`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-023`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules_building_block/discovery_generic_registry_query.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules_building_block/discovery_generic_registry_query.toml) - SHA-256 `7f8d19ded043ad2c1628197327d066134e9487fb4506f7d2d3adcfd8b61e9e82`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| security-sensitive registry discovery by uncommon process | registry reads to sensitive paths plus process rarity | public rules identify concrete credential/security configuration paths and command-line queries | multi-family sensitive registry enumeration - moderate | ordered downstream security effect | complementary | Procedure `CSB-023` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: burst across several sensitive registry families and subsequent credential/security effect.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

inventory and compliance scanners legitimately read these keys. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| multi-family sensitive registry enumeration | moderate | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but burst across several sensitive registry families and subsequent credential/security effect. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Approval enrichment now fails open with `!= true`, so missing enrichment cannot silently suppress (DR-16).
  - Distinct-family count moved to `outcome`.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_registry_read_compensating_signal.yaral`, SHA-256 `b5f4c1148237af5eb6158cca199596ca6c862aee58ed302f0822656f69c7950b`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-023`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: burst across several sensitive registry families and subsequent credential/security effect.
- Required telemetry: normalized `REGISTRY_READ` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_sensitive_registry_read_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-023"
  events:
    $e.metadata.event_type = "REGISTRY_READ"
        $e.principal.process.file.sha256 = $hash
        $e.additional.fields["registry_security_family"].value.string_value = $family
        $e.additional.fields["approved_inventory_process"].value.bool_value = false
  match:
    $hash over 15m
  condition:
    $e and #family >= 3
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `b5f4c1148237af5eb6158cca199596ca6c862aee58ed302f0822656f69c7950b`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- Between 7e91c15 and 9d792a8 the candidate changed from a 7-day new-terms rule (novel per host/user) to a plain EQL match on every `reg query` or PowerShell registry read. It is now broader and noisier, still command-line based rather than registry-read telemetry, and does not affect our decision.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| One process reading several sensitive registry families | covered per host/process hash | `discovery_generic_registry_query.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | multi-family read burst - moderate | base single-read rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_sensitive_registry_read_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Detects a single process reading several distinct sensitive-registry-family keys within a short window, surfacing multi-family enumeration bursts that the base single-event sensitivity check does not aggregate."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "A burst of reads across several distinct sensitive registry families by one process is a moderate discovery signal, but inventory and compliance scanners legitimately read these keys in bulk."
    procedure_ids = "CSB-023"
    log_source_prerequisites = "Normalize REGISTRY_READ with process hash, hostname, a registry-security-family classification field, and an approved-inventory-process enrichment, joined on host and process hash within 15 minutes."
    false_positives = "Inventory, compliance, EDR, backup, and forensics tooling that legitimately reads across many sensitive registry families; the approved-inventory-process enrichment is required to keep this usable."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_sensitive_registry_read.md"
    validation_status = "needs_validation"
    validation_method = "Use benign reads of non-secret test keys spanning several classification families from both approved and unapproved inventory tooling."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_sensitive_registry_read"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_sensitive_registry_read.md"
    modification_note = "Proposal accepted with a required change: added principal.hostname to the joined/matched fields. The original proposal aggregated only by process file hash across the entire fleet with no host in the event or match clause, so a matching alert could not be attributed to a specific host for triage."
  events:
    $e.metadata.event_type = "REGISTRY_READ"
    $e.principal.hostname = $host
    $e.principal.process.file.sha256 = $hash
    $e.additional.fields["registry_security_family"].value.string_value = $family
    $e.additional.fields["approved_inventory_process"].value.bool_value != true
  match:
    $host, $hash over 15m
  outcome:
    $families = count_distinct($family)
  condition:
    $e and $families >= 3
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
