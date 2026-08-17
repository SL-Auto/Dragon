# Public-rule comparison: havoc_discovery_fanout

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_discovery_fanout.yaral`
- Internal SHA-256: `599479a3cf1a171ace75e84b6eaf8e1b470b022586723a1bd5d1df55305b1d4b`
- Internal review completed before public comparison: `true`
- Procedures: HV-P04, HV-P13
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/discovery_generic_process_discovery.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/discovery_generic_process_discovery.toml) - SHA-256 `6fe09ca83b4bba1b048c20053fa086ead26afbe96a45cf3847d8fd1b81ac37fa`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | process-attributed multi-target directory network discovery | local process-discovery behavior | strong when close to the effect; weak when name/default based | single sensitive query and local discovery |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: single sensitive query and local discovery.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: process-attributed multi-target directory network discovery; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: local process-discovery behavior; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- single sensitive query and local discovery.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: single sensitive query and local discovery
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "LDAP_SEARCH"` / `"SMB_SESSION"`, but every canonical Havoc rule in this repository correctly uses `metadata.event_type` for normalized UDM category values; `product_event_type` holds the raw vendor-specific event identifier, not a semantic UDM enum name, so as written this predicate would not match real telemetry and the rule would silently never fire. Second, independent of the field-name defect, the logic does not implement the branch it claims to address: it requires both an LDAP_SEARCH and an SMB_SESSION event on the same process, which is a generic two-event correlation, not the stated "single sensitive query" (a single LDAP event with a sensitive-attribute predicate, no SMB requirement) or "local discovery" (no network session at all) branch.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated missing branch and introduces no correlation distinct from the existing canonical fanout rule; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `split`
- Addresses branches: single sensitive query and local discovery
- Required telemetry: concrete LDAP_SEARCH and SMB_SESSION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_discovery_fanout_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "LDAP_SEARCH"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "SMB_SESSION"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.