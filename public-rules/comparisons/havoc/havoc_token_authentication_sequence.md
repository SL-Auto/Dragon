# Public-rule comparison: havoc_token_authentication_sequence

## Identity and independence gate

- Internal rule: `detections/havoc/yaral/havoc_token_authentication_sequence.yaral`
- Internal SHA-256: `fd1f4115a1db451e52e8dbb0ff638e335ed82c1c054bc03a1fd1e9302e3b260a`
- Internal review completed before public comparison: `true`
- Procedures: HV-P12
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/privilege_escalation_via_token_theft.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/privilege_escalation_via_token_theft.toml) - SHA-256 `c13444f44d5fc2d13910cd597a223c644ad09e4fca535a4709f59395673ef8bf`

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate â€” establishes causal scope | Both depend on source completeness |
| Security-sensitive action | explicit credentials or token semantic followed by execution | token theft from sensitive process | strong when close to the effect; weak when name/default based | sensitive token-source process access |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak â€” neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: sensitive token-source process access.
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: explicit credentials or token semantic followed by execution; `moderate` to `strong` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: token theft from sensitive process; strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: `complementary` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- sensitive token-source process access.
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: sensitive token-source process access
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: `rejected`
- Reason: Adversarial review of the proposal (2026-08-16) found two independent defects. First, it queries `metadata.product_event_type = "PROCESS_ACCESS"` / `"TOKEN_IMPERSONATION"`, but every canonical Havoc rule in this repository correctly uses `metadata.event_type`, and TOKEN_IMPERSONATION is not a verified UDM event_type mapping, so as written this predicate would not reliably match real telemetry. Second, the proposal reintroduces a generic PROCESS_ACCESS-plus-token-semantic correlation with no source-process sensitivity predicate (e.g. LSASS or another privileged source) -- exactly the class of overly generic token/authentication join that this repository's own adversarial review (`reviews/havoc/detection-review.md` HV-DR-01) already removed from the canonical rule for producing accidental token joins on ordinary logon activity.
- Adversarial re-check: Re-ran the procedure-branch matrix against the proposal. It does not close the stated "sensitive token-source process access" branch and would reintroduce a finding this repository already fixed once; canonical logic is unchanged and no compensating rule is added.
- Required regeneration: none. Canonical logic, telemetry, translations, and dependencies are unchanged because the proposal was rejected, not adopted or modified.

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: sensitive token-source process access
- Required telemetry: concrete PROCESS_ACCESS and TOKEN_IMPERSONATION mappings with stable entity fields and collection health
- Validation status: `unvalidated_proposal`

```yaral
rule havoc_token_authentication_sequence_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = "PROCESS_ACCESS"
    $a.principal.hostname = $host
    $a.principal.process.product_specific_process_id = $pid
    $b.metadata.product_event_type = "TOKEN_IMPERSONATION"
    $b.principal.hostname = $host
    $b.principal.process.product_specific_process_id = $pid
  match:
    $host, $pid over 10m
  condition:
    $a and $b
}
```

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.