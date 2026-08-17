# Public-rule comparison: <internal_rule>

## Identity and independence gate

- Internal tool: `<tool>`
- Internal canonical rule: `detections/<tool>/yaral/<internal_rule>.yaral`
- Internal SHA-256: `<sha256>`
- Internal review completed before public comparison: `<yes|no>`
- Public source/revision/path: `<source>/<commit>/<path>`
- Public SHA-256: `<sha256>`
- Scope mapping rationale: `<ordered attacker behavior, observable effect, ATT&CK, telemetry, platform, procedure>`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `<precondition or initial observable>` | | | | | | |
| `<security-sensitive operation>` | | | | | | |
| `<resulting state change or artifact>` | | | | | | |
| `<network, remote, or cross-event behavior>` | | | | | | |
| `<cleanup or follow-on behavior>` | | | | | | |

Coverage conclusions: `ours_stronger`, `public_stronger`, `complementary`, `equivalent`, `different_scope`, `insufficient_evidence`.

Signal strengths: `strong`, `moderate`, `weak`. Explain strength using causal proximity to the security effect, behavioral specificity, resistance to mutable indicators, telemetry reliability, and benign prevalence.

## Missing detection branches

- Missing from ours: `<branches or none>`
- Missing from public rule: `<branches or none>`
- Missing from both: `<branches or none>`

## Detection edge cases and blind spots

Assess alternate procedure paths, platform/version differences, parser and collection gaps, partial telemetry, identity/entity ambiguity, distributed or low-and-slow activity, ordering/window races, cleanup, and false-positive/false-negative tradeoffs. Do not describe operational evasion steps.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| | | | | |

## Public-rule weaknesses

Evidence-backed missing branches, weak signals, risky assumptions, or `None identified`.

## Internal-rule weaknesses

Evidence-backed missing branches, weak signals, risky assumptions, or `None identified`.

## Decision trail

- Candidate improvement: `<description|none>`
- Independent verification: `<source/telemetry/review evidence>`
- Decision: `<adopted|rejected|deferred|not_applicable>`
- Reason: `<why>`
- Required regeneration: `<YARA-L review, telemetry, translations, comparison|none>`

## Unmatched scope

Public behavior with no internal counterpart and internal procedure with no public counterpart.

## Proposed YARA-L improvement

- Change type: `<patch|compensating_rule|split|rewrite|new_rule>`
- Addresses branches: `<specific missing or weak branches>`
- Required telemetry: `<concrete providers, event types, fields, enrichment and collection-health assumptions>`
- Validation status: `unvalidated_proposal`

```yaral
rule <proposed_rule_name> {
  // Actual YARA-L 2.0 proposal. Include the events, match/outcome when needed,
  // and condition that materially improves the detection branch.
}
```

Explain why this code improves detection coverage, what it still misses, and which canonical review/telemetry/translation artifacts must change if adopted.
