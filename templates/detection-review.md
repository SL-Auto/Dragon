# <Tool> detection-logic review

## Review scope

- Rule files:
- Rule revision/commit:
- Source report:
- Review date:
- Reviewer:

## Overall assessment

- Decision: `revise | acceptable_experimental | blocked`
- Residual risk:
- Telemetry confidence:

## Findings

### REVIEW-001 — <Finding>

- Severity: `blocker | high | medium | low`
- Affected rules/procedures:
- Assumption challenged:
- Gap or failure mode:
- Defensive impact:
- Evidence:
- Resolution: `fixed | accepted_gap | compensating_signal | blocked`
- Rule change or compensating signal:
- Validation needed:

## Checklist

- [ ] UDM fields and event types verified against the target parser
- [ ] Join keys cannot trivially collide or disappear
- [ ] Event ordering and time windows reflect the procedure
- [ ] Missing-event and partial-telemetry cases considered
- [ ] Mutable names, paths, hashes, and defaults are not primary dependencies
- [ ] Exclusions are narrow and cannot suppress unrelated activity broadly
- [ ] Legitimate administrative and security-tool behavior considered
- [ ] Each procedure has at least one primary or compensating signal
- [ ] Safe test fixtures cover positive, negative, and near-miss cases
- [ ] Unresolved gaps are explicit and linked from the rules

## Required follow-up

