# Public-rule comparison: roadtools_scripting_user_agent_signin

## Identity and independence gate

- Internal tool: `roadtools` (revision `792708365789be4e6f58db65c3f90701159fd0ea`)
- Internal canonical rule: `detections/roadtools/yaral/roadtools_scripting_user_agent_signin.yaral`
- Internal SHA-256: `280b9036994e28d6edac3578242c891343e8bcb68e9c762995d1caa9792f2997`
- Internal review completed before public comparison: `yes` (`reviews/roadtools/detection-review.md`, RT-DR-01 to RT-DR-08)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_aad_graph_suspicious_user_agent.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/integrations/azure/discovery_aad_graph_suspicious_user_agent.toml) - SHA-256 `3b4b3a8e9f520eb31633425d2f1c7f4831dd9b042bcd3e9b221daadaf6a0519c`
- Scope mapping rationale: Both use scripting or unusual user agents as tool indicators (T1087.004).

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Scripting user agent on sign-ins and Graph requests | covered | covered for Azure AD Graph requests | user agent - weak (mutable) | behavioral rules - strong | complementary |
| Scripting user agent on Azure AD Graph requests | covered through the new internal API rule's outcome | covered | user agent - weak | api-version - strong | complementary |

## Missing detection branches

- None.

## Detection edge cases and blind spots

- Operator-set user agents (RT-DR-01).

## Signal-quality assessment

- Both: user agent - weak.

## Public-rule weaknesses

- Mutable.

## Internal-rule weaknesses

- Mutable.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/roadtools/source-analysis.md`, `telemetry/roadtools.md` and `reviews/roadtools/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal adds AADGraphActivityLogs to the scripting user-agent rule. The new internal API-version rule already covers that log with a stronger, non-user-agent signal and reports user agents in its outcome.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

None. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Scripting user agents on Azure AD Graph requests.
- Required telemetry: AADGraphActivityLogs with user agent.
- Validation status: `unvalidated_proposal`

```yaral
rule roadtools_aad_graph_scripting_ua {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "RT-P11"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.product_event_type = "AADGraphActivityLogs"
    re.regex($e.network.http.user_agent, `(?i)(python-requests|aiohttp)`)
  condition:
    $e
}
```
