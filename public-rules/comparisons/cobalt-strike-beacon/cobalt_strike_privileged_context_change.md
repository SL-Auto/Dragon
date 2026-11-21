# Public-rule comparison: cobalt_strike_privileged_context_change

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_privileged_context_change.yaral`
- Internal SHA-256: `a805797e08e42cef32c9f860938ae7672c11ff12d2334d672e7baf1458aed353`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-011`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_tokenmanip_sedebugpriv_enabled.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/privilege_escalation_tokenmanip_sedebugpriv_enabled.toml) - SHA-256 `6e8f7a7fb4ce7a4c2dd84b21d8be310b5dfb5a8c3c216bb4d4458e6f9f946735`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| special privileges assigned or enabled in a process token | 4672 or token-privilege change for uncommon processes | SeDebugPrivilege rules identify a particularly sensitive privilege and process context | privilege enablement plus protected-process access - strong | ordered downstream security effect | complementary | Procedure `CSB-011` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: specific dangerous privilege enablement followed by protected-process access.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

4672 is common for administrative logons and is weak without subsequent use. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| privilege enablement plus protected-process access | strong | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but specific dangerous privilege enablement followed by protected-process access. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Enforced first-event-before-second ordering (DR-15).
  - Host added to the second event.
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_privileged_context_change_compensating_signal.yaral`, SHA-256 `4e90d6b451b096ac717a0fe97556b3411e33463da11095b2b44e0b08e731012a`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-011`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: specific dangerous privilege enablement followed by protected-process access.
- Required telemetry: normalized `TOKEN_PRIVILEGE_CHANGE` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_privileged_context_change_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-011"
  events:
    $priv.metadata.event_type = "TOKEN_PRIVILEGE_CHANGE"
        $priv.principal.hostname = $host
        $priv.additional.fields["privilege_name"].value.string_value = "SeDebugPrivilege"
        $priv.principal.process.pid = $pid
        $open.metadata.event_type = "PROCESS_OPEN"
        $open.principal.process.pid = $pid
        re.regex($open.target.process.file.full_path, `(?i)\\(lsass|winlogon)\.exe$`)
  match:
    $host, $pid over 10m
  condition:
    $priv and $open
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `4e90d6b451b096ac717a0fe97556b3411e33463da11095b2b44e0b08e731012a`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- Between 7e91c15 and 9d792a8 the candidate added 12 process exclusions (dllhost, w3wp, netsh, netstat, RuntimeBroker, taskkill, tasklist; System32 and SysWOW64). This narrows the public rule's coverage of the privilege-enable branch and does not affect our decision.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SeDebugPrivilege enable then open of lsass/winlogon | covered, ordered | `privilege_escalation_tokenmanip_sedebugpriv_enabled.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | privilege-to-protected-process sequence - strong | base 4672/token rule - weak | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_privileged_context_change_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Correlates SeDebugPrivilege enablement on a process with that same process subsequently opening a protected process (lsass.exe or winlogon.exe), closing the causal gap left by the base rule's standalone 4672/token-change signal."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Enabling SeDebugPrivilege and then opening a protected process is a specific, dangerous, ordered sequence, though EDR, backup and diagnostic tools legitimately do the same."
    procedure_ids = "CSB-011"
    log_source_prerequisites = "Normalize TOKEN_PRIVILEGE_CHANGE with the enabled privilege name, and PROCESS_OPEN with target image path, joined on host and PID within 10 minutes."
    false_positives = "EDR, debuggers, backup/VSS tooling, and administrative diagnostic utilities that enable SeDebugPrivilege before inspecting system processes."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_privileged_context_change.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized privilege-enablement events from legitimate EDR/backup tooling paired with protected-process opens to confirm expected benign matches are understood before enabling."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_privileged_context_change"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_privileged_context_change.md"
  events:
    $priv.metadata.event_type = "TOKEN_PRIVILEGE_CHANGE"
    $priv.principal.hostname = $host
    $priv.additional.fields["privilege_name"].value.string_value = "SeDebugPrivilege"
    $priv.principal.process.product_specific_process_id = $pid
    $open.metadata.event_type = "PROCESS_OPEN"
    $open.principal.hostname = $host
    $open.principal.process.product_specific_process_id = $pid
    re.regex($open.target.process.file.full_path, `(?i)\\(lsass|winlogon)\.exe$`)
    $priv.metadata.event_timestamp.seconds <= $open.metadata.event_timestamp.seconds
  match:
    $host, $pid over 10m
  condition:
    $priv and $open
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
