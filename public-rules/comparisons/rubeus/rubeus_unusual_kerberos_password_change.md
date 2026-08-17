# Public-rule comparison: rubeus_unusual_kerberos_password_change

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_unusual_kerberos_password_change.yaral`
- Internal SHA-256: `6403fe2a55e28790496c1faa26e371afb9f96feb134e655d4d580ed0725b08a7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-012`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml) - SHA-256 `8ad0cbf4b7adcaccf50f8923542387bf1bb29e5e3f5c0410187856043f10eefd`
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/persistence_remote_password_reset.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/persistence_remote_password_reset.toml) - SHA-256 `494f7c799f5ec9a154df77868f884fe7cde2f35893455bae0d3e39c58cc054e9`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Password change/reset occurs | 4723 or 4724 for two targets | Sentinel detects multiple resets; Elastic covers remote reset context | Account-change event - moderate | Kerberos password-service network attribution | equivalent | All cover the generic account-management effect. |
| Kerberos password-change protocol/process used | Advertised prerequisite but not present in condition | Public rules do not identify Kerberos password service | Process-attributed kpasswd traffic - strong | Caller process and destination port/service | insufficient_evidence | No implemented rule covers the Rubeus-specific transport branch. |
| Single sensitive account changed | Below two-target threshold | Remote-reset/public context may cover one account | Sensitive-account change - strong | Privileged actor/source baseline | public_stronger | Public context can detect targeted single-account changes. |

## Missing detection branches

- Missing from ours: Single target, process/network attribution, change versus reset distinction, privileged target sensitivity and success/result.
- Missing from public rule: Kerberos password-change protocol attribution.
- Missing from both: Attribution to Rubeus when only ordinary account-change events exist.

## Detection edge cases and blind spots

Helpdesk and identity systems legitimately change many accounts. 4723/4724 may be emitted on different systems and actor normalization varies. Machine password rotation can dominate volume.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Sensitive account password changed by unusual actor/source | strong | public compensation | Security effect plus context. | Requires tenant-specific validation and collection-health monitoring. |
| Two target changes | moderate | ours/public | Behavioral burst but common in administration. | Requires tenant-specific validation and collection-health monitoring. |
| Ordinary 4723/4724 | weak | both | Cannot attribute implementation. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Generic reset logic does not identify Kerberos password-change transport and can be noisy for helpdesk operations.

## Internal-rule weaknesses

The rule claims process-attributed Kerberos password-service coverage but implements only two-target 4723/4724 cardinality.

## Decision trail

- Candidate improvement: Correct the description/implementation mismatch; add a distinct process-attributed kpasswd branch if telemetry exists and a sensitive-single-account branch. Keep generic multi-target logic compensating only.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-012` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Process-attributed Kerberos password-change traffic followed by the account-change effect, including one target.
- Required telemetry: Endpoint network telemetry for Kerberos password service (TCP/UDP 464) with process attribution plus 4723/4724 actor/target events.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_kpasswd_process_and_account_change {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-012"
  events:
    $net.metadata.event_type = "NETWORK_CONNECTION"
    $net.target.port = 464
    $net.principal.hostname = $host
    $net.principal.process.file.full_path = $process
    $change.metadata.product_event_type = /(4723|4724)/
    $change.principal.hostname = $host
    $change.principal.user.userid = $actor
    $change.target.user.userid = $target
  match:
    $host, $actor over 5m
  condition:
    $net and $change
}
```

Adds the missing transport/process branch and can cover one account change. It still cannot attribute the change to Rubeus without caller trust/history, and port 464 is also used legitimately by native password workflows.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
