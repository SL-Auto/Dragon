# Public-rule comparison: rubeus_unusual_kerberos_password_change

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_unusual_kerberos_password_change.yaral`
- Internal SHA-256: `6403fe2a55e28790496c1faa26e371afb9f96feb134e655d4d580ed0725b08a7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-012`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/MultipleDataSources/MultiplePasswordresetsbyUser.yaml) - SHA-256 `8ad0cbf4b7adcaccf50f8923542387bf1bb29e5e3f5c0410187856043f10eefd`
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/persistence_remote_password_reset.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/persistence_remote_password_reset.toml) - SHA-256 `eb33f3fb58144446745d8d6e71cdb3676309903f67c27a0c01b0e45669a10682`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, and canonical logic had not acted on the proposal; decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The proposal's join of a port-464 connection to 4723/4724 by host and actor cannot succeed: those events are logged on the DC and carry no client workstation or IP.
  - The missing branch it named (process-attributed kpasswd traffic) is real and is adopted without the unjoinable leg, as `rubeus_kerberos_transport_from_unexpected_process` covering ports 88 and 464 (REVIEW-015). PROC-012 moves from `not_observable` to `detected`.
- Canonical result: `detections/rubeus/yaral/rubeus_unusual_kerberos_password_change.yaral`, SHA-256 `d8a689f045c862f5bb8743ea25ed91ec0dd2ad199e75a3cb85681d7ef4dffae3`.
- Canonical result: `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral`, SHA-256 `3135be137086b6cba19c72bf21974e8aa19f01a4ef42afd3f58e5c79da5a465c`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/persistence_remote_password_reset.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Process-attributed kpasswd (port 464) from a non-LSA process | covered by `rubeus_kerberos_transport_from_unexpected_process` | not covered | non-LSA port 464 - strong | 4723/4724 multi-target - weak | ours_stronger |
| Remote reset of a privileged account password | covered only as multi-target cardinality; no logon-session join | `persistence_remote_password_reset.toml`: 4624 network logon followed within 1m by 4724 in the same logon session (privileged-account scoping advised) | 4724 privileged target - moderate | `MultiplePasswordresetsbyUser.yaml` multi-source volume - weak | public_stronger |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_unusual_kerberos_password_change.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_unusual_kerberos_password_change {
  meta:
    author = "Detection Research Agent"
    description = "Detects a Kerberos password change from an unusual source or process context."
    date = "2026-08-15"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "Unexpected password changes can represent account manipulation but are normal in identity workflows."
    procedure_ids = "PROC-012"
    log_source_prerequisites = "Normalize account-management password-change events and process-attributed network connections to Kerberos password-change service where available."
    false_positives = "User password changes, helpdesk resets, machine-account rotation, and identity management."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md"
    validation_status = "needs_validation"
    validation_method = "Baseline password-management sources and replay approved account-change fixtures."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = /(4723|4724)/
    $e.principal.hostname = $source_host
    $e.principal.user.userid = $actor
    $e.target.user.userid = $target
  match:
    $source_host, $actor over 10m
  outcome:
    $targets = count_distinct($target)
  condition:
    $e and $targets >= 2
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_kerberos_transport_from_unexpected_process {
  meta:
    author = "Detection Research Agent"
    description = "Detects a Windows process other than lsass.exe connecting to a Kerberos KDC (port 88) or the Kerberos password-change service (port 464). This is the client-side network effect of ticket requests, roasting, delegation abuse or password change performed by a tool that implements its own Kerberos transport instead of using the LSA."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "On domain-joined Windows hosts, Kerberos AS/TGS and kpasswd exchanges are normally sent by the LSA (lsass.exe). A user-mode process speaking Kerberos directly is uncommon, independent of tool names, and sits on the path of every Rubeus ticket operation (raw TcpClient transport, Networking.cs L116-160)."
    procedure_ids = "PROC-001,PROC-002,PROC-003,PROC-004,PROC-005,PROC-012"
    log_source_prerequisites = "Process-attributed network-connection telemetry (Sysmon Event ID 3 or EDR equivalent, NETWORK_CONNECTION) with destination port, host and initiating process image path. Windows hosts are identified by a drive-letter image path."
    false_positives = "Java and other cross-platform applications with their own Kerberos stack, MIT Kerberos for Windows, identity-synchronization and password-management agents, and authorized security assessment tools; approve them by image path and signer after validation. Domain controllers should be scoped separately if their KDC-to-KDC traffic is attributed to processes other than lsass.exe."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_unusual_kerberos_password_change.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; reviews/rubeus/detection-review.md#review-015"
    validation_status = "needs_validation"
    validation_method = "Confirm on sanitized endpoint telemetry that ordinary logon, ticket renewal and interactive or scripted password changes appear only from lsass.exe, inventory approved non-LSA Kerberos clients, and replay a fixture of a non-LSA process connecting to ports 88 and 464."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    ($e.target.port = 88 or $e.target.port = 464)
    $e.principal.hostname = $host
    $e.principal.process.file.full_path = $process
    re.regex($e.principal.process.file.full_path, `(?i)^[a-z]:\\`)
    not re.regex($e.principal.process.file.full_path, `(?i)^[a-z]:\\windows\\system32\\lsass\.exe$`)
  match:
    $host, $process over 10m
  outcome:
    $ports = array_distinct($e.target.port)
    $destinations = array_distinct($e.target.ip)
    $connections = count($e.metadata.id)
    $accounts = array_distinct($e.principal.user.userid)
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
