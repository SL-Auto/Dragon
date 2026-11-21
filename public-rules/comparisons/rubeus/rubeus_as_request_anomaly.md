# Public-rule comparison: rubeus_as_request_anomaly

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_as_request_anomaly.yaral`
- Internal SHA-256: `729c1bcd9139583935f6c96e78cc35b0ea7a8a52d8e2518bd02cf9bd4dafc3cf`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-001`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml) - SHA-256 `6ab27ba3bdb4279de4387de8a76f928fc24dd16eb25a2e8d7658cd9d447c1648`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| AS request reaches a KDC | 4768 fan-out by source across three accounts | Port 88 flow followed by authentication from a nonstandard process | 4768 account/source cardinality - moderate | Process-attributed KDC network flow - moderate | complementary | Ours covers multi-principal probing; public adds process/network context. |
| Atypical preauthentication or failed probing | Not distinguished beyond 4768 count | Authentication result is present but public sequence is not AS-specific | 4768 result and PreAuthType - moderate | 4768 failure/result baselines | ours_stronger | Public rule does not isolate AS request failure/preauthentication branches. |
| Single-account TGT acquisition | Below three-account threshold | Can detect an unusual process making a KDC request | Process-to-KDC flow - moderate | Rare-process and account baseline | public_stronger | Ours deliberately misses a single targeted request. |

## Missing detection branches

- Missing from ours: Single-account requests; repeated requests spread across source IPs; account-specific preauthentication anomalies.
- Missing from public rule: AS-specific request/result semantics and multi-principal probing.
- Missing from both: Encrypted or un-attributed KDC traffic when neither DC 4768 nor endpoint network attribution is complete.

## Detection edge cases and blind spots

NAT can merge independent clients; DHCP and IPv6 representations can split one source. Password audits and identity infrastructure create benign fan-out. Source-only cardinality does not model account sensitivity or per-account history.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4768 across distinct principals | moderate | ours | Behavioral fan-out but common in scanners and identity systems. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process contacting KDC | moderate | public | Adds endpoint context but process rarity is environment-dependent. | Requires tenant-specific validation and collection-health monitoring. |
| Single 4768 | weak | both | Normal authentication is overwhelmingly common. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Broad Kerberos network/authentication sequence is not AS-specific and can conflate normal ticket activity.

## Internal-rule weaknesses

The condition does not implement the advertised atypical PreAuthType or result branches; it is only a three-account source fan-out.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The 2026-08-16 adoption kept the proposal's `security_result.action != "ALLOW"`, which also matches an unpopulated action and degraded the rule to the base fan-out (REVIEW-012).
  - Re-review added Security 4771, where wrong-password pre-authentication failures are actually logged, and requires explicit failure codes `0x6`, `0x12` or `0x18`, or a BLOCK action.
  - The re-comparison found the process-attributed transport branch uncovered; it is now covered by `rubeus_kerberos_transport_from_unexpected_process` (REVIEW-015).
- Canonical result: `detections/rubeus/yaral/rubeus_as_request_anomaly.yaral`, SHA-256 `f0dd81bd806fe2289cdb753eb284a797732e2f5ec01dac4b32dbac999b5d2491`.
- Canonical result: `detections/rubeus/yaral/rubeus_as_request_failed_preauth_fanout.yaral`, SHA-256 `907802ed687345d875d357d59e6a9c8b418a49901de6348579dc3bcab9978982`.
- Canonical result: `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral`, SHA-256 `3135be137086b6cba19c72bf21974e8aa19f01a4ef42afd3f58e5c79da5a465c`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

Public candidates do not cover the full `PROC-001` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Failed or atypical-preauthentication AS probing that does not reach the existing generic fan-out threshold.
- Required telemetry: DC Security 4768; source IP, target account, result/action and normalized PreAuthType.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_as_request_failed_preauth_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-001"
  events:
    $e.metadata.product_event_type = "4768"
    $e.security_result.action != "ALLOW"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source over 10m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 3
}
```

Separates failed AS probing from successful TGT acquisition, producing a clearer branch than the current all-4768 cardinality. It still depends on tenant-specific result normalization and can miss single-account probing.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/lateral_movement_credential_access_kerberos_correlation.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Failed AS requests across many accounts from one source | covered by `rubeus_as_request_failed_preauth_fanout` (4768 + 4771, explicit codes) | `lateral_movement_credential_access_kerberos_correlation.toml`: unusual process to port 88 correlated with a DC ticket request | multi-account failure codes - strong | base AS fan-out - moderate | complementary |
| Successful AS requests across many accounts | covered by base `rubeus_as_request_anomaly` | covered when the requesting process is unusual | multi-account 4768 - moderate | transport rule - strong | complementary |
| Rubeus process sends Kerberos to the KDC directly (raw `TcpClient`) | covered by `rubeus_kerberos_transport_from_unexpected_process` | `credential_access_kerberoasting_unusual_process.toml`: port-88 connection from a non-LSA process (with osquery triage) | non-LSA process to port 88/464 - strong | DC-side 4768/4769 cardinality - moderate | equivalent |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_as_request_anomaly.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_as_request_anomaly {
  meta:
    author = "Detection Research Agent"
    description = "Detects one source making AS requests for multiple principals or atypical preauthentication patterns."
    date = "2026-08-15"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Multi-principal AS activity can indicate authentication probing, but scanners and identity systems overlap."
    procedure_ids = "PROC-001"
    log_source_prerequisites = "Normalize DC Security 4768 with source IP, target account, preauthentication type, result, and encryption type."
    false_positives = "Identity monitoring, password audits, migration, and authorized assessment."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized 4768 fixtures with benign single-account and approved multi-account cases."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4768"
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source over 10m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 3
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_as_request_failed_preauth_fanout.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_as_request_failed_preauth_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects one source generating failed AS requests (4768 unknown/revoked principal, or 4771 pre-authentication failure) against multiple accounts, distinct from the existing multi-principal AS fan-out rule."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Non-success AS-REQ fan-out across multiple principals is closely associated with authentication/preauthentication probing rather than a single account's ordinary failed logon."
    procedure_ids = "PROC-001"
    log_source_prerequisites = "DC Security 4768 and 4771 with source IP, target account and the Status/Result Code field normalized to additional.fields[\"Status\"] (or security_result.action = BLOCK)."
    false_positives = "Password audits, account-lockout/health monitoring tooling, and misconfigured legacy clients retrying stale credentials."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_as_request_anomaly.md; reviews/rubeus/detection-review.md#review-012"
    validation_status = "needs_validation"
    validation_method = "Verify the parser's security_result.action / 4768 Result Code mapping with sanitized fixtures covering bad-password, preauthentication-required, and clock-skew outcomes before enabling; replay benign password-audit fixtures to confirm the three-account threshold does not over-fire. Failure is matched on explicit result codes 0x6 (unknown principal), 0x12 (revoked or locked) and 0x18 (pre-authentication failed), or on a BLOCK action; an unpopulated field no longer fails open."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = /^(4768|4771)$/
    ($e.security_result.action = "BLOCK" or re.regex($e.additional.fields["Status"].value.string_value, `(?i)^0x(6|12|18)$`))
    $e.principal.ip = $source
    $e.target.user.userid = $account
  match:
    $source over 10m
  outcome:
    $accounts = count_distinct($account)
  condition:
    $e and $accounts >= 3
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
