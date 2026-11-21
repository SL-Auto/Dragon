# Public-rule comparison: rubeus_kerberoast_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_kerberoast_sequence.yaral`
- Internal SHA-256: `f70f549433ef69b82d59788dab687605fb3903ada30efd3490751bfea5d593b7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-004`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/SecurityEvent/PotentialKerberoast.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Detections/SecurityEvent/PotentialKerberoast.yaml) - SHA-256 `747d8097f4af3b53bd1d3093223a149055eac51ac600d1e272b42d9567028f51`
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/Execution/PotentialKerberoastActivities.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/Microsoft Defender XDR/Analytic Rules/Execution/PotentialKerberoastActivities.yaml) - SHA-256 `1c2463290723bcc6a52ee4cff785a594ed83ff0c831238062dce9a53b74cea5a`
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberoasting_unusual_process.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberoasting_unusual_process.toml) - SHA-256 `3e84a66e6565021a3ad046cdf5fbca7167c01ba0e62e4b28b2970ad18d466881`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SPN-bearing accounts discovered | LDAP filter for servicePrincipalName | Not required by public rules | LDAP SPN search - moderate | Directory query fan-out and caller context | ours_stronger | Ours captures reconnaissance immediately preceding requests. |
| Roastable service tickets requested | Five services after LDAP search | Sentinel detects RC4/options burst; MDE uses Kerberoast-tagged identity events; Elastic uses unusual process Kerberos traffic | 4769 RC4/options plus service fan-out - strong | Unusual process-to-KDC flow | complementary | Public rules cover ticket properties and single-stage activity; ours adds ordered reconnaissance. |
| Single high-value SPN requested | Below five-service threshold | RC4/options or MDE enriched event may detect | Rare RC4 request for sensitive SPN - strong | First-seen requester-to-SPN relationship | public_stronger | Public ticket-property branches cover targeted low volume better. |

## Missing detection branches

- Missing from ours: Targeted single-SPN requests; roasting without visible LDAP; distributed or slow fan-out; encryption/ticket-option risk.
- Missing from public rule: LDAP-to-TGS ordered sequence and non-RC4 roastable tickets.
- Missing from both: Offline cracking and credential use without later correlated authentication.

## Detection edge cases and blind spots

Legitimate service discovery produces the same LDAP filter. Modern AES-capable service accounts reduce RC4 usefulness. Host/user joins can fail when DC events lack hostname or use different identity forms.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4769 RC4 with roast-associated options | strong | public | Close to a roastable ticket request and more specific than volume alone. | Requires tenant-specific validation and collection-health monitoring. |
| LDAP SPN search followed by TGS fan-out | strong | ours | Ordered procedure coverage, dependent on rare LDAP telemetry. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process using Kerberos | moderate | public | Broad but useful when DC fields are incomplete. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

RC4-only logic misses AES requests and may rely on fragile option constants; MDE technique tags are opaque upstream enrichment.

## Internal-rule weaknesses

Requires LDAP visibility and five services, omits ticket encryption/options, and can miss targeted or tool-separated activity.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - Adopted as `rubeus_rc4_service_ticket_fanout` (split from the base rule on 2026-08-16), with the approval failing open (`!= true`), Status `0x0` required, and machine-account and `krbtgt` services excluded (REVIEW-008).
  - The base rule's invalid `re.regex ... nocase` was fixed (REVIEW-010).
  - The re-comparison showed the public port-88 non-LSA branch uncovered; adopted independently as `rubeus_kerberos_transport_from_unexpected_process` (REVIEW-015).
- Canonical result: `detections/rubeus/yaral/rubeus_kerberoast_sequence.yaral`, SHA-256 `4e44b2b04faa5aed40fa23e74761f59230278821f2bafba3c6ee75c9f6d7d312`.
- Canonical result: `detections/rubeus/yaral/rubeus_rc4_service_ticket_fanout.yaral`, SHA-256 `d3c84be9ce37220cb488f1a2c1c1acb6083442186c8a54b1f3a729a9d689d541`.
- Canonical result: `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral`, SHA-256 `3135be137086b6cba19c72bf21974e8aa19f01a4ef42afd3f58e5c79da5a465c`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

Public candidates do not cover the full `PROC-004` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Kerberoasting without visible LDAP reconnaissance, including low-volume RC4 service-ticket acquisition.
- Required telemetry: DC Security 4769 with encryption type, ticket options, requester, service/SPN, source and an approved legacy-service enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_kerberoast_rc4_service_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-004"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value = false
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
```

Adds ticket-property specificity and works when LDAP telemetry is missing. The threshold and legacy-service enrichment require local testing; AES and single-SPN branches remain separate gaps.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_kerberoasting_unusual_process.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| SPN discovery followed by many TGS requests | covered by base rule | `PotentialKerberoast.yaml`: 4769 RC4 success with ticket options 0x40810000, non-machine services, last hour against a 23-hour baseline | LDAP SPN search + 4769 fan-out - strong | RC4 fan-out - moderate | complementary |
| Low-volume RC4 TGS acquisition without visible LDAP | covered by `rubeus_rc4_service_ticket_fanout` (>= 3 services) | covered by volume thresholds in `PotentialKerberoastActivities.yaml` | RC4 success per service - moderate | transport rule - strong | complementary |
| Rubeus process sends Kerberos to the KDC directly (raw `TcpClient`) | covered by `rubeus_kerberos_transport_from_unexpected_process` | `credential_access_kerberoasting_unusual_process.toml`: port-88 connection from a non-LSA process (with osquery triage) | non-LSA process to port 88/464 - strong | DC-side 4768/4769 cardinality - moderate | equivalent |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_kerberoast_sequence.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_kerberoast_sequence {
  meta:
    author = "Detection Research Agent"
    description = "Correlates LDAP SPN discovery with service-ticket fan-out by the same host and user."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Discovery followed by broad service-ticket requests is stronger than encryption type or volume alone."
    procedure_ids = "PROC-004"
    log_source_prerequisites = "Normalize directory-side LDAP filters and 4769 with host, user, and service."
    false_positives = "Service inventory, monitoring, identity governance, and authorized assessment."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md, reviews/rubeus/detection-review.md#review-010"
    validation_status = "needs_validation"
    validation_method = "Test missing LDAP visibility and approved inventory sequences separately."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $ldap.metadata.product_event_type = "LDAP_SEARCH"
    re.regex($ldap.additional.fields["ldap_filter"].value.string_value, `(?i)servicePrincipalName`)
    $ldap.principal.hostname = $host
    $ldap.principal.user.userid = $user
    $tgs.metadata.product_event_type = "4769"
    $tgs.principal.hostname = $host
    $tgs.target.user.userid = $user
    $tgs.target.resource.name = $service
  match:
    $host, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $ldap and $tgs and $services >= 5
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_rc4_service_ticket_fanout.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_rc4_service_ticket_fanout {
  meta:
    author = "Detection Research Agent"
    description = "Detects a single requester obtaining RC4-encrypted service tickets for three or more distinct unapproved-legacy services within a 15-minute window, independent of LDAP SPN-discovery visibility."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "RC4 service-ticket fan-out against services not on the approved-legacy allowlist closely matches offline-crackable ticket collection (Kerberoasting) and low-and-slow renewal-adjacent acquisition, and is more specific than generic 4769 volume."
    procedure_ids = "PROC-002,PROC-004"
    log_source_prerequisites = "Normalize DC Security 4769 with source IP, requesting user, target service, TicketEncryptionType and Status, plus an approved-legacy-RC4-service enrichment keyed by target service (missing enrichment fails open)."
    false_positives = "Approved legacy RC4 services and application servers that have not yet been migrated to AES; environments where the legacy-RC4-service enrichment is stale, incomplete, or absent (an unpopulated enrichment field defaults to unapproved and will over-alert until the allowlist is built)."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md"
    validation_status = "needs_validation"
    validation_method = "Verify the TicketEncryptionType parser mapping for 0x17 (RC4-HMAC) with sanitized fixtures. Build and validate the approved-legacy-RC4-service allowlist before enabling, and confirm services correctly marked approved do not fire. This rule intentionally consolidates two independently proposed comparison improvements (rubeus_kerberoast_sequence.md and rubeus_service_ticket_or_renewal_anomaly.md both proposed a near-identical RC4 service-ticket fan-out compensating rule under different names and thresholds); adopting both separately would have duplicated the same detection logic, so a single shared rule is canonical for both procedures."
    review_status = "reviewed"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["Status"].value.string_value = "0x0"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value != true
    not re.regex($e.target.resource.name, `(?i)(\$$|^krbtgt$)`)
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
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
