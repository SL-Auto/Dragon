# Rubeus detection-logic review

## Review scope

- Rule files: one rule per file under `detections/rubeus/yaral/`
- Rule revision/commit: working tree after baseline commit `cb145be`
- Source report: `RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md`
- Review date: 2026-08-15
- Reviewer: Detection Research Agent

## Overall assessment

- Decision: `acceptable_experimental`
- Residual risk: Medium-high because Kerberos behavior is shared with legitimate clients and several strongest rules depend on tenant-specific EDR or directory parser fields.
- Telemetry confidence: High for raw Windows event availability, medium-low for UDM normalization and API telemetry.

## Findings

### REVIEW-001 — Cardinality rules miss low-volume activity

- Severity: `high`
- Affected rules/procedures: AS, TGS, roasting, and password-change rules; PROC-001 through PROC-004 and PROC-012
- Assumption challenged: A useful detection can require multiple accounts, services, or events.
- Gap or failure mode: A single target or service can remain below threshold, while legitimate inventory can exceed it.
- Defensive impact: False negatives at low volume and false positives from automation.
- Evidence: Rule thresholds and report detection matrix.
- Resolution: `compensating_signal`
- Rule change or compensating signal: Kept sequence/cardinality rules as generic leads and separately retained direct process-to-DC, LSA API, artifact, KKDCP, and ticket-use inconsistency coverage. Reclassified a normal single password change as `not_observable` for tool attribution rather than claiming full coverage from a two-target rule.
- Validation needed: Establish per-account/source baselines and near-threshold fixtures.

### REVIEW-002 — S4U semantics may not appear in description text

- Severity: `high`
- Affected rules/procedures: `rubeus_s4u_ticket_sequence`, PROC-005
- Assumption challenged: The parser renders S4U or transited-service semantics in `security_result.description`.
- Gap or failure mode: Many 4769 parsers expose ticket options and transited services in separate fields or omit explicit S4U labels.
- Defensive impact: Complete false-negative failure if the assumed description mapping is absent.
- Evidence: Source report PROC-005 telemetry requirements.
- Resolution: `accepted_gap`
- Rule change or compensating signal: Rule metadata now requires delegation context and parser verification; service-account/target-edge baselining is the compensating signal. No universal UDM field was invented.
- Validation needed: Map actual 4769 fields and authoritative delegation edges before enabling.

### REVIEW-003 — LSA rules require nonstandard EDR API telemetry

- Severity: `high`
- Affected rules/procedures: cache, submit, purge, and net-only rules; PROC-006 and PROC-007
- Assumption challenged: EDR emits `LsaCallAuthenticationPackage` and Kerberos message types in the proposed additional fields.
- Gap or failure mode: Standard Windows logs do not expose these calls; vendor schemas differ.
- Defensive impact: Rules may never receive eligible events.
- Evidence: Source report sections 4 and 5.
- Resolution: `accepted_gap`
- Rule change or compensating signal: Kept explicit prerequisites and paired API rules with Type 9 logon, artifact, ticket-request, and later service-use telemetry. Rules must be disabled when the EDR mapping is unavailable.
- Validation needed: Obtain sanitized API events from the deployed EDR.

### REVIEW-004 — Forged-ticket absence correlation is fragile

- Severity: `high`
- Affected rules/procedures: `rubeus_ticket_use_without_credible_kdc_issue`, PROC-008 and PROC-009
- Assumption challenged: Centralized 4769 telemetry is complete enough for meaningful absence and the resource parser supplies a PAC/identity anomaly.
- Gap or failure mode: Missing DC logs, referrals, cached tickets, cross-realm activity, or field mismatches can imitate absence; absent anomaly enrichment prevents matching.
- Defensive impact: Either false positives or no coverage depending on parser completeness.
- Evidence: Source report limitations and ticket-forging detection discussion.
- Resolution: `compensating_signal`
- Rule change or compensating signal: Required a positive resource-side identity/PAC anomaly in addition to absence, explicitly avoiding absence-only attribution. Artifact and privileged-use anomalies provide additional coverage.
- Validation needed: Test complete and deliberately incomplete DC datasets.

### REVIEW-005 — File extensions do not cover in-memory operations

- Severity: `medium`
- Affected rules/procedures: artifact rule; PROC-008 through PROC-010 and PROC-013
- Assumption challenged: Ticket processing produces a recognizable file.
- Gap or failure mode: In-process invocation and memory-only inputs/outputs create no file event; names and extensions are mutable.
- Defensive impact: False negatives for offline/in-memory operations.
- Evidence: `Program.MainString` and report output/memory sections.
- Resolution: `compensating_signal`
- Rule change or compensating signal: File logic is explicitly supporting coverage; LSA, KDC network, CLR/process, and later ticket-use signals remain primary. No filename is used to attribute Rubeus by itself.
- Validation needed: Test fileless fixtures as negative-to-artifact but positive-to-compensating paths.

## Implemented improvements

- Accounted for every dispatcher command in the coverage ledger instead of treating the original behavioral matrix as implicit completeness.
- Removed process-name attribution and made mutable filenames supporting signals only.
- Required a positive resource-side anomaly for forged-ticket absence correlation.
- Reclassified local key derivation and normal single password change as not uniquely observable rather than overstating detection coverage.
- Linked every observable procedure to at least one rule and every inherent gap to compensating telemetry.

## 2026-11-21 delta review — four rules added 2026-08-16

Scope:

- `rubeus_lsa_encoded_ticket_retrieval` and `rubeus_lsa_ticket_submission`, adopted from comparisons.
- `rubeus_rc4_service_ticket_fanout` and `rubeus_ticket_renewal_anomaly`, split from `rubeus_service_ticket_or_renewal_anomaly`.

All four carried review metadata, but no finding existed for them.

### REVIEW-006 — invalid modifier and unanchored message type

- Severity: `high`
- Rule: `rubeus_lsa_encoded_ticket_retrieval`
- Gap or failure mode: `re.regex(...) nocase` applies a string-comparison modifier to a function call, which is not valid YARA-L. The unanchored pattern would also match any message type containing the substring.
- Resolution: `fixed`. The rule uses inline `(?i)` and an anchored `^Kerb(RetrieveEncodedTicket|RetrieveTicket)(Message)?$`. The submission rule received the same anchoring.

### REVIEW-007 — per-call alerts without session context

- Severity: `medium`
- Rules: both LSA rules.
- Gap or failure mode: every successful API call raised a separate alert with no caller or session context. `rubeus_lsa_ticket_submission` assigned `$luid` but never used it. Extraction across many logon sessions, which is what a dump does, was not distinguishable from a single self-retrieval.
- Resolution: `fixed`. The rules aggregate per host and caller process over 10m, with outcomes for target LUIDs (and a count for retrieval), caller paths and accounts, so many-session extraction is visible. Target-LUID versus caller-LUID comparison remains an analyst enrichment.

### REVIEW-008 — RC4 approval fails closed; non-roastable services counted

- Severity: `high`
- Rule: `rubeus_rc4_service_ticket_fanout`
- Gap or failure mode:
  - `approved_legacy_rc4_service = false` silently suppressed every event when the enrichment was absent.
  - Failed requests were counted.
  - Machine-account (`$`-suffixed) and `krbtgt` services, which are not Kerberoast targets and are common legacy-client RC4 noise, inflated the fan-out.
- Resolution: `fixed`. The approval now fails open (`!= true`). The rule requires Status `0x0` and excludes `$`-suffixed services and `krbtgt`.

### REVIEW-009 — renewal burst does not model tool auto-renewal

- Severity: `medium`
- Rule: `rubeus_ticket_renewal_anomaly`
- Assumption challenged: Rubeus renewal produces many 4770 events in a short window.
- Gap or failure mode: Rubeus renewal loops until near expiry or renewal limits (`RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md` §10, `Renew.cs` L13–110). That is low-rate and indistinguishable in 4770 from native LSA renewal. The 15-in-10-minutes burst is a generic scripted-renewal anomaly, not the Rubeus pattern, and MEDIUM overstated its value.
- Resolution: `accepted_gap` for low-rate auto-renewal, which is inherent to 4770. The description now states the limit honestly and severity is lowered to LOW. Compensating signal: `rubeus_ticket_use_without_credible_kdc_issue`, for renewed tickets with no credible issuance.

### Re-review

All four rules were re-traced:

- No blocker remains.
- Regexes are anchored and use valid syntax.
- Approval enrichment fails open.
- Aggregation keys carry host and process.

## 2026-11-21 delta review — comparison backlog resolution

Ten `public-rules/comparisons/rubeus/*.md` trails still read `deferred_pending_rule_improvement_run`. Seven proposals had already been copied into canonical rules on 2026-08-16 without a recorded decision or review finding. Each live rule was re-reviewed against its proposal before the terminal decision was recorded; the other three proposals were decided fresh.

### REVIEW-010 — invalid `re.regex(...) nocase` in four more rules

- Severity: `high`
- Rules: `rubeus_kerberoast_sequence`, `rubeus_lsa_ticket_cache_operations`, `rubeus_lsa_ticket_mutation`, `rubeus_ticket_artifact_access_or_creation` (and `rubeus_s4u_ticket_sequence`, REVIEW-011).
- Gap or failure mode: REVIEW-006 fixed this modifier misuse in one rule only. The same invalid form remained in five more Rubeus rule files, plus `detections/mimikatz/yaral/mimikatz_lsass_memory_access.yaral`.
- Resolution: `fixed`. Every occurrence now uses inline `(?i)`, and a repository-wide search finds none remaining.

### REVIEW-011 — S4U unapproved-edge branch fired on every S4U ticket

- Severity: `high`
- Rule: `rubeus_s4u_ticket_sequence` (adopted from its comparison on 2026-08-16).
- Gap or failure mode: `delegation_edge_approved = false` also matches when the enrichment is absent, because unset UDM booleans read as false. Without a delegation inventory, the single-event `$u` branch therefore bypassed the two-target threshold and alerted on every S4U2Self/S4U2Proxy ticket, including approved constrained delegation.
- Resolution: `fixed`. `$u` additionally requires `delegation_inventory_evaluated = true`, set by the inventory enrichment. Without the inventory, only the two-target `$e` branch can fire. Prerequisites document the marker.

### REVIEW-012 — failed-preauth fan-out missed 4771 and failed open

- Severity: `high`
- Rule: `rubeus_as_request_failed_preauth_fanout` (adopted from `rubeus_as_request_anomaly` comparison on 2026-08-16).
- Gap or failure mode:
  - A wrong-password Kerberos attempt against an account that requires pre-authentication is logged as Security 4771 (Status `0x18`), not as a 4768 failure, so password-spray and credential probing were largely invisible to the rule.
  - `security_result.action != "ALLOW"` also matches an unpopulated action. The rule degraded to the base all-4768 fan-out, contrary to its validation note.
- Resolution: `fixed`:
  - Events are now `/^(4768|4771)$/`.
  - Failure is required as `action = "BLOCK"` or Status `^0x(6|12|18)$` (unknown principal, revoked/locked, pre-authentication failed).
  - The misleading validation note was corrected.
  - The native translations moved from generator candidate retrieval to `scripts/native_translations/specs_ri.py`.

### REVIEW-013 — collection-health gate was not joined to the activity

- Severity: `high`
- Rule: `rubeus_ticket_use_without_credible_kdc_issue` (the 2026-08-16 adoption equals the proposal).
- Gap or failure mode:
  - `$health` shared no placeholder with `$access` or `$tgs`. Any healthy DC report anywhere satisfied the gate, and an unjoined event variable is not a valid multi-event correlation.
  - `#tgs = 0` is not the documented non-existence form.
- Resolution: `fixed`. `$health` and `$access` now join on `target.administrative_domain`, and the condition uses `!$tgs`. Forgery is still never inferred from absence alone. REVIEW-004 stands.

### REVIEW-014 — targeted single-account AS-REP roasting below threshold

- Severity: `medium`
- Rule: new `rubeus_asrep_single_account_sensitive`, from the `rubeus_asrep_roast_sequence` comparison.
- Gap or failure mode: the base rule needs three no-pre-authentication accounts from one source, so a named single-account request (`Roast.cs` L16–101 accepts a named account) is missed.
- Resolution: `compensating_signal`:
  - Adopted with Status `0x0` added, so only issued AS-REPs count.
  - The proposal's hard `account_risk_tier = "high"` dependency is kept deliberately. Without the enrichment the additive rule stays silent instead of alerting on every legitimate no-pre-authentication account. The base rule is unaffected.
  - No encryption-type predicate is used, because the pinned report gives no evidence for a default etype.

### REVIEW-015 — Kerberos and kpasswd transport is observable on the client network path

- Severity: `medium`
- Rule: new `rubeus_kerberos_transport_from_unexpected_process`, from the `rubeus_unusual_kerberos_password_change` comparison, widened after the `rubeus_kerberoast_sequence` re-comparison.
- Assumption challenged: that PROC-012 is `not_observable` beyond multi-target 4723/4724 cardinality, and that DC-side 4768/4769 cardinality is the only practical signal for PROC-001 to PROC-005.
- Gap or failure mode:
  - The proposal joined a port-464 connection to 4723/4724 by `principal.hostname` and actor. Those events are logged on the DC and carry no client workstation or IP, so the join cannot succeed, and the proposal is not adopted as written.
  - Rubeus implements its own Kerberos transport from its own process (`TcpClient`, `Networking.cs` L116–160; observed source fact). By inference (medium confidence), its kpasswd exchange is also sent from the tool process rather than from lsass.exe.
  - The re-pinned public candidate `credential_access_kerberoasting_unusual_process.toml` (elastic-security `9d792a8`) applies the same principle to port 88. No canonical Rubeus rule covered that branch, although every AS/TGS operation uses the raw transport.
- Resolution: `compensating_signal`. A process-attributed connection to port 88 or 464 from a Windows process other than lsass.exe, aggregated per host and process with ports and destinations as outcomes. The rule is linked to PROC-001 to PROC-005 and PROC-012, and PROC-012 moves to `detected` in `coverage/rubeus.yml`. False positives are non-LSA Kerberos stacks (Java, MIT Kerberos), which must be approved by path and signer.

### Re-review of the 2026-08-16 adoptions without logic change

- `rubeus_kerberos_over_http_proxy`: diverges from its proposal by OR-ing the client and destination approvals.
  - `= "application/kerberos" nocase` is a valid string-equality modifier.
  - Unset approval booleans read as false, so the rule fails open by design when enrichment is absent.
  - It requires process attribution (`principal.process.file.full_path != ""`), so proxy-only HTTP logs cannot satisfy it. This is an accepted gap; the closest compensating signal is `rubeus_ticket_use_without_credible_kdc_issue`.
- `rubeus_ticket_artifact_access_or_creation`: adds FILE_READ to the proposal and drops its process-path requirement. Name-based artifact matching remains an accepted gap (REVIEW-005).
- `rubeus_rc4_service_ticket_fanout` already covers the `rubeus_service_ticket_or_renewal_anomaly` and `rubeus_kerberoast_sequence` RC4 proposals (REVIEW-008).
- `rubeus_netonly_ticket_sequence` is unchanged: its proposal is rejected. The third leg requires a host-side Kerberos logon event carrying the net-only session LUID, which standard Windows auditing does not produce. Requiring it would remove existing coverage. Compensating signals: `rubeus_lsa_ticket_submission` and resource-side `rubeus_ticket_use_without_credible_kdc_issue`.

No unresolved blocker remains.

## Required follow-up

- Compile and field-map all rules in the target Google SecOps tenant.
- Validate with positive, benign, incomplete-log, missing-field, and near-threshold fixtures.
- Keep rules experimental; comprehensive source coverage does not imply production validation.
