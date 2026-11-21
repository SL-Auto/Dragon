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

## Required follow-up

- Compile and field-map all rules in the target Google SecOps tenant.
- Validate with positive, benign, incomplete-log, missing-field, and near-threshold fixtures.
- Keep rules experimental; comprehensive source coverage does not imply production validation.
