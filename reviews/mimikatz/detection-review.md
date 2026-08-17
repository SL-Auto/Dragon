# Mimikatz detection-logic review

## Review scope

- Rule files: one rule per file under `detections/mimikatz/yaral/`
- Rule revision/commit: working tree after baseline commit `cb145be`
- Source report: `reports/mimikatz/source-analysis.md`
- Review date: 2026-08-15
- Reviewer: Detection Research Agent

## Overall assessment

- Decision: `acceptable_experimental`
- Residual risk: High until the target Google SecOps parser and representative telemetry are available.
- Telemetry confidence: Medium for the Windows primitives; low for the proposed UDM normalization and custom context labels.

## Findings

### REVIEW-001 — Process-open normalization is an assumption

- Severity: `high`
- Affected rules/procedures: `mimikatz_lsass_memory_access`, PROC-001
- Assumption challenged: Sysmon Event 10 will normalize as `PROCESS_OPEN`, put the accessed image under `target.process`, and expose access rights in `security_result.description`.
- Gap or failure mode: A parser may use another event type or field, omit access text, or encode the mask numerically. The current expression could miss all applicable events.
- Defensive impact: False negatives for LSASS access despite raw telemetry being present.
- Evidence: `reports/mimikatz/source-analysis.md`, PROC-001 telemetry assessment.
- Resolution: `compensating_signal`
- Rule change or compensating signal: Revised the rule to accept either normalized `PROCESS_OPEN` or raw product event type `10` and removed the broad process-name exclusion that could suppress unrelated access. Parser verification remains required.
- Validation needed: Export sanitized normalized Sysmon Event 10 records and verify every field and access-mask representation.

### REVIEW-002 — Registry-read event and PID join may be unavailable

- Severity: `high`
- Affected rules/procedures: `mimikatz_protected_sam_system_access_sequence`, PROC-002
- Assumption challenged: Sensitive registry reads normalize as `REGISTRY_READ` and both events retain the same source PID.
- Gap or failure mode: Many sensors collect registry writes only; PID reuse or missing process IDs can break or misjoin the sequence. Offline hive access bypasses registry telemetry entirely.
- Defensive impact: False negatives and occasional cross-process false correlation.
- Evidence: `reports/mimikatz/source-analysis.md`, PROC-002 gaps.
- Resolution: `compensating_signal`
- Rule change or compensating signal: Strengthened the join from host/PID alone to host, PID, process path, and user. Offline hive file access remains a separate required follow-up because general file-read telemetry is not guaranteed.
- Validation needed: Test missing-PID, reused-PID, offline-hive, and registry-write-only fixtures.

### REVIEW-003 — DCSync description matching and custom allowlist label are brittle

- Severity: `high`
- Affected rules/procedures: `mimikatz_dcsync_non_dc_replication_access`, PROC-003
- Assumption challenged: Replication GUIDs/names appear in `security_result.description`, and assets carry `approved_dc_or_sync` in `principal.labels.value`.
- Gap or failure mode: Localized rendering, parser changes, missing labels, or an approved identity used from an unapproved host can defeat or distort the rule.
- Defensive impact: False negatives or excessive alerts; a broad asset label may suppress risky context.
- Evidence: `reports/mimikatz/source-analysis.md`, PROC-003 telemetry gaps.
- Resolution: `fixed`
- Rule change or compensating signal: Removed the single custom-label suppression entirely and lowered severity from critical to high until verified identity and source-host context is added downstream. The rule now favors recall and cannot be bypassed through that broad label.
- Validation needed: Verify GUID parsing across DC versions/locales and test approved-account/unapproved-host cases.

## Required follow-up

- Compile in Google SecOps after substituting tenant parser mappings.
- Add positive, negative, missing-field, and near-miss fixtures before changing validation status.
- Keep all three rules experimental until these high findings are resolved or concretely compensated.

## Implemented improvements

- Removed hard-coded security-product process exclusions from LSASS access.
- Added a raw Event ID 10 fallback and stronger registry correlation keys.
- Removed the brittle one-label DCSync allowlist and made approved context a triage requirement.

## Comprehensive reconciliation review (2026-08-15)

- Scope: all one-rule-per-file detections under `detections/mimikatz/yaral/`, mapped to P01-P46.
- Decision: `acceptable_experimental`; no unresolved blocker. All rules remain `needs_validation`.

### REVIEW-004 — Broad contextual rules could be mistaken for attribution

- Severity: `high`; affected: process/file, Kerberos, discovery, device, RPC, service and account-change rules.
- Finding: the underlying events are common and cannot identify Mimikatz. A filename, command, pipe name, patch byte, or hash filter would be mutable and unsafe.
- Resolution: `fixed`. Rules use behavior/product events, explicitly state contextual severity and false positives, and avoid Mimikatz names/defaults. Low-specificity procedures are LOW/MEDIUM and must be correlated downstream. Coverage means a signal exists, not attribution.

### REVIEW-005 — Product event IDs collide across providers

- Severity: `high`; affected: rules accepting `6`, `7`, `17`, `18`, `104` and account/directory IDs.
- Finding: `product_event_type` is not meaningful without provider/product scoping; parsers may normalize differently.
- Resolution: `accepted_gap`. Prerequisites now require the named Windows/Sysmon provider and tenant parser validation. No broad exclusions were added. Best compensation is normalized event type plus provider enrichment in deployment.

### REVIEW-006 — Description regex fields are parser hypotheses

- Severity: `high`; affected: process tamper, store, firmware, discovery, device and RPC rules.
- Finding: vendor text can be absent, localized or moved to structured fields.
- Resolution: `accepted_gap`. These remain experimental hypotheses until representative UDM is available. Rules favor recall and do not suppress missing enrichment; deployment must replace text matching with verified structured fields. Existing LSASS and DCSync alternatives retain raw event fallbacks.

### REVIEW-007 — Offline computation cannot be detected honestly

- Severity: `medium`; affected: P08, P11, P17.
- Finding: LSASS-dump parsing, offline ticket construction/crypto, and offline DPAPI computation emit no intrinsic OS event.
- Resolution: `accepted_gap`. Coverage marks them `not_observable`, rather than claiming file telemetry proves the computation. Compensating signals are acquisition/input reads, output creation and subsequent credential/ticket use.

### REVIEW-008 — Single-event rules lack attribution and sequence

- Severity: `medium`; affected: most broad rules.
- Finding: without authorized baseline data, invented time windows or joins would introduce PID reuse, missing-field and ordering assumptions.
- Resolution: `fixed`. Only the SAM/SYSTEM rule retains a defensible same-process five-minute correlation with host, PID, image and user. Other rules are atomic signals intended for tenant-specific correlation after field validation. No unsafe global allowlists are embedded.

### REVIEW-009 — Telemetry absence can defeat whole procedure families

- Severity: `high`; affected: registry/file reads, token, clipboard/device, RPC, firmware and injection.
- Finding: standard Windows logging does not collect many reads/API calls; a rule cannot recover absent telemetry.
- Resolution: `accepted_gap`. Every rule names prerequisites, and the report documents compensating signals. Coverage status `detected` means detection is possible when prerequisites exist, not universally observable.

## Re-review of revised rules

The revised set has no broad signer/process allowlists, no mutable tool-name dependency, no unsupported cross-host PID join, and no claim of production readiness. Remaining high findings are inherent parser/collection dependencies and are explicitly accepted with compensating telemetry. Required next step is compilation and positive/negative/missing-field testing against authorized Google SecOps UDM before changing `needs_validation`.

## Public-rule comparison resolution (2026-08-16)

- Scope: drained the `deferred_pending_rule_improvement_run` backlog across all 17 `public-rules/comparisons/mimikatz/*.md` files. Every comparison's "Candidate improvement" was re-run against the procedure-branch matrix, `coverage/mimikatz.yml`, `telemetry/mimikatz.md`, `schemas/chronicle-udm.yml` and the existing canonical rules.
- Systemic finding: all 17 proposed rules depend on invented `metadata.product_event_type` literals (for example `NETLOGON_SECRET_CHANGE`, `CLIPBOARD_READ`, `LSA_KERBEROS_TICKET_SUBMIT`, `CAPI2_KEY_EXPORT`, `RPC_CALL`) and invented boolean trust/approval labels (for example `principal.labels["approved_password_manager"]`, `principal.process.file.labels["trusted_key_manager"]`, `target.resource.attribute.labels["security_sensitive"]`) that are not documented in `schemas/chronicle-udm.yml`, not sourced from any capability in `telemetry/mimikatz.md`, and not populated by any telemetry path described in `reports/mimikatz/source-analysis.md`. This reproduces, at larger scale, exactly the brittle single-label allowlist pattern that REVIEW-003 already found `high` severity and removed. Because these fields do not exist in any described telemetry source, rules built on them would silently never match (false negative by default) rather than fail open, which is a more severe defect than REVIEW-003's original finding.
- 15 of 17 comparisons were decided `reject` on this basis, or because the comparison's own coverage conclusion was `insufficient_evidence`/`equivalent`/`ours_stronger` (no public rule actually demonstrates a real capability gap), or because the required telemetry for the proposed branch does not exist per the source report (Kerberos in-memory ticket submission has no OS event, matching the already-`not_observable` P11 finding). Per-comparison reasons are recorded in each file's Decision Trail.
- 2 of 17 comparisons (`mimikatz_sensitive_store_access`, `mimikatz_service_driver_module_change`) identified genuine, evidenced gaps (multi-family credential-store access; module load into a protected process) that are implementable using only fields and event identifiers already established elsewhere in this ruleset (`metadata.event_type`, `metadata.product_event_type = "7"`, `principal.hostname`, `principal.process.product_specific_process_id`, `principal.user.userid`, `target.resource.name`, `principal.process.file.full_path`) — no invented labels or event types. These were decided `modify` and implemented as new, additive compensating rules rather than rewrites of the existing atomic rules, preserving the atomic-signal architecture established in REVIEW-008.

### REVIEW-010 — `mimikatz_sensitive_store_multi_family_access` (new rule)

- Severity: `high`
- Affected: `mimikatz_sensitive_store_multi_family_access`, P18/P19/P20/P23/P25/P37/P41/P46.
- Assumption challenged: `target.resource.name` is populated for both `FILE_READ` and `REGISTRY_READ` across vendors, and `principal.process.product_specific_process_id` is stable and not reused within the 15-minute match window.
- Gap or failure mode: same read-telemetry scarcity and PID-reuse risk already documented in REVIEW-002; legitimate backup, migration, browser-sync and credential-manager tooling can plausibly touch two families in one session, producing false positives. If a vendor only emits one of the two families as read telemetry (a documented TEL-003 gap), the rule silently under-fires.
- Defensive impact: false positives from legitimate multi-family tooling; false negatives when either family lacks read telemetry.
- Resolution: `compensating_signal`. This rule is additive — it supplements, not replaces, the existing broad `mimikatz_sensitive_store_access` atomic rule, which is unchanged. It must remain `needs_validation` and requires benign-baseline testing against local backup/credential-manager software before any active response is attached.
- Validation needed: representative fixtures for both a genuine multi-family attacker sequence and known-legitimate multi-family sessions (profile migration, backup agents); confirm at least two vendor products emit read telemetry with resolvable resource paths.

### REVIEW-011 — `mimikatz_module_load_into_lsass_or_spooler` (new rule)

- Severity: `high`
- Affected: `mimikatz_module_load_into_lsass_or_spooler`, P06/P36/P44/P45.
- Assumption challenged: raw `metadata.product_event_type = "7"` means Sysmon Image Load in every deployed sensor, and `principal.process.file.full_path` reliably contains the loading process (not the loaded module) for this event.
- Gap or failure mode: non-Sysmon EDR products may reuse the numeric ID "7" for an unrelated event (the same provider-scoping gap accepted in REVIEW-005). High benign volume is expected: legitimate third-party SSPs/smartcard middleware load into `lsass.exe`, and OEM print-monitor DLLs load into `spoolsv.exe`, on any typical domain-joined fleet.
- Defensive impact: false positives from legitimate authentication-package and print-monitor loading; false negatives if the sensor does not enable or normalize Image Load telemetry, or maps the raw ID differently.
- Resolution: `accepted_gap` for the provider/product-mapping ambiguity (per REVIEW-005 precedent); `fixed` for scope — the rule intentionally targets only the two named, historically abused target processes (`lsass.exe` for mimilib/mimikatz SSP registration, `spoolsv.exe` for mimispool) rather than all module loads, and does not invent a `trusted_module` label that no telemetry source documents, keeping the false-positive surface bounded and auditable.
- Validation needed: baseline the population of legitimate LSA SSPs and print-monitor DLLs on representative hosts; confirm Sysmon/EDR Event ID 7 is enabled and the loading-process field mapping is correct before use.

### Re-review of the two new rules

Both new rules use only fields already established by the existing reviewed ruleset (no new schema dependency), keep `status = "experimental"` and `validation_status = "needs_validation"`, and are additive compensating signals rather than replacements — the previously reviewed atomic rules `mimikatz_sensitive_store_access` and `mimikatz_service_driver_module_change` are unchanged. No blocker findings were raised.
