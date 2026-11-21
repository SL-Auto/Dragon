# Impacket adversarial detection-logic review

## Review scope

- Rules: one rule per file under `detections/impacket/yaral/`
- Coverage: IMP-01 through IMP-22 at pinned revision `c23b3d55bc846a2460a459437601a94bfd25a269`
- Date/reviewer: 2026-08-15, Detection Research Agent
- Method: traced each event branch, join, threshold, mutable value and source dependency against the report; revised rules in the same run.

## Overall assessment

- Decision: `acceptable_experimental`
- Residual risk: high. These are telemetry hypotheses, not tool-identity rules or production-ready detections.
- Blockers: none in detection logic. IMP-17 and enumerated source files remain explicit source-coverage blockers rather than hidden assumptions.
- Re-review result: every observable family has a rule; offline-only IMP-12/20 are `not_observable`; exact Exchange behavior IMP-17 is `blocked_source`.

## Findings

### REVIEW-001 — Tool names are neither required nor sufficient

- Severity: `high`
- Affected: all rules
- Assumption challenged: Impacket can be identified by executable or default artifact names.
- Gap or failure mode: library reuse and renaming remove names; legitimate tools share protocols.
- Defensive impact: name rules miss activity and over-attribute common administration.
- Resolution: `fixed`
- Change: rules use service/task/WMI/directory/Kerberos/SMB/RPC effects and state that matches identify procedures, not Impacket.

### REVIEW-002 — Correlations can join unrelated events

- Severity: `high`
- Affected: service, relay, privilege-path rules
- Assumption challenged: time proximity proves causality.
- Gap or failure mode: busy DCs/servers, NAT and shared accounts create collisions.
- Defensive impact: false positives and attribution error.
- Resolution: `compensating_signal`
- Change: service joins require host and user; relay requires same user but different source; privilege joins require user. Best remaining compensator is logon ID, source/destination and object enrichment where tenant mappings support them.

### REVIEW-003 — Mandatory cleanup/output causes misses

- Severity: `high`
- Affected: service, WMI and task execution
- Assumption challenged: output files and successful cleanup always occur and arrive in order.
- Gap or failure mode: outputless operation, failed deletion and delayed ingestion.
- Defensive impact: false negatives.
- Resolution: `fixed`
- Change: WMI no longer requires a shell child or SMB output; tasks require registration/run but not deletion; service control has an authentication/effect rule independent of command text.

### REVIEW-004 — Parser field placement is unvalidated

- Severity: `high`
- Affected: LDAP filter, AD attribute, service path, access description and listener direction expressions
- Assumption challenged: every Chronicle parser populates the chosen UDM fields consistently.
- Gap or failure mode: vendor/version/parser changes move or omit raw values.
- Defensive impact: silent false negatives.
- Resolution: `accepted_gap`
- Change: prerequisites now name required raw semantics; rules remain `needs_validation`. This cannot be resolved without tenant telemetry. Validate alternate UDM locations before deployment.

### REVIEW-005 — Thresholds are environment-sensitive

- Severity: `medium`
- Affected: RPC discovery, Kerberos and service-authentication rules
- Assumption challenged: fixed counts separate normal from suspicious activity.
- Gap or failure mode: scanners exceed thresholds; low-and-slow activity remains below them.
- Defensive impact: false positives and negatives.
- Resolution: `compensating_signal`
- Change: thresholds are scoped by source/target/user and short windows. Recommended compensators are peer-group baselines, first-seen source/service and downstream effect correlation.

### REVIEW-006 — Optional telemetry is not universal

- Severity: `high`
- Affected: IMP-01/05/06/08/09/13/14/16/19/21
- Assumption challenged: object SACLs, LDAP 1644, RPC decoding, Sysmon WMI, raw-socket and application audit exist everywhere.
- Gap or failure mode: disabled channels make procedures unobservable.
- Defensive impact: coverage exists in code but not operationally.
- Resolution: `accepted_gap`
- Change: every rule declares prerequisites; coverage is conditional. Best compensators are EDR plus NDR, DC audit and application logs. Deployment must suppress rules whose prerequisites are absent rather than interpreting no alerts as no activity.

### REVIEW-007 — Broad security effects create benign overlap

- Severity: `medium`
- Affected: identity changes, Terminal Services, registry, WMI, SMB and SQL rules
- Assumption challenged: an effect is malicious by itself.
- Gap or failure mode: IAM, backup, deployment, monitoring and helpdesk use the same primitives.
- Defensive impact: alert fatigue.
- Resolution: `compensating_signal`
- Change: false-positive classes are explicit; no broad product/account exclusion was added. Tune using approved source, change window, signer/process ancestry and asset role, while retaining raw high-risk events.

### REVIEW-008 — Blocked source cannot be inferred into exact logic

- Severity: `high`
- Affected: IMP-17 and blocked branches in IMP-05/07/08/11/13/19/20/21/22
- Assumption challenged: readable neighboring code proves inaccessible implementation detail.
- Gap or failure mode: hidden branches may have materially different effects.
- Defensive impact: overstated completeness.
- Resolution: `fixed`
- Change: IMP-17 is `blocked_source`; other families cite only effects established by readable callers/helpers and retain blocked-path accounting. No endpoint protection bypass occurred.

## Implemented improvements and re-review

- Expanded four remote-execution rules to 19 observable procedure families.
- Removed shell-child dependence from WMI coverage and cleanup dependence from task coverage.
- Added separate service-effect correlation so command-line truncation does not eliminate all coverage.
- Added conditional coverage for SMB secrets, directory changes/searches, Kerberos, registry, RPC, service authentication, Terminal Services, packet capture and relay.
- Preserved offline-only procedures as `not_observable` and inaccessible Exchange behavior as `blocked_source`.
- Re-reviewed all conditions: no mutable tool filename is required; no broad allowlist suppresses signals; all multi-event rules use at least one contextual join; all rules remain experimental and need tenant validation.

## 2026-11-21 delta review — three rules added 2026-08-16, plus repository-wide ID anchoring

Scope:

- `impacket_ntlm_relay_with_privileged_effect`, `impacket_terminal_services_session_control_by_other_actor` and `impacket_wmi_activity_operational_class_signal`. They carried review metadata, but no finding existed for them.
- Base rules sharing REVIEW-009.

### REVIEW-009 — unanchored short event-ID alternations

- Severity: `high`
- Rules:
  - Base rules: `impacket_terminal_services_control`, `impacket_remote_registry_activity`, `impacket_wmi_subscription_change`, `impacket_rapid_scheduled_task_create_and_run`.
  - Compensating rule: `impacket_terminal_services_session_control_by_other_actor`.
- Gap or failure mode: patterns such as `/(4778|4779|23|24|25)/`, `/(4657|12|13|14|7036)/`, `/(19|20|21|5861)/` and `/(100|200)/` match any ID containing those digits. That includes 4625 (failed logon), 4723 (password change), 4720 (account created), 1102 (log cleared) and 5140 (share access). The result was false-positive storms and wrong semantics.
- Resolution: `fixed`. Every alternation is anchored `^(...)$`. The same defect was fixed in BloodHound (BH-DR-26). A repository-wide search now finds no remaining unanchored short-ID alternation.

### REVIEW-010 — relay rule matched any logon followed by administration

- Severity: `high`
- Rule: `impacket_ntlm_relay_with_privileged_effect`
- Gap or failure mode:
  - With no authentication-package or logon-type constraint, any network logon followed by a service, account or AD change by the same user on that host matched. That is ordinary administration, under a CRITICAL rule.
  - 4776 is credential validation logged on the DC, so its host is the validating DC, not the relay target, and it joined on the wrong host.
  - The order of events was not enforced.
- Resolution: `fixed`. The rule requires 4624 LogonType 3 with AuthenticationPackageName `NTLM`, drops 4776, anchors the effect IDs, and requires authentication before effect. Source IPs are kept as an outcome. Relay origin is still established by the base `impacket_cross_source_ntlm_relay`.

### REVIEW-011 — actor identity rarely present in session events

- Severity: `medium`
- Rule: `impacket_terminal_services_session_control_by_other_actor`
- Gap or failure mode: 4778/4779 and LocalSessionManager 23/24/25 natively record the session user. The acting user who issued a connect, disconnect or logoff against another session is normally absent. Placeholder inequality also let empty identities count as "different".
- Resolution:
  - `fixed`: both identities must be non-empty and are compared field to field; results aggregate per host.
  - `accepted_gap`: native logs do not carry the acting identity; only EDR- or RPC-enriched sources satisfy this rule. Compensating signal: base `impacket_terminal_services_control`.

### REVIEW-012 — WMI-Activity does not log successful method execution

- Severity: `medium`
- Rule: `impacket_wmi_activity_operational_class_signal`
- Gap or failure mode: WMI-Activity Operational records provider loads (5857), operation errors (5858) and subscriptions (5860/5861). It does not record successful `Win32_Process.Create` calls, so the rule sees mainly failures and subscriptions.
- Resolution:
  - `fixed`: IDs are anchored and results aggregate per host.
  - `accepted_gap`: the limit is inherent to the provider. Compensating signal: `impacket_remote_wmi_activity` (WmiPrvSE process lineage and network context).

### Re-review

All three rules and the four anchored base rules were re-traced:

- No blocker remains.
- No unanchored short-ID alternation remains.
- Sequences are ordered.
- Accepted gaps name compensating rules.

## Required follow-up

- Compile against the tenant YARA-L version and validate every UDM field using positive, negative, missing-event and reordered-event fixtures.
- Establish prerequisite dashboards for DC audit, LDAP 1644, WMI, Task Scheduler, RPC/NDR, registry/object SACL, application and EDR coverage.
- Tune thresholds by asset role and peer group; test concurrent benign activity for accidental joins.
- Have an authorized analyst independently review endpoint-protection-blocked source without changing controls, then revisit IMP-17 and affected branch accounting.
