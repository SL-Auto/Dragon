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

## Required follow-up

- Compile against the tenant YARA-L version and validate every UDM field using positive, negative, missing-event and reordered-event fixtures.
- Establish prerequisite dashboards for DC audit, LDAP 1644, WMI, Task Scheduler, RPC/NDR, registry/object SACL, application and EDR coverage.
- Tune thresholds by asset role and peer group; test concurrent benign activity for accidental joins.
- Have an authorized analyst independently review endpoint-protection-blocked source without changing controls, then revisit IMP-17 and affected branch accounting.
