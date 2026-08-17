# Havoc adversarial detection-logic review

## Overall assessment

- Revision: `c84f7755a8b1c0f737576bdd3a0e982a296012f1`
- Scope: all 12 canonical rules under `detections/havoc/yaral/` against HV-P01–HV-P22.
- Decision: `acceptable_experimental`; no unresolved blocker.
- Attribution: rules detect behavior and effects, not Havoc identity. Only the authorized server-audit rule names the product because that datasource is explicitly a sanctioned Havoc control plane.

## Findings

Across the findings below, the common **Assumption challenged:** is that normalized event names, PIDs and timing prove a complete causal procedure. The common **Gap or failure mode:** is missing or semantically different telemetry, entity ambiguity, benign overlap, or behavior outside a correlation window. Each finding records its own **Resolution:** and compensation.

## Findings and same-run improvements

### HV-DR-01 — Generic authentication created accidental token joins

- Severity: `high`
- Affected: HV-P12, `havoc_token_authentication_sequence`
- Gap: ordinary 4624 and 4672 events are common and do not prove explicit credentials or token manipulation; host/account timing could join unrelated execution.
- Resolution: `fixed`
- Change: removed generic 4624/4672 branches. The rule now requires Security 4648 or tenant-verified token duplicate/impersonate/create semantics before same-account execution. Logon ID or stable account-session enrichment remains a prerequisite.

### HV-DR-02 — PID is not a durable cross-event entity

- Severity: `high`
- Affected: all endpoint correlations
- Gap: PID reuse, sensor restarts and parser differences can create false joins or misses.
- Resolution: `accepted_gap`
- Compensation: every PID join also requires host and a 10–15 minute window. Deployment must replace PID with a process GUID/entity where available; all rules remain `needs_validation`.

### HV-DR-03 — Generic file correlation is broad and file reads are incomplete

- Severity: `medium`
- Affected: HV-P06–HV-P08
- Gap: browsers, backup and sync tools meet file-plus-network logic; many sensors omit reads and directory enumeration.
- Resolution: `compensating_signal`
- Change: retained medium severity and causal same-process join rather than adding mutable path exclusions. Analysts should prioritize deletion, sensitive-path access, unusual signer/prevalence and transfer byte context. Narrow environmental allowlists belong outside canonical logic.

### HV-DR-04 — Memory semantic event names are vendor-dependent

- Severity: `high`
- Affected: HV-P09–HV-P11
- Gap: PROCESS_INJECTION, REMOTE_THREAD, MEMORY_EXECUTION and CLR_ASSEMBLY_LOAD are hypotheses until parser mappings are verified; some sensors expose only process access or resulting effects.
- Resolution: `accepted_gap`
- Compensation: rule requires tenant-verified mapping and concurrent egress. Spawned interpreter, file staging and downstream behavior are independent signals. Do not enable an unbound semantic branch.

### HV-DR-05 — Native discovery can be low-volume or unlogged

- Severity: `high`
- Affected: HV-P04, HV-P13
- Gap: five-target fanout misses targeted single-object queries and local process enumeration; lowering the threshold would overwhelm defenders with legitimate administration.
- Resolution: `accepted_gap`
- Compensation: enable AD DS 1644, RPC/SMB and EDR discovery telemetry where available; correlate sensitive LDAP attributes, privileged targets and subsequent execution outside this generic fanout rule.

### HV-DR-06 — Recurrence is weak and cadence is configurable

- Severity: `medium`
- Affected: HV-P01, HV-P03
- Gap: legitimate agents recur, while sparse or unstable channels fall below five connections across three active minutes.
- Resolution: `fixed_with_compensating_signal`
- Change: recurrence remains medium severity and never attributes Havoc. Public beaconing logic highlighted that grouping unrelated destinations can inflate counts, so an independently designed `havoc_stable_destination_beaconing` rule now groups by host, process and destination and requires eight connections across four active minutes. The original rule remains as lower-confidence coverage for destination churn. Named-pipe, execution, injection, file, identity, forwarding, ticket, capture and cleanup rules provide independent effects.

### HV-DR-07 — Named-pipe literals and transport defaults are unsafe

- Severity: `high`
- Affected: HV-P02, HV-P15
- Gap: pipe names and transport profiles are configurable.
- Resolution: `fixed`
- Change: no pipe-name, URI, certificate, user-agent, process-name or infrastructure literal is used. The rule correlates pipe behavior with the same network-active process.

### HV-DR-08 — Screen capture and server audit may not exist

- Severity: `high`
- Affected: HV-P14, HV-P21
- Gap: standard Windows logs do not identify capture and adversary-controlled teamservers are invisible.
- Resolution: `accepted_gap`
- Compensation: rules are conditional on verified EDR or authorized-server mappings. File creation and egress are weaker victim-side alternatives; the server rule is not presented as universal coverage.

### HV-DR-09 — Pure memory bookkeeping and extension behavior cannot be bounded

- Severity: `high`
- Affected: HV-P18, HV-P19, HV-P22
- Gap: memory-file/job state may create no OS event, and external services can supply arbitrary future behavior.
- Resolution: `accepted_gap`
- Compensation: coverage marks these `not_observable`; use resulting execution/file/network effects and sanctioned control-plane audit. No invented direct detection was added.

### HV-DR-10 — Cleanup correlation can lose process identity

- Severity: `medium`
- Affected: HV-P20
- Gap: delayed/helper deletion or termination after telemetry loss breaks same-PID correlation; broad host-only joins are noisy.
- Resolution: `accepted_gap`
- Compensation: retain the higher-confidence same-process rule. Add standalone self-delete, service deletion and collection-health-gated disappearance analytics in tenant-specific content.

## Re-review result

- All 19 observable procedures link to at least one of 13 canonical rules; three inherently unavailable/unbounded procedures have explicit compensation.
- The high-severity token false-positive branch was removed in the same run.
- No mutable tool defaults or broad exclusions are completeness dependencies.
- Remaining gaps are telemetry-, entity- or extension-bound and are documented as experimental prerequisites rather than hidden assumptions.
- Safe validation requires synthetic UDM fixtures and benign administrative analogues only; Havoc must not be built or run.

## Required follow-up

- Compile all 13 rules in the target Chronicle tenant and bind every semantic event to verified parser output.
- Replace PID joins with stable process entities where available; validate account/logon-session joins and event delay.
- Baseline recurrence, discovery fanout, administrative proxies, management agents and sanctioned red-team activity.
- Keep every rule experimental until sanitized fixture evidence and collection-health behavior are recorded.
