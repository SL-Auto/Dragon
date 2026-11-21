# Cobalt Strike Beacon adversarial detection review

## Overall assessment

The 38 rules (21 original plus 17 compensating signals reviewed 2026-11-21, findings DR-13 to DR-22) provide behavior-level coverage for all 31 procedures assessed as observable. They do **not** identify Cobalt Strike by themselves and remain `experimental` / `needs_validation`. The review removed dependence on mutable defaults, separated weak contextual signals from higher-value effects, strengthened correlations with stable process/account/host identities, and made vendor-specific visibility explicit. No blocker remains; accepted gaps are inherent to proprietary internals, custom modules/transports, missing sensor events, or in-memory/client-only behavior.

## Findings

### Finding DR-01 — mutable names and defaults

- Severity: `high`
- Assumption challenged: default process, pipe, service, URI, certificate, sleep interval or command-line values would persist.
- Gap or failure mode: profiles, spawn settings, argument/parent shaping, custom transports and extensions make fixed indicators incomplete and brittle.
- Resolution: `fixed`. Rules use behavioral event types, stable entities, process rarity/signing, sensitive targets and cross-event effects; no Beacon name, default pipe, service, URI, sacrificial image or exact cadence is required.

### Finding DR-02 — PID-only and host-only correlation

- Severity: `high`
- Assumption challenged: PID or host/account alone safely identifies the same actor across time.
- Gap or failure mode: PID reuse and concurrent administrators can create false joins; remote events may omit causal source context.
- Resolution: `fixed`. Process correlations use `entity_id` where available; alternate-identity and remote execution use bounded host/account windows. The telemetry plan requires logon/session/source fields and warns that missing stable identifiers degrades confidence.

### Finding DR-03 — network periodicity and destination assumptions

- Severity: `high`
- Assumption challenged: Beacon C2 is strictly periodic or uses stable infrastructure.
- Gap or failure mode: jitter, interactive mode, retry/exit logic, proxying and host rotation break regularity and fixed-destination logic.
- Resolution: `fixed`. C2 context accepts jittered repeated egress over 30 minutes, does not require one destination, and is explicitly medium severity. Separate DNS, named-pipe, socket-listen and fan-out rules provide compensating signals.

### Finding DR-04 — optional enrichment treated as native UDM

- Severity: `high`
- Assumption challenged: prevalence, entropy, sensitivity, runtime-expected and first-seen fields exist in every parser.
- Gap or failure mode: rules would silently fail or behave inconsistently without tenant enrichment.
- Resolution: `compensating_signal`. Metadata and telemetry requirements explicitly require these enrichments; dependent rules must remain disabled until verified. Effect rules using native events (service, injection, share, authentication) remain available as compensation. This is an `accepted_gap` because YARA-L cannot manufacture missing telemetry.

### Finding DR-05 — process injection coverage too narrow

- Severity: `high`
- Assumption challenged: every injection creates a remote thread or module load.
- Gap or failure mode: self-injection, manual mapping, alternative execution and Interpreter RW bytecode may omit those events.
- Resolution: `fixed`. The injection rule accepts remote-thread or executable-memory effects after process access, while a separate lineage/private-memory rule covers parent mismatch and in-process memory events. Interpreter and arbitrary BOF behavior still require resulting-effect coverage.

### Finding DR-06 — unmanaged runtime execution

- Severity: `medium`
- Assumption challenged: PowerShell always creates `powershell.exe` and assemblies always produce normal image/module artifacts.
- Gap or failure mode: unmanaged PowerShell and memory-hosted CLR can execute inside other processes.
- Resolution: `fixed`. Detection keys on PowerShell/CLR runtime telemetry in an unexpected host, not a process name. Missing runtime instrumentation is an `accepted_gap`; injection/memory and resulting behaviors compensate.

### Finding DR-07 — remote service causality

- Severity: `high`
- Assumption challenged: any 7045 or 4697 event alone indicates Beacon lateral movement.
- Gap or failure mode: software deployment creates high volume, and System 7045 lacks remote creator identity.
- Resolution: `fixed`. The higher-value rule correlates share access and service installation on target/account within ten minutes. Service-only elevation remains a separate contextual rule, preserving coverage when share auditing is absent without claiming attribution.

### Finding DR-08 — combined WinRM/WMI/SSH semantics

- Severity: `medium`
- Assumption challenged: these remote protocols share identical providers and fields.
- Gap or failure mode: parser field differences can break a combined condition and remote session events may not map the child identity.
- Resolution: `compensating_signal`. The combined rule uses normalized semantic session types only after parser verification and requires target/account child correlation. Atomic raw-provider requirements remain separate in telemetry. Disable any unavailable branch rather than treating it as mandatory.

### Finding DR-09 — direct observation of discovery and collection

- Severity: `medium`
- Assumption challenged: local Win32 enumeration, clipboard, screen and input APIs are universally logged.
- Gap or failure mode: standard Windows audit often has no direct event.
- Resolution: `compensating_signal`. Discovery uses network/directory fan-out when available; collection depends on vendor-specific capture events and sensitive file/browser effects. Procedures CSB-003, CSB-010 and CSB-029 are correctly `not_observable` rather than covered by invented signals.

### Finding DR-10 — false attribution to Cobalt Strike

- Severity: `blocker`
- Assumption challenged: a behavioral match can name the tool.
- Gap or failure mode: every covered procedure is shared with legitimate software and other offensive tooling.
- Resolution: `fixed`. Rule descriptions and rationale state they are Beacon-compatible behavior/context, not attribution. No rule uses a tool-specific claim; attribution requires multiple independent signals plus contextual or forensic evidence.

### Finding DR-11 — correlation ordering and missing-event behavior

- Severity: `medium`
- Assumption challenged: events arrive in causal order and all required sources are complete.
- Gap or failure mode: forwarding delay and partial collection can invert or omit sequences.
- Resolution: `fixed`. Correlations are order-independent bounded windows; no rule uses absence as evidence. Telemetry requirements state that missing fields/sources disable or weaken a rule.

### Finding DR-12 — extension/custom transport completeness

- Severity: `high`
- Assumption challenged: core rules can enumerate arbitrary operator modules and UDC2 implementations.
- Gap or failure mode: third-party code can produce any behavior and proprietary source prevents internal-path verification.
- Resolution: `compensating_signal`. Dispatch/in-memory/network surfaces plus resulting effects are covered; each pinned external artifact needs separate analysis. This is an `accepted_gap` inherent to unbounded inputs, not an unassessed core procedure.

## Improvements applied and re-review

- Removed all fixed Beacon names and mutable default indicators.
- Split C2 into HTTP/process egress, DNS, named pipe, bind/custom socket and forwarding/fan-out hypotheses.
- Used stable process entities for injection, file/egress and fan-out correlation.
- Added explicit rare/signer, sensitivity, entropy and runtime enrichment prerequisites rather than assuming parser availability.
- Correlated remote service installation with share access while preserving a lower-context service/elevation signal.
- Covered unmanaged PowerShell/CLR and Interpreter/BOF behavior through runtime, injection, memory and resulting-effect signals.
- Kept three genuinely client/in-memory configuration surfaces `not_observable` and documented compensating telemetry.
- Re-review found no unresolved blocker. Remaining high/medium gaps require tenant parser validation or telemetry that is not universally available.

## 2026-11-21 delta review — 17 comparison-adopted compensating signals

Scope: the 17 `*_compensating_signal` rules written into `yaral/` on 2026-08-16 from comparison proposals. They carried `review_status = "reviewed_with_gaps"`, but no finding existed for them. Five base rules that share one defect (DR-13) are included.

### Finding DR-13 — event types absent from the telemetry inventory

- Severity: `high`
- Rules: directory discovery, DNS, file cleanup, named pipe, remote service, sensitive file compensating signals; base rules `cobalt_strike_directory_discovery`, `cobalt_strike_dns_process_context`, `cobalt_strike_file_cleanup_or_timestomp`, `cobalt_strike_named_pipe_peer_activity`, `cobalt_strike_sensitive_file_activity`.
- Assumption challenged: the event-type names used exist in the repository's normalization.
- Gap or failure mode: `LDAP_QUERY`, `DNS_QUERY`, `FILE_DELETE`, `PIPE_CONNECT` and `FILE_WRITE` appear nowhere in `telemetry/MASTER.md`. The rest of the repository uses `LDAP_SEARCH`, `NETWORK_DNS`, `FILE_DELETION`, `NAMED_PIPE_CONNECTION`/`NAMED_PIPE_CREATION` and `FILE_CREATION`/`FILE_MODIFICATION`. A parser following the inventory would never match these rules.
  - `cobalt_strike_dns_process_context` had no alternative branch at all.
  - The other base rules survived only through their Sysmon event-ID branches.
- Resolution: `fixed`. The inventory names were added additively; the old names are kept as vendor aliases.

### Finding DR-14 — cross-host PID join

- Severity: `high`
- Rule: `cobalt_strike_credential_access_effect_compensating_signal`
- Gap or failure mode: the match key was `$pid` alone, so an LSASS open on one host and a dump file created on another host with the same PID would correlate.
- Resolution: `fixed`. Host was added to both events and to the match key; the rule now uses `product_specific_process_id`.

### Finding DR-15 — unordered sequences

- Severity: `medium`
- Rules: credential access, file cleanup, named pipe, privileged context, remote service, sensitive file, socket fanout, socket listen, memory/thread, user data.
- Gap or failure mode: each rule's description states an order (for example, open then dump, or listen then accept), but the events never enforced it. Reversed benign activity, such as a dump file created before an unrelated LSASS scan, satisfied the rule.
- Resolution: `fixed`. Explicit `event_timestamp.seconds <=` ordering was added. Clock skew between sensors is a residual risk, and the windows are kept unchanged to absorb it.

### Finding DR-16 — approval enrichment fails closed

- Severity: `high`
- Rules: directory discovery, discovery fanout, sensitive registry, integrity transition, memory/thread.
- Gap or failure mode: `approved_* = false` requires the enrichment to be present. When the allowlist enrichment is missing, the field is empty and the rule silently never matches, so missing enrichment looks like benign activity.
- Resolution: `fixed`. The predicates are now `!= true`: absent enrichment fails open (more alerts, no silent loss) and only an explicit approval suppresses.

### Finding DR-17 — placeholder comparison in condition

- Severity: `blocker`
- Rule: `cobalt_strike_dns_process_context_compensating_signal`
- Gap or failure mode: `($rtype = 16 or $rtype = 10)` compared a multi-valued placeholder inside `condition`. That is not valid YARA-L, and even if it compiled it would be semantically undefined across the aggregated window.
- Resolution: `fixed`. The record-type predicate moved into `events`, and the distinct-query count is now an outcome. The prerequisites also note that DNS Client service-attributed resolver logs cannot attribute the requesting process.

### Finding DR-18 — CLR rule missed the sacrificial-process pattern

- Severity: `high`
- Rule: `cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal`
- Gap or failure mode: in-memory assembly execution and unmanaged PowerShell (CSB-015/017) typically load the CLR into a spawned native, signed, prevalent Windows binary. The rule required an unsigned or rare loader, so it missed exactly that case. The OR of unsigned/rare also fired on every unsigned internal .NET application.
- Resolution: `fixed`. One branch now matches CLR loads into native Windows host binaries that are not .NET applications (rundll32, dllhost, regsvr32, werfault, searchprotocolhost, gpupdate, spoolsv, notepad, svchost, wuauclt, mstsc). The other branch requires unsigned AND rare. `msiexec` was deliberately excluded because managed installer custom actions load the CLR. Residual false negatives: an operator-chosen host that is itself a .NET application. Compensating signal: the base rule's runtime telemetry.

### Finding DR-19 — exact path join between UNC write and service image path

- Severity: `high`
- Rule: `cobalt_strike_remote_service_sequence_compensating_signal`
- Gap or failure mode: the staged write is observed as a UNC/admin-share path or a target-local path, while the 7045 ImagePath may be local, UNC, quoted or carry arguments. Exact string equality almost never holds without a normalization layer the prerequisites did not provide.
- Resolution: `fixed`. Both sides are joined on the captured image file name (executable/script extension), and both paths are kept as outcomes for triage. Benign deployment tools that reuse one file name remain the main false-positive source, as before.

### Finding DR-20 — non-UDM process entity field

- Severity: `medium`
- Rules: socket fanout, socket listen, user data.
- Gap or failure mode: `process.entity_id` is not a UDM field; the rest of the repository correlates on `product_specific_process_id`. Joins on the unmapped field would be empty.
- Resolution: `fixed`. The rules now use `product_specific_process_id`, and host was added to every joined event. Base rules `cobalt_strike_cross_process_injection` and `cobalt_strike_discovery_fanout` still use `entity_id`; this is recorded as follow-up because those rules are outside this delta.

### Finding DR-21 — enrichment-dependent fields

- Severity: `medium`
- Rules: all rules using `is_signed`, `prevalence`, `sensitivity`, `domain_baseline_rarity`, `pipe_prevalence`, `interval_variance_bucket` or `dangerous_memory_rights`.
- Gap or failure mode: these are tenant enrichments, not native telemetry. When they are absent, the rule is silent or degrades to broad behavior.
- Resolution: `accepted_gap`. They cannot be derived from raw events. Every one is listed in the rule prerequisites and in `telemetry/cobalt-strike-beacon.md`, and the base rule for each procedure remains the compensating signal.

### Finding DR-22 — beacon periodicity enrichment

- Severity: `low`
- Rule: `cobalt_strike_process_network_context_compensating_signal`
- Gap or failure mode: periodicity relies on an upstream `interval_variance_bucket`; jittered or sleep-masked beacons may not reach `LOW`.
- Resolution: `accepted_gap`. YARA-L cannot compute inter-arrival variance natively. Compensating signal: the base rarity and fan-in rule and the stable-destination recurrence rules.

### Re-review of revised rules

All 17 rules were re-traced after the changes above:

- No blocker remains.
- Every joined event carries host.
- Every sequence enforces order.
- Every approval enrichment fails open.
- Every event type matches the inventory, with legacy names kept as aliases.
- Every count is computed in `outcome`.

## 2026-11-21 delta review — remaining four deferred comparisons

The comparisons for `cobalt_strike_alternate_identity_process`, `cobalt_strike_cross_process_injection`, `cobalt_strike_remote_management_execution` and `cobalt_strike_unusual_authentication_material_use` still read `deferred_pending_rule_improvement_run`. Canonical logic had not acted on any of them.

### Finding DR-23 — remote-management child joined only by account

- Severity: `medium`
- Rule: `cobalt_strike_remote_management_execution` (base), new `cobalt_strike_remote_management_execution_compensating_signal`.
- Gap or failure mode: the base rule pairs a WinRM, WMI or SSH session with any process launched by the same account on the target within 10 minutes. An interactive or scheduled process by that account satisfies it, so the executed command is never tied to the remote channel.
- Proposal defects:
  - It reads the parent from `principal.process.parent_process`, which in a UDM PROCESS_LAUNCH is the grandparent, since `principal.process` is the launcher.
  - It uses a non-inventory `REMOTE_SESSION` event type.
  - It requires a source-side event, which fails when the operator host is unmonitored.
- Resolution: `compensating_signal`. The new rule keeps the base's target-side session types and requires the launching process (`principal.process.file.full_path`) to be wsmprovhost.exe, wmiprvse.exe or sshd. It joins on host and account, session first. It uses OS service-host lineage only, with no mutable tool names.

### Finding DR-24 — three proposals rejected

- Severity: `medium`
- Rules: unchanged.
- `cobalt_strike_alternate_identity_process`: the proposal matches every successful AUTHENTICATION by any user (`#target >= 1`), with no link to the 4648 alternate identity. Resource-side confirmation would need a cross-host join (4648 TargetServerName to a 4624 on that server with the source workstation), and WorkstationName is not reliably populated for Kerberos network logons. Compensating signal: `cobalt_strike_unusual_authentication_material_use`.
- `cobalt_strike_cross_process_injection`: the proposal replaces stable `process.entity_id` joins with reusable PIDs and hard-requires a `dangerous_memory_rights = true` enrichment, which fails closed. The base rule already joins the opener to the effect on the same source and target entities, which is the strongest causal link the telemetry supports.
- `cobalt_strike_unusual_authentication_material_use`: the proposal's syntax is invalid (`not $issue...` in events, `not $issue` in condition). Its 20-minute absence window is far shorter than service-ticket lifetime, so it would alert on every logon that reuses a cached ticket. The sound form, with a 12-hour window, a domain-joined collection-health gate and a PAC-anomaly requirement, already exists as `rubeus_ticket_use_without_credible_kdc_issue` (Rubeus REVIEW-013).
- Resolution: `rejected`. Proposed code is preserved in each comparison.

### Accepted limitation noted on re-review

- `cobalt_strike_alternate_identity_process` joins the 4648 target account to a process running as that account. A new-credentials (net-only) token keeps the original user on the process, so that pattern does not satisfy the join.
- `accepted_gap`. Standard process telemetry does not expose the network identity of a new-credentials token. Compensating signals: 4624 LogonType 9 analytics and resource-side authentication rules.

## Required follow-up

1. Compile every rule in the target Google SecOps tenant after mapping semantic event types and enrichment fields to actual UDM.
2. Disable rules whose required vendor event or enrichment is absent; do not weaken them into name-only logic.
3. Replay sanitized benign EDR, administration, deployment, identity, DNS, proxy and remote-management fixtures.
4. Baseline prevalence, fan-out, query entropy/cardinality and authorized remote-management identities per environment.
5. Evaluate alerts as behavior clusters; never label a host Cobalt Strike-positive from one rule.
6. Re-review whenever Fortra changes Beacon, the parser changes, or a new third-party module/UDC2 artifact enters scope.
