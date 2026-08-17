# Cobalt Strike Beacon adversarial detection review

## Overall assessment

The 21 rules provide behavior-level coverage for all 31 procedures assessed as observable. They do **not** identify Cobalt Strike by themselves and remain `experimental` / `needs_validation`. The review removed dependence on mutable defaults, separated weak contextual signals from higher-value effects, strengthened correlations with stable process/account/host identities, and made vendor-specific visibility explicit. No blocker remains; accepted gaps are inherent to proprietary internals, custom modules/transports, missing sensor events, or in-memory/client-only behavior.

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

## Required follow-up

1. Compile every rule in the target Google SecOps tenant after mapping semantic event types and enrichment fields to actual UDM.
2. Disable rules whose required vendor event or enrichment is absent; do not weaken them into name-only logic.
3. Replay sanitized benign EDR, administration, deployment, identity, DNS, proxy and remote-management fixtures.
4. Baseline prevalence, fan-out, query entropy/cardinality and authorized remote-management identities per environment.
5. Evaluate alerts as behavior clusters; never label a host Cobalt Strike-positive from one rule.
6. Re-review whenever Fortra changes Beacon, the parser changes, or a new third-party module/UDC2 artifact enters scope.
