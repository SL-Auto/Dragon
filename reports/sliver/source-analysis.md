# Sliver comprehensive procedure analysis

> Scope correction (2026-08-15): active completeness and detections cover only the victim-side Sliver implant/agent and host-observable effects. Server listeners, builds, hosted content, loot/credential stores, operator automation, and UI discussion below is retained as protocol context and historical evidence, but is excluded from procedure counts and detection scope.

## Scope, provenance, and completeness method

- Revision: `13c2d3344927429cf55f6f7212499087e804bf47`; input: complete static checkout at `sources/sliver-src-pinned`; accessed/analyzed 2026-08-15. Nothing was built or executed.
- Primary evidence: [official pinned tree](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47). Capability completeness was reconciled from the implant registries for [Windows](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L56-L134), [Linux](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_linux.go#L46-L102), [Darwin](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_darwin.go#L34-L84), [generic targets](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_generic.go#L35-L60), [tunnels](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tun.go#L33-L48), [pivots](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/pivot-handlers.go#L33-L39), operator command packages, and server RPC surfaces.
- Tests, generated protobuf bindings, vendored dependencies, CI/build packaging, and documentation assets were inspected for scope but excluded because they introduce no independent runtime procedure. Generated implant templates were statically read, never rendered. Confidence is high for source behavior and medium for telemetry hypotheses.

## Completeness inventory

| Surface | Accounted procedures |
|---|---|
| lifecycle, limits, session/beacon, reconfigure, kill | PROC-001–002 |
| mTLS, HTTP/S, DNS, WireGuard, proxy, TCP/named-pipe pivot C2 | PROC-003–005 |
| host/process/service/network/mount/environment discovery | PROC-006 |
| full filesystem, transfer, permissions, timestamps, memfiles | PROC-007–009 |
| execute, shell, task/shellcode, migrate, assembly, sideload/spawndll, native/WASM extensions | PROC-010–013 |
| screenshot and process dump | PROC-014–015 |
| token/credentialed execution/getsystem | PROC-016–017 |
| Windows registry and services | PROC-018–019 |
| remote service and SSH movement | PROC-020 |
| port/reverse forwarding, SOCKS and interactive tunnels | PROC-021 |
| cursed browser/Electron and external module ecosystem | PROC-022 |
| listeners/stagers/sites/builds and server loot/credentials/tasks/operators/automation | PROC-023–025 |
| every implant/server teardown path | PROC-026 |

Windows has identity, registry, service, assembly and migration branches; Linux adds dump, permission and memfile branches; Darwin adds native extensions, screenshot, mount and SSH; generic targets retain core filesystem/process/environment/reconfigure/WASM. Unsupported build-tag stubs return unavailable and are not additional behavior.

## Procedures

### PROC-001 — Initialization, host identity, and execution limits

Generated main evaluates configured time/host/user/locale/domain/file limits, gathers identity, then starts session or beacon operation; unmet limits exit. Reconfigure changes name and timing. Evidence: [main](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/main.go#L36-L104), [limits](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/limits/limits.go#L33-L79). ATT&CK: T1082, T1033, T1124, T1497.001. **Telemetry:** process start/exit (image, hash, signer, parent, user), targeted file access and identity/domain telemetry. Most environment reads are `not_observable`; compensate with subsequent process-network behavior. Enable EDR/process and sensitive-path audit; validate with benign fixtures.

### PROC-002 — Session/beacon lifecycle, tasking, reconnect, and kill

Sessions maintain interactive connections; beacons sleep with jitter, check in, obtain tasks and return results. Failure rotates endpoints; kill closes transport, exits and may self-delete. Evidence: [session](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/session.go#L67-L159), [beacon](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/beacon.go#L62-L153), [kill](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/kill-handlers.go#L36-L64). ATT&CK: T1071, T1105, T1070.004. **Telemetry:** process-linked flow/DNS/TLS/HTTP timing and bytes, process exit, EDR file deletion. Jitter and encrypted tasks are gaps; validate with sanitized logs.

### PROC-003 — mTLS and HTTP(S) C2

Endpoint selection is sequential/random; dispatch invokes mTLS or configurable HTTP(S) methods, paths, headers, cookies and encoders, including native WinINet and system proxy discovery. Evidence: [selection](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/transports.go#L49-L119), [dispatch](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/session.go#L87-L146), [HTTP client](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/httpclient/httpclient.go#L62-L149). ATT&CK: T1071.001, T1573.002. **Telemetry:** EDR/firewall/proxy/TLS events with process, destination, SNI/certificate, method/URI/header, bytes. Profiles are mutable and content encrypted; enable process-network/TLS metadata and validate synthetic schemas.

### PROC-004 — DNS and WireGuard C2

DNS carries encoded fragments through configured domains; WireGuard establishes an encrypted virtual network. Evidence: [DNS code](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/dnsclient), [WireGuard code](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/transports/wireguard). ATT&CK: T1071.004, T1572, T1573. **Telemetry:** DNS client/qname/type/response/size/rate and UDP flow/process ownership. Resolvers obscure source and WireGuard overlaps VPNs; retain full DNS/flow metadata and validate benign DNS/VPN datasets.

### PROC-005 — Pivot C2 listeners and peer routing

Implants start/stop TCP or named-pipe listeners, accept peers and frame/route peer envelopes over parent C2. Evidence: [registry](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/pivot-handlers.go#L33-L39), [implementation](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/pivots). ATT&CK: T1090, T1572. **Telemetry:** EDR socket listen/accept, east-west flow, named-pipe create/connect (Sysmon 17/18), process/pipe/endpoints/user. Unix/pipe coverage varies; validate benign IPC/listeners.

### PROC-006 — Host, process, service, network, mount, and environment discovery

Handlers return processes, interfaces/connections, environment, directory/mount and Windows service data. Evidence: platform registries above; [process code](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/ps), [netstat](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/netstat), [services](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/service/service_windows.go#L139-L219). ATT&CK: T1057, T1016, T1082, T1083, T1007, T1120. **Telemetry:** usually `not_observable` through standard logs for in-process API reads; vendor API/handle telemetry may help. Compensate with C2 plus subsequent activity; test visibility with benign inventory tools.

### PROC-007 — File/directory discovery, reads, search, and collection

`ls/pwd/cd/cat/head/tail/grep/download` read, search, recursively collect and return content. Evidence: [handlers](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers.go#L147-L403), [commands](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/client/command/filesystem/commands.go#L40-L251). ATT&CK: T1083, T1005, T1119. **Telemetry:** EDR file-read or selective 4663/auditd plus process/path/user/bytes and egress. Ordinary reads are often absent; target sensitive-path audit and validate benign collection.

### PROC-008 — File creation, upload, copy/move, directory creation, and removal

Upload writes bytes; copy/move/mkdir/remove mutate paths, with recursive/overwrite variants. Evidence: [filesystem mutation handlers](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers.go#L256-L612). ATT&CK: T1105, T1074, T1070.004. **Telemetry:** Sysmon 11/23/26, EDR create/delete/rename, 4663/auditd; process/path/hash/size/user. Same-volume moves/overwrites may be incomplete; validate benign fixtures.

### PROC-009 — Mode, ownership, timestamps, and memory-backed files

Linux changes mode/owner, all supported platforms alter timestamps, and Linux adds/lists/removes memfd content. Evidence: [Linux registry](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_linux.go#L93-L102), [chtimes](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers.go#L1210-L1248). ATT&CK: T1222, T1070.006, T1027.011. **Telemetry:** auditd/eBPF chmod/chown/utimensat/memfd_create or EDR metadata/executable-memory events. Windows timestamp and memory-only behavior are weak; compensate with execution from anonymous memory.

### PROC-010 — Child process and interactive shell execution

Execute creates a requested child with args/environment and optional captured output; shell starts an interpreter with pipes/PTY and tunnels I/O. Evidence: [execute](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers.go#L1138-L1207), [shell](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tunnel_handlers/shell_handler.go#L37-L118). ATT&CK: T1059.003, T1059.004. **Telemetry:** 4688/Sysmon 1/EDR/auditd exec with parent, command, user, hash/signer, correlated egress. Enable command line; validate benign trees.

### PROC-011 — Task/shellcode execution and migration

Windows/Linux task handlers execute supplied code in-process or in another process; migration injects generated implant code into a selected target. Evidence: [Windows registry](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L58-L67), [taskrunner](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/taskrunner), [runner](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/runner). ATT&CK: T1055, T1106. **Telemetry:** EDR injection/process access, Sysmon 8/10; source/target GUID, access, start address/module/call stack. In-process paths may lack events; validate vendor benign injection fixtures.

### PROC-012 — Assembly, shared-library/DLL, and native extension execution

Windows assembly has sacrificial/in-process paths; sideload/spawndll loads libraries; Windows/Darwin extensions register bytes and invoke exports. Evidence: [handler set](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L64-L68), [extensions](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/extension/extension.go#L28-L69). ATT&CK: T1620, T1055, T1129. **Telemetry:** EDR module/.NET/private-executable-memory/process-access events, Sysmon 7/8/10; module hash/signer/target/call stack. Manual memory loads are a gap; compensate with memory and egress.

### PROC-013 — WASM execution

WASM modules register in memory, list/remove, and run interactively or otherwise through tunnel I/O. Evidence: [registration](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_generic.go#L55-L60), [execution](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tunnel_handlers/wasm_handler.go#L42-L147). ATT&CK: T1059, T1027.009. **Telemetry:** distinct invocation is `not_observable` in standard logs; use runtime memory/syscall and resulting child/file/network behavior. Validate benign WASM-host telemetry.

### PROC-014 — Screen capture

Captures active displays and returns encoded bytes; Windows unions monitor bounds and PNG-encodes in memory. Evidence: [handler](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/rpc-handlers-cgo.go#L31-L51), [Windows](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/screen/screenshot_windows.go#L30-L66). ATT&CK: T1113. **Telemetry:** vendor screen-capture/API event plus process and immediate egress; standard audit is `not_observable`. Validate approved screenshot telemetry.

### PROC-015 — Process memory dump

Windows/Linux dump a selected process and return bytes. Evidence: [registration](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L58-L60), [implementation](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/procdump). ATT&CK: T1003.001, T1005. **Telemetry:** EDR/Sysmon 10 source/target/access and file create if materialized; Linux audit/eBPF ptrace/process reads. Memory-only transfer is a gap; validate sanctioned dump logs.

### PROC-016 — Privilege/token discovery, impersonation, alternate credentials, revert

Windows enumerates privileges/token owner, makes a logon token, impersonates a process, runs under credentials, and reverts. Evidence: [registrations](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L60-L76), [priv code](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/priv). ATT&CK: T1134.001, T1134.002, T1078. **Telemetry:** 4624/4648/4672/4688 and EDR token/process access; account, logon type, source process, target, token level. Revert/token changes may be absent; validate authorized fixtures.

### PROC-017 — SYSTEM acquisition

GetSystem invokes a privileged execution path and returns SYSTEM-context results. Evidence: [registration](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L63-L64), [handler](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/rpc-handlers_windows.go#L138-L181). ATT&CK: T1134, T1543.003. **Telemetry:** 7045/4697/4672/process, pipe and process-access events depending variant. No universal sequence; correlate privilege transition and validate only historical emulation logs.

### PROC-018 — Windows registry read/list/hive and create/write/delete

Evidence: [registrations](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_windows.go#L77-L92), [code](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/registry). ATT&CK: T1012, T1112. **Telemetry:** Sysmon 12–14, 4656/4663 with SACL, EDR registry; process/key/value/data/user. Reads/listing often `not_observable`; validate targeted benign registry audit.

### PROC-019 — Service discovery, control, creation, and removal

Lists/details services, starts existing services, or remotely creates/starts/stops/deletes them through SCM. Evidence: [implementation](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/service/service_windows.go#L37-L219). ATT&CK: T1007, T1543.003, T1569.002. **Telemetry:** System 7035/7036/7045, Security 4697, SCM RPC, registry/process; service/path/account/source. Enumeration is usually unlogged; validate legitimate admin datasets.

### PROC-020 — Remote service and SSH execution

Psexec coordinates transfer then remote SCM execution; SSH opens an authenticated connection and runs a command. Evidence: [psexec](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/client/command/exec/psexec.go#L45-L173), [SSH registration](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers_linux.go#L73-L76). ATT&CK: T1021.002, T1021.004, T1569.002. **Telemetry:** 4624/5140/5145/4697/7045 and SSH auth/process/network logs; source/account/share/service/command. Cross-host correlation and encrypted SSH content are gaps.

### PROC-021 — Shell tunnels, forwards/reverse forwards, SOCKS, WireGuard relays

Handlers proxy interactive and arbitrary TCP/SOCKS streams; reverse listeners accept implant-side; stop closes listeners and tracking maps. Evidence: [tunnels](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tun.go#L33-L48), [reverse](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tun-rportfwd.go#L37-L42), [forwarders](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/forwarder). ATT&CK: T1090.001, T1090.002, T1572. **Telemetry:** EDR listen/connect and firewall/netflow with process/endpoints/bytes/duration. Tunneled content is opaque; validate benign proxy/VPN logs.

### PROC-022 — Browser/Electron instrumentation and external modules

`cursed` launches/attaches instrumented Chrome/Edge/Electron for console, cookies and screenshots. Alias/extensions/armory dispatch third-party modules through PROC-011–013. Evidence: [cursed](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/cursed), [aliases](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/alias), [extensions](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/extensions). ATT&CK: T1539, T1185. **Telemetry:** browser command line/parent, debugging sockets, profile/cookie reads, children and egress. External module semantics require separate pinned analysis; validate benign automation.

### PROC-023 — Listener, staging, website, profile, encoder, and build control plane

Server commands manage implant profiles/builds/canaries/encoders, external builders, C2/stage listeners and hosted website content. Evidence: [generate](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/client/command/generate/commands.go#L38-L257), [listeners](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/jobs), [sites](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/websites). ATT&CK: T1587.001, T1584.004, T1608.001. **Telemetry:** server process/file audit, sockets, firewall/cloud flow, DNS/cert/HTTP access, operator RPC and artifact hashes. Victim side is `not_observable` before deployment; validate synthetic server audit without building.

### PROC-024 — Loot, credential, cracking, host/IOC, and task administration

Server stores/fetches/renames/removes loot, credentials, hosts/IOCs and queued tasks and coordinates cracking workers. Evidence: [loot](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/loot), [creds](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/creds), [tasks](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/tasks), [crack](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/crack). ATT&CK: T1005, T1555, T1110 when used. **Telemetry:** server app/database/file/operator audit and worker process/network/GPU logs. Victim-side administration is `not_observable`; underlying collection inherits its procedure.

### PROC-025 — Operators, certificates, objects, automation, monitoring, and UI administration

Operator/certificate identity, sessions/beacons/jobs/builders, reactions/taskmany/monitor/watch and settings/AKA/AI/MCP/docs/update affect server/client workflow; dispatched host actions inherit their own procedures. Evidence: [operators](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/operators), [reactions](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/reaction), [taskmany](https://github.com/BishopFox/sliver/tree/13c2d3344927429cf55f6f7212499087e804bf47/client/command/taskmany). ATT&CK: no independent victim technique. **Telemetry:** server auth/certificate/RPC/config audit; distinct orchestration is victim-side `not_observable`; compensate with cross-host fan-out.

### PROC-026 — Cleanup and teardown

Cleanup removes files/memfiles/services, sessions/beacons/tasks, pivots/listeners/forwarders/tunnels, hosted content, loot/credentials/builds/profiles and optionally the implant; stop closes sockets/maps and failures may leave artifacts. Evidence: [file delete](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/handlers.go#L405-L453), [service teardown](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/service/service_windows.go#L64-L116), [tunnel close](https://github.com/BishopFox/sliver/blob/13c2d3344927429cf55f6f7212499087e804bf47/implant/sliver/handlers/tunnel_handlers/close_handler.go#L31-L54). ATT&CK: T1070.004, T1070.009. **Telemetry:** EDR/Sysmon deletion, SCM 7035/7036, process termination, flow end and server audit. In-memory cleanup is `not_observable`; validate benign teardown and before/after state.

## Explicit exclusions and limitations

- `vendor/` is dependency code; invoked effects are accounted by callers. `protobuf/` bindings add schema, not behavior. Tests, CI, docs, assets and packaging never run in deployed paths.
- External aliases, armory packages, extensions, encoders, staged content and operator-supplied commands are unbounded third-party inputs. Core loading/dispatch is covered; each external artifact needs its own pinned analysis.
- Server-only actions cannot appear in victim telemetry. Every such case names server audit as primary telemetry and host behavior as compensation.
- This is comprehensive for the pinned core revision, not a claim of universal detectability. All telemetry mappings are `needs_validation`; none is production-ready.
