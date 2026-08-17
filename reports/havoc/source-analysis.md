# Havoc procedure analysis

> Scope correction (2026-08-15): active completeness and detections cover only the victim-side Demon/agent. Teamserver, listener/build, operator-client, and external-service control-plane discussion below is retained as protocol context and historical evidence, but is excluded from procedure counts and detection scope under the victim-host eligibility policy.

## Scope and provenance

- Tool revision: `c84f7755a8b1c0f737576bdd3a0e982a296012f1`
- Analysis input: official public source code, cloned through WSL and read statically
- Repository: https://github.com/HavocFramework/Havoc
- Analysis date: 2026-08-15
- Status: comprehensive static inventory for the pinned revision; detections remain experimental
- Safety: nothing was built or executed. Prebuilt files present in the upstream repository were not opened or inspected and remain in an ignored source checkout.

## Evidence

| ID | Immutable source | Supports |
| --- | --- | --- |
| H-E01 | [Demon command identifiers](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/payloads/Demon/include/core/Command.h#L7-L29) | Core command inventory |
| H-E02 | [Demon command dispatch declarations](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/payloads/Demon/include/core/Command.h#L137-L220) | Handler coverage |
| H-E03 | [Teamserver task preparation](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/teamserver/pkg/agent/demons.go#L60-L320) | Operator-to-agent task mapping |
| H-E04 | [Socket and forwarding command identifiers](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/payloads/Demon/include/core/Socket.h#L8-L23) | SOCKS and port-forward branches |
| H-E05 | [HTTP transport implementation](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/payloads/Demon/src/core/TransportHttp.c) | HTTP check-in and task transport |
| H-E06 | [SMB transport implementation](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/payloads/Demon/src/core/TransportSmb.c) | Named-pipe transport and pivoting |
| H-E07 | [Client command catalogue](https://github.com/HavocFramework/Havoc/blob/c84f7755a8b1c0f737576bdd3a0e982a296012f1/client/src/Havoc/Demon/Commands.cc) | Operator-visible command surface |
| H-E08 | [Teamserver listener and service packages](https://github.com/HavocFramework/Havoc/tree/c84f7755a8b1c0f737576bdd3a0e982a296012f1/teamserver/pkg) | Remaining server-side inventory scope |

## Current procedure inventory

Every row is telemetry-assessed. Detection design is deliberately deferred until the remaining source branches are reconciled.

| ID | Procedure family | Ordered behavior and security effect | Telemetry requirement and gaps | ATT&CK |
| --- | --- | --- | --- | --- |
| HV-P01 | Lifecycle and HTTP check-in | Initialize process state, gather host/process identity, contact the configured HTTP endpoint, exchange encrypted task packages, and repeat after a delay. | Process start/identity plus process-attributed HTTP/TLS/network flow, DNS, proxy fields, timing and collection health. Encryption and configurable endpoints prevent content attribution. | T1071.001, T1105 |
| HV-P02 | SMB named-pipe transport | Create or open a named-pipe channel, exchange task packages through a parent/pivot, and maintain linked agent state. | Sysmon 17/18 or EDR pipe create/connect, process entity, pipe endpoint, remote host/session, SMB network telemetry. Pipe naming is configurable. | T1090, T1021.002 |
| HV-P03 | Sleep, kill date, working hours and runtime configuration | Change delay/jitter and runtime memory/injection settings; suppress tasking outside configured periods; terminate at the kill date. | Recurrent process-attributed flows, process memory/protection telemetry, and process termination. Configuration-only changes may have no direct victim event. | T1029, T1070 |
| HV-P04 | Process discovery and module inspection | Enumerate processes, filter results, enumerate loaded modules, or query process memory state. | EDR process-discovery/API telemetry where available; process access events and Sysmon 10 for remote targets. Native local enumeration is often not directly logged. | T1057, T1518.001 |
| HV-P05 | Process creation and command execution | Create a child process for shell/PowerShell or configured spawn targets, optionally altering parent context, then capture output. | Security 4688/Sysmon 1/EDR process create with process GUID, parent, command line, token, integrity, signer and network lineage. Parent spoofing weakens literal lineage. | T1059.003, T1059.001, T1134.004 |
| HV-P06 | Filesystem discovery and reads | List directories, resolve working directory and read file content. | EDR file-read/enumeration telemetry, object access where narrowly enabled, process/path/user. Standard Windows logs often omit reads and directory listing. | T1083, T1005 |
| HV-P07 | File transfer and staging | Download a remote file to the teamserver or upload/write operator content to the endpoint; maintain transfer state. | EDR file create/write/read plus process-attributed network bytes, file path/hash and stable process entity. Memory-only staging is not covered. | T1105, T1005 |
| HV-P08 | File mutation and cleanup | Create directories, copy, move, remove files, and clean up agent artifacts during exit. | Sysmon 2/23/26 and EDR create/rename/delete with initiating process; process termination and service cleanup compensate for missing initiator fields. | T1107, T1070.004 |
| HV-P09 | COFF/BOF inline execution | Load an object in memory, resolve symbols, apply relocations, invoke it in the agent, and return output/errors. | EDR memory allocation/protection, unsigned or memory-backed module/thread telemetry and resulting effects. Portable OS logs may expose no direct event. | T1106, T1055 |
| HV-P10 | CLR/.NET assembly execution | Initialize or select a CLR runtime, load an assembly in memory, execute its entry point, and collect output. | CLR Runtime/Loader events, EDR managed-runtime/module-load telemetry, process network context and resulting child/file behavior. In-memory loads may be vendor-dependent. | T1620, T1055 |
| HV-P11 | DLL and shellcode execution/injection | Execute content in the current process, access a remote process, allocate/write/protect memory, create execution, or spawn a temporary target and inject it. | Sysmon 10, EDR process access/injection/cross-process memory/thread events, process creation and module telemetry with source/target GUIDs. Sensor semantics require tenant validation. | T1055, T1055.002, T1055.012 |
| HV-P12 | Token discovery and manipulation | Enumerate tokens/privileges, duplicate or steal a token, create a token from credentials, impersonate it, revert, or maintain an in-memory vault. | Security 4624/4648/4672, EDR token manipulation, process access and account/logon ID correlation. Vault-only list/remove actions have no direct event. | T1134, T1134.001, T1134.002 |
| HV-P13 | Network and directory discovery | Query domain, DCs, computers, users, groups, shares, sessions and logons using Windows network/directory interfaces. | AD DS 1644 when enabled, LDAP/RPC/SMB network telemetry, share access 5140/5145 and EDR API telemetry. Local/native queries may be unlogged. | T1016, T1087.002, T1069.002, T1135, T1049 |
| HV-P14 | Screen capture | Capture the interactive desktop into memory and return image data. | Tenant-verified EDR screen-capture semantic event plus stable process/session and subsequent egress. Standard event logs generally lack a direct signal. | T1113 |
| HV-P15 | SMB pivot management | Connect/disconnect child agents over SMB pipes and relay their task packages through a parent. | Sysmon 17/18, SMB session/tree-connect telemetry, process network context and graph correlation across source/target hosts. Encrypted task content is opaque. | T1090.001, T1021.002 |
| HV-P16 | Port forwarding and SOCKS proxy | Open listeners, create outbound target connections, relay socket data, and close/list forwarding state. | EDR listen/connect telemetry, firewall/flow records, process entity, local/remote addresses, direction and byte counts. Generic proxy software is a major false-positive class. | T1090, T1572 |
| HV-P17 | Kerberos ticket operations | Enumerate logon sessions/tickets, purge cached tickets, or submit ticket material through LSA interfaces. | Security 4768/4769/4770 and resource authentication, EDR/ETW LSA call telemetry, account/LUID/process correlation. Cache query/purge can lack standard events. | T1550.003, T1558 |
| HV-P18 | Memory-file staging | Store, reference and remove operator-supplied content in agent memory for later execution. | EDR memory/fileless-content telemetry and downstream execution effects. Pure in-memory bookkeeping is not directly observable. | T1027, T1620 |
| HV-P19 | Job and transfer control | List, suspend, resume or remove agent jobs and transfer state. | Resulting thread/process/network state transitions where exposed; in-memory control operations are generally not observable. | T1106 |
| HV-P20 | Exit and teardown | Clean agent state and terminate the current thread or process; server state is updated. | Process/thread termination, self-delete/file deletion, service stop/delete, loss of recurrent egress and authorized teamserver audit. Absence alone needs collection-health gating. | T1070, T1070.004 |
| HV-P21 | Teamserver listeners, build and operator control | Configure HTTP/SMB/external listeners, build payload formats, accept authenticated clients and dispatch tasks. | Authorized Havoc application audit, process execution on the server, listener/socket telemetry, file creation and operator identity. Adversary-controlled servers are outside defender visibility. | T1587.001, T1102 |
| HV-P22 | Extensible service and client API | Register external agents/listeners and invoke client Python/API command paths that can introduce behavior beyond core Demon. | Authorized server/client application audit and resulting endpoint behavior. Extension behavior is unbounded and must be inventoried at deployment time. | T1059.006, T1106 |

## Completeness accounting

- Completed: core command identifiers and handlers; client catalogue and Python method surface; HTTP/SMB transports; socket, Kerberos, token, process, filesystem, transfer, memory-file, job and exit families; teamserver listeners, profiles, builders, operator dispatch, service/plugin registration and external-agent contracts. The latter branches resolve to HV-P21 or the explicitly unbounded HV-P22 extension boundary.
- Excluded from procedure inventory: vendored YAOTL/parser code, tests, documentation, screenshots, icons and packaging scaffolding because they do not independently add deployed attacker behavior.
- Upstream prebuilt payload files were not opened or analyzed. Their source implementations are the analysis basis.
- Inventory result: 22 procedure families. Nineteen have behavioral/effect detections; HV-P18, HV-P19 and HV-P22 are directly `not_observable` because their core operation is in-memory bookkeeping or unbounded externally supplied behavior. Their closest compensating telemetry is downstream execution/file/network behavior or authorized server audit.

## Safe validation approach

Use synthetic normalized event fixtures and benign administrative analogues only. Validate parser mappings for process creation/access, named pipes, network listeners/connections, file lifecycle, authentication, Kerberos, CLR, screen capture and server audit. Do not build or run Havoc or its payloads.
