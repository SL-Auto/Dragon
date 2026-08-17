# Cobalt Strike Beacon comprehensive procedure analysis

## Scope, provenance, and confidence

- **Analyzed revision:** Cobalt Strike **4.13**, documentation build `202606220941`, June 2026; accessed 2026-08-15. The official release notes identify the 4.13 additions, including Beacon Interpreter, BOF-PE support, Payload Store references, and IPv6 SSH support. Sources: [Fortra current user guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [Fortra release notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm).
- **Input type:** public documentation and intelligence only. Beacon is proprietary; source code was unavailable. No payload, binary, malware sample, or executable content was downloaded, built, opened, or run.
- **Method:** the entire official Beacon command table, command-behavior appendix, current post-exploitation chapters, listener documentation, current REST API surface, and 4.13 release notes were reconciled. MITRE ATT&CK S0154 was used as an independent capability/technique cross-check, not as implementation proof: [MITRE ATT&CK S0154](https://attack.mitre.org/software/S0154/).
- **Evidence labels:** **Documented fact** means Fortra explicitly describes the behavior. **Inference** means likely operating-system behavior or telemetry derived from that description; it is not a source-code finding. Confidence is high for the existence and user-visible purpose of documented commands, medium for internal sequence, and low-to-medium for product-specific field mappings until validated in authorized telemetry.

## Completeness inventory

The following inventory accounts for every built-in command named by Fortra's [Beacon command-behavior appendix](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm) and the current [Beacon console command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm). Commands are grouped only where their documented observable procedure is equivalent.

| Surface | Commands/capabilities accounted for | Procedures |
|---|---|---|
| lifecycle and task control | `checkin`, `sleep`, `mode dns`, `mode dns-txt`, `mode dns6`, `cancel`, `clear`, `jobs`, `jobkill`, `exit`, `history`, `help`, `note`, `downloads`, `file_browser`, `process_browser`, `windows_error_code`, `!` | CSB-001, 002, 029 |
| runtime configuration | `argue`, `beacon_config`, `beacon_gate`, `blockdlls`, `data-store`, `ppid`, `spawnto`, `sycall-method`, `variables`, `setenv`, `powershell-import`, Beacon guardrails/sleep mask | CSB-003, 004, 010, 029 |
| C2 and peer transport | HTTP, HTTPS, DNS/DNS-TXT/DNS6/DoH, SMB named pipe, TCP bind, External C2 and user-defined C2; `connect`, `link`, `unlink` | CSB-002, 005-008 |
| proxying and tunnels | `socks`, `rportfwd`, `rportfwd_local`, `spunnel`, `spunnel_local`, `covertvpn` | CSB-009 |
| identity/token/Kerberos | `getuid`, `getprivs`, `make_token`, `steal_token`, `rev2self`, `token-store`, `kerberos_ccache_use`, `kerberos_ticket_use`, `kerberos_ticket_purge`, `pth` | CSB-011-013 |
| execution | `execute`, `run`, `shell`, `powershell`, `powerpick`, `psinject`, `execute-assembly`, `inline-execute`, `beacon-interpreter`, `beacon-interpreter-lint`, `execute-dll`, `dllload` | CSB-014-018 |
| injection/session creation | `inject`, `shinject`, `shspawn`, `spawn`, `spawnas`, `spawnu`, `runas`, `runu`, `dllinject` | CSB-016-019 |
| privilege elevation | `getsystem`, `elevate svc-exe`, `elevate uac-token-duplication`, `runasadmin uac-cmstplua`, `runasadmin uac-token-duplication` | CSB-020 |
| discovery | `ps`, `drives`, `net computers`, `dclist`, `domain`, `domain_controllers`, `domain_trusts`, `group`, `localgroup`, `logons`, `sessions`, `share`, `user`, `time`, `view`, `portscan`, `reg query`, `reg queryv` | CSB-021-023 |
| filesystem and transfer | `pwd`, `cd`, `ls`, `drives`, `cp`, `mv`, `mkdir`, `download`, `upload`, `rm`, `timestomp` | CSB-024-026 |
| collection and credentials | `clipboard`, `screenshot`, `printscreen`, `screenwatch`, `desktop`, `keylogger`, `chromedump`, `browserpivot`, `hashdump`, `logonpasswords`, `mimikatz`, `dcsync` | CSB-027, 028 |
| lateral movement | `jump psexec`, `psexec64`, `psexec_psh`, `winrm`, `winrm64`; `remote-exec psexec`, `winrm`, `wmi`; `ssh`, `ssh-key` | CSB-030-033 |
| cleanup/destruction | `rm`, `timestomp`, `kill`, `jobkill`, `unlink`, stop variants for SOCKS/forwarding, `exit`, Kerberos purge, service cleanup | CSB-034 |

Fortra permits user-defined Aggressor commands, BOFs, BOF-PE, Beacon Interpreter scripts, reflective DLLs, assemblies, shellcode, commands, and user-defined C2 channels. Their **dispatch mechanisms** are inventoried here, but arbitrary third-party payload semantics cannot be exhaustively enumerated without the specific pinned artifact. The official documentation explicitly exposes extensibility through the console and REST API: [REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html), [Beacon Interpreter](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_beacon-interpreter.htm).

## Procedures

### CSB-001 — Initialization, host identity, and guardrails

**Documented fact:** Beacon sessions report host name, user, PID and check-in state; listener guardrails can constrain where a payload runs. **Inference:** initialization must collect host/user/process/network context and may exit when constraints fail. ATT&CK: T1082, T1033, T1057, T1480.001. Evidence: [Post Exploitation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_main.htm), [listener options](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm).

**Telemetry:** EDR process start/metadata (image, hash, signer, parent, user, integrity, PID), process-attributed network initiation, and unusual short-lived process exits. Most in-process environment reads are `not_observable` in standard logs. Enable process and network telemetry; retain at least one check-in interval plus hunt window. **Safe validation:** replay sanitized process/network records or use a benign inventory program; do not deploy Beacon.

### CSB-002 — Asynchronous tasking, sleep, jitter, interactive mode, retries, and exit

**Documented fact:** Beacon queues tasks, checks in asynchronously, sleeps with configurable jitter, can enter interactive mode, rotates/holds callback hosts, applies retry/exit strategy, and returns results. ATT&CK: T1071, T1029. Evidence: [Asynchronous and Interactive Operations](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_asynch-interactive.htm), [HTTP/S Beacon host strategy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructure_beacon-http-https.htm).

**Telemetry:** process-linked DNS/HTTP/TLS/network flows with timestamps, destination, bytes, duration and process identity; process exit. Jitter, host rotation and profiles defeat simple periodicity or fixed-destination assumptions. Correlate repeated low-volume egress, process rarity and endpoint changes; do not require exact cadence. **Safe validation:** test timing logic on synthetic jittered flow data.

### CSB-003 — Runtime C2, BeaconGate, system-call, and mutable-host configuration

**Documented fact:** `beacon_config`, `beacon_gate`, `sycall-method`, and related settings change callback hosts, notification behavior, BeaconGate use and runtime execution behavior. **Inference:** some changes remain entirely in memory and may alter which telemetry a sensor sees. ATT&CK: T1027, T1106. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [4.13 notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm).

**Telemetry:** usually `not_observable` directly; compensate with before/after changes in network destination, process-access method, call-stack/API telemetry and Team Server audit if available. **Safe validation:** schema/unit tests using fabricated configuration-change and endpoint events.

### CSB-004 — Sleep masking, process-argument/parent shaping, spawn target, and child DLL policy

**Documented fact:** `argue` spoofs child arguments, `ppid` changes selected child parentage, `spawnto` changes sacrificial processes, `blockdlls` applies a Microsoft-binary policy, and malleable settings control sleep masking and post-execution behavior. ATT&CK: T1564.010, T1134.004, T1027. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** EDR process creation with both reported and effective parent, creator process, token, image, command line and signature-policy attributes; memory-region/protection/thread/call-stack telemetry. Direct observation of sleep masking is vendor-dependent. Avoid rules tied to default `rundll32.exe`, default parents, or visible command text. **Safe validation:** synthetic process graphs containing parent discrepancies and benign policy-enabled children.

### CSB-005 — HTTP and HTTPS C2

**Documented fact:** Beacon supports HTTP/S, multiple callback hosts, proxy configuration, host rotation, mutable request/response structure and host-profile changes. ATT&CK: T1071.001, T1573, T1001.003, T1090.004. Evidence: [HTTP/S Beacon](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructure_beacon-http-https.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** process-attributed network, proxy, HTTP and TLS events: destination/IP/port, SNI, certificate, JA4/implementation fingerprint where lawful, method, URI, headers, status, bytes and timing. Content and indicators are profile-mutable and encryption may hide tasks; use behavioral correlation, not static URIs. **Safe validation:** benign synthetic HTTP/TLS sessions matching the expected schema.

### CSB-006 — DNS-family C2

**Documented fact:** Beacon supports DNS modes including DNS, DNS-TXT and DNS6; current listener APIs also expose DNS-over-HTTPS mode. ATT&CK: T1071.004, T1573. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [Aggressor listener types](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm).

**Telemetry:** DNS client/resolver logs with process, qname, qtype, answer, response code, length, entropy and timing; DoH requires endpoint/browser/network flow attribution because resolvers may hide names. Profiles and resolver caching are gaps. **Safe validation:** generated benign DNS records, never live Beacon traffic.

### CSB-007 — SMB named-pipe peer C2

**Documented fact:** SMB Beacon communicates through a parent over Windows named pipes; `link` connects and `unlink` tears down the relationship. ATT&CK: T1071.002, T1090.001. Evidence: [Post Exploitation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_main.htm), [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** Sysmon 17/18 or EDR pipe create/connect, SMB 5140/5145 where networked, network flows and process identity; fields include pipe, source/target host, PID, user/share and timestamps. Pipe names are mutable, and local pipes may never create SMB audit. **Safe validation:** authorized benign named-pipe fixtures and synthetic cross-host joins.

### CSB-008 — TCP bind, External C2, and user-defined C2

**Documented fact:** TCP Beacon listens for a parent connection; External C2 and user-defined channels allow alternate transport implementations. ATT&CK: T1095, T1572, T1090. Evidence: [TCP Beacon](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-tcp.htm), [listener types](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm), [4.13 UDC2 notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm).

**Telemetry:** EDR socket listen/accept/connect, host firewall and east-west flow with process, local/remote endpoints, direction, bytes and duration. User-defined transports have no universal wire signature; compensate with process-network rarity and linked downstream behavior. **Safe validation:** benign listener/client telemetry or synthetic flows.

### CSB-009 — SOCKS, reverse forwarding, spunnel, and VPN-style pivoting

**Documented fact:** Beacon supports SOCKS4a/5 relays, reverse port forwards via Team Server or client, spawn-and-tunnel variants, and Covert VPN. ATT&CK: T1090.001, T1090.002, T1572. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** process-attributed listen/connect events, firewall/netflow, loopback connections and many-destination fan-out; record endpoints, direction, bytes, duration and process lineage. Tunnel content may be opaque and client-side relay may move the visible endpoint. **Safe validation:** synthetic proxy/forwarding flow sets with legitimate-admin negatives.

### CSB-010 — In-memory data, imported PowerShell, and mutable variables

**Documented fact:** `data-store`, `powershell-import`, `variables`, and Payload Store references retain operator-supplied content or settings for later tasks. ATT&CK: T1027, T1105 where content is transferred. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [4.13 notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm).

**Telemetry:** storage inside Beacon is `not_observable`; use Team Server task/audit records if retained, endpoint memory telemetry, and the eventual execution/file/network effects. **Safe validation:** metadata-only task records and synthetic subsequent effects.

### CSB-011 — Identity/privilege discovery and token enablement

**Documented fact:** `getuid` returns the current identity and `getprivs` enables available privileges. ATT&CK: T1033, T1069, T1134. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** identity reads and token privilege adjustment are commonly `not_observable`; EDR token-change telemetry or Security 4672 may provide partial context. Compensate with subsequent privileged child/process-access operations. **Safe validation:** benign token-inspection telemetry if the endpoint product supplies it.

### CSB-012 — Token creation, theft, storage, impersonation, revert, and credentialed execution

**Documented fact:** Beacon can create a network token from credentials, steal a process token, store/use tokens, revert, and run/spawn as another user or under another PID. ATT&CK: T1134.001, T1134.003, T1134.004, T1078. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** Windows Security 4624/4648/4672/4688, EDR process/token access and effective-user fields; correlate source process, target PID, account, logon ID, child and network authentication. Token-only changes can be invisible. **Safe validation:** sanitized administrative `runas`/service-account events and synthetic token joins.

### CSB-013 — Kerberos ticket application, cache use, purge, and pass-the-hash

**Documented fact:** Beacon can apply Kerberos tickets or caches, purge tickets, and use a hash-derived token through its `pth` workflow. ATT&CK: T1550.002, T1550.003. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** DC 4768/4769/4770/4771/4776, endpoint 4624/4648, logon session/account/encryption/service/client fields, plus named-pipe and child-process telemetry for documented `pth` behavior. Ticket injection/purge itself may be absent. **Safe validation:** historical authorized authentication logs or synthetic Kerberos sequences.

### CSB-014 — Native child execution and command shell

**Documented fact:** `execute` starts a program without output, `run` captures output without `cmd.exe`, and `shell` invokes `cmd.exe`; `runas` and `runu` alter identity or parent context. ATT&CK: T1106, T1059.003. Evidence: [Running Commands](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** Security 4688, Sysmon 1 or EDR process events with creator/effective parent, user, integrity, command, hash and signer. `run` means cmd.exe is not required; argument spoofing means command text is not authoritative. **Safe validation:** benign process-tree fixtures.

### CSB-015 — PowerShell host and unmanaged PowerShell

**Documented fact:** `powershell` launches PowerShell, while `powerpick` and `psinject` run unmanaged PowerShell through a sacrificial or specified process; imported scripts can extend commands. ATT&CK: T1059.001, T1055. Evidence: [Running Commands](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** 4688/Sysmon 1, PowerShell 4103/4104/400/403 where a normal host is used, AMSI if available, EDR CLR/PowerShell/injection/memory events. Unmanaged hosting may produce no `powershell.exe` or script-block record. **Safe validation:** sanitized legitimate PowerShell and synthetic unmanaged-host events.

### CSB-016 — BOF, BOF-PE, Beacon Interpreter, and arbitrary in-session execution

**Documented fact:** `inline-execute` runs BOFs inside Beacon; 4.13 adds BOF-PE support and compiles Beacon Interpreter scripts to bytecode executed by a Beacon VM without executable bytecode pages. ATT&CK: T1106, T1620, T1027. Evidence: [Beacon Interpreter](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_beacon-interpreter.htm), [4.13 notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm), [REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html).

**Telemetry:** dispatch is usually `not_observable` in standard logs; interpreter bytecode may remain RW, so RW-to-RX assumptions are incomplete. Use EDR thread/memory/API behavior, Team Server task audit, and resulting file/process/network/registry effects. Each third-party module requires its own analysis. **Safe validation:** synthetic task metadata and benign VM/runtime events.

### CSB-017 — .NET assembly execution

**Documented fact:** `execute-assembly` runs a .NET executable as a fork-and-run post-exploitation job and inherits the current token. ATT&CK: T1055, T1620. Evidence: [Running Commands](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** sacrificial process creation, injection/process-access, CLR loading, module/memory/thread and child/file/network effects. CLR and payload may be memory-only; default spawn image is mutable. **Safe validation:** benign .NET host and synthetic injection telemetry.

### CSB-018 — DLL load, reflective DLL, shellcode injection, and execute-DLL

**Documented fact:** `dllload` uses LoadLibrary in a selected process; `dllinject`, `execute-dll`, `shinject`, and `inject` load DLL, shellcode, payload, or Beacon into a process; remote and self-injection paths differ. ATT&CK: T1055, T1055.001, T1620. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** Sysmon 7/8/10 and EDR process access, remote thread, module, executable-memory, start address and call stack; include source/target process GUIDs and access rights. Self-injection/manual mapping may evade module/remote-thread telemetry. **Safe validation:** vendor-provided benign injection datasets only.

### CSB-019 — Spawn-and-inject session creation and process termination

**Documented fact:** `spawn`, `spawnas`, `spawnu`, `shspawn`, `spunnel` and local variants create sacrificial processes and inject sessions/code; `kill` terminates a selected process. ATT&CK: T1055, T1106, T1489 where destructive. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** process start/termination, injection/process access, named pipes and ensuing network; creator, effective parent, token/user, target, image, hash, signer and lifetime. Spawn targets are configurable, so no fixed-image prerequisite is valid. **Safe validation:** synthetic spawn/inject graphs.

### CSB-020 — Privilege elevation and SYSTEM acquisition

**Documented fact:** built-ins include service-based elevation, UAC token duplication, CMSTPLUA-based `runasadmin`, and `getsystem`; Fortra describes some as BOFs and some as spawn/session paths. ATT&CK: T1548.002, T1134, T1543.003. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** Security 4672/4688/4697, System 7045/7035/7036, UAC/COM and EDR token/integrity/process-access telemetry; correlate a medium-integrity source to elevated/SYSTEM child or session. Variant-dependent paths mean there is no universal sequence. **Safe validation:** approved historical emulation logs or synthetic privilege transitions.

### CSB-021 — Process, identity, drive, time, network and port discovery

**Documented fact:** `ps`, `getuid`, `drives`, `net time`, `portscan`, process browser and host/network enumeration expose processes, identity, storage, time and reachable services. ATT&CK: T1057, T1033, T1083, T1124, T1046. Evidence: [Network and Host Enumeration](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_network-host-enumeration.htm), [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** most local Win32 enumeration is `not_observable`; port scanning produces many destination/port attempts in EDR/firewall/netflow. Compensate with C2 correlation and follow-on activity. **Safe validation:** benign inventory/scan datasets within an isolated authorized test set.

### CSB-022 — Active Directory, account, group, trust, session, share and host discovery

**Documented fact:** the `net` module uses Windows Network Enumeration APIs for computers, DCs, domains/trusts, groups, local groups, users, logons, sessions, shares and browser-service host view. ATT&CK: T1018, T1087.002, T1069.001, T1069.002, T1482, T1033, T1135. Evidence: [Network and Host Enumeration](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_network-host-enumeration.htm).

**Telemetry:** DC LDAP/RPC, directory-service diagnostic events where enabled, Security 4662 with carefully scoped SACLs, SMB/session RPC and EDR network/API events; record client/process/account, server, operation, object class/filter and volume. Native enumeration often lacks endpoint events and encryption obscures LDAP content. **Safe validation:** benign domain-inventory logs and synthetic query bursts.

### CSB-023 — Registry discovery

**Documented fact:** `reg query` and `reg queryv` enumerate keys and values in selectable registry views. ATT&CK: T1012. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** registry reads are usually `not_observable`; targeted SACL/4656/4663 or EDR registry-read telemetry can expose process, hive, key and value. Compensate with subsequent execution/config changes. **Safe validation:** benign registry-query fixtures against non-sensitive test keys.

### CSB-024 — File/directory discovery and collection

**Documented fact:** `pwd`, `cd`, `ls`, `drives`, and `download` navigate, enumerate and collect local content. ATT&CK: T1083, T1005. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** EDR file-read/enumeration events or targeted Security 4663 with process, user, path, object, bytes and sensitivity classification; ordinary reads/enumeration are often absent. Correlate sensitive reads with outbound transfer. **Safe validation:** benign file-inventory/read fixtures.

### CSB-025 — File ingress, copy/move, and directory creation

**Documented fact:** `upload`, `cp`, `mv`, and `mkdir` create or mutate filesystem objects; post-exploitation and lateral-movement workflows may stage files. ATT&CK: T1105, T1074. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm).

**Telemetry:** Sysmon 11, EDR create/write/rename, 4663 and network transfer; record process, source/destination, hash, size, signer, zone/origin and user. Same-volume rename and overwrite visibility varies. **Safe validation:** benign filesystem mutations and synthetic transfer correlation.

### CSB-026 — File deletion and timestamp replacement

**Documented fact:** `rm` deletes files/folders and `timestomp` copies created/accessed/modified timestamps from another file. ATT&CK: T1070.004, T1070.006. Evidence: [command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** Sysmon 2/23/26 where configured, EDR delete/metadata-change and Security 4663; record process, path, prior/new times, hash and user. Filesystem journaling may provide compensation. **Safe validation:** benign temporary-file deletion/timestamp fixtures.

### CSB-027 — Screen, desktop, clipboard, browser and input collection

**Documented fact:** Beacon can capture screenshots/printscreen/screenwatch, expose a remote desktop, read clipboard text, log keys, dump Chromium-derived data, and browser-pivot through a selected browser process. ATT&CK: T1113, T1115, T1056.001, T1539, T1185. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** vendor-specific screen/input/clipboard/browser-access events, browser process access, cookie/profile file reads, injection, unusual desktop/viewer traffic and immediate egress. Many capture APIs are `not_observable` in standard logs. **Safe validation:** EDR-provided benign screen/clipboard/browser test telemetry; never collect real user secrets.

### CSB-028 — Credential dumping and directory replication

**Documented fact:** `hashdump`, `logonpasswords`, `mimikatz`, `dcsync`, `pth`, and `chromedump` provide credential-access workflows; Fortra classifies several as fork-and-run or explicit-process post-ex jobs. ATT&CK: T1003.001, T1003.002, T1003.006, T1555.003, T1550.002. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [MITRE S0154](https://attack.mitre.org/software/S0154/).

**Telemetry:** EDR/Sysmon 10 process access to LSASS, LSA/SAM/SECURITY hive access, registry/file events, DC Security 4662 replication-control access with subject/object/access mask, authentication events, browser profile reads and correlated egress. Injection into a chosen process and memory-only return weaken fixed-image/file assumptions. **Safe validation:** sanitized vendor test events or historical authorized emulation records; never run credential-dumping tooling.

### CSB-029 — Operator housekeeping, queue/history, job control, and task cancellation

**Documented fact:** help/history/note/downloads/browser views may be client-side; queue clear/cancel and job kill affect pending/running tasks; variables and status commands affect operator state. ATT&CK: no independent victim technique unless a stop/kill reaches the endpoint. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html).

**Telemetry:** primarily Team Server/client task transcript and REST API audit. Victim telemetry is `not_observable` for client-only actions; job termination may show thread/process stop. **Safe validation:** fabricated audit/task-state records.

### CSB-030 — Service-based remote execution and SMB/admin-share staging

**Documented fact:** `jump psexec`, `psexec64`, `psexec_psh`, and `remote-exec psexec` use SCM; selected variants upload a service executable and service workflows clean it up. ATT&CK: T1021.002, T1569.002, T1543.003. Evidence: [Lateral Movement](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** source/target 4624, 5140/5145, 4697, System 7045/7035/7036, SCM RPC, file create and child process; fields include source host/IP, account/logon ID, share/path, service/name/image and process lineage. Service names and artifacts are mutable; deletion may fail. **Safe validation:** legitimate software-deployment/service-install records and synthetic cross-host sequences.

### CSB-031 — WinRM remote execution

**Documented fact:** `jump winrm/winrm64` runs a PowerShell payload remotely and `remote-exec winrm` executes commands through WinRM. ATT&CK: T1021.006, T1059.001. Evidence: [Lateral Movement](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm), [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm).

**Telemetry:** 4624/4648, WinRM Operational 6/91/142 where available, PowerShell 4103/4104, WSMAN/network and `wsmprovhost.exe` child telemetry; source, account, destination, operation/session and child command. Script hosting and unmanaged variants can reduce content visibility. **Safe validation:** sanitized approved remote-administration logs.

### CSB-032 — WMI remote execution

**Documented fact:** `remote-exec wmi` executes a command on a remote host and is implemented as a built-in BOF. ATT&CK: T1047. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [Lateral Movement](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm).

**Telemetry:** 4624, WMI-Activity Operational 5857-5861 where available, RPC/network, `WmiPrvSE.exe` children and EDR remote WMI events; source, user, namespace, operation, consumer/query and child. Event availability varies by Windows version and provider configuration. **Safe validation:** benign enterprise WMI administration records.

### CSB-033 — SSH remote execution

**Documented fact:** `ssh` and `ssh-key` authenticate with a password or key and execute through SSH as fork-and-run/target-process jobs; 4.13 adds IPv6 support. ATT&CK: T1021.004, T1078. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [4.13 notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm).

**Telemetry:** server sshd authentication/session/process logs, source network flows, account/key fingerprint where lawful and child command/process; client-side sacrificial process/injection. Encrypted content and log-policy differences are gaps. **Safe validation:** sanitized legitimate SSH administration data.

### CSB-034 — Teardown, artifact cleanup, process/job termination, and residual memory

**Documented fact:** stop/unlink/exit/jobkill/kill/rm/purge operations terminate relays, tasks, processes, sessions, files or tickets. Fortra notes that injection can leave memory artifacts and that service workflows attempt cleanup. ATT&CK: T1070.004, T1070.009, T1489 where processes are disrupted. Evidence: [command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), [TCP Beacon unlink](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-tcp.htm).

**Telemetry:** process/thread/job termination, Sysmon 23/26, service stop/delete, pipe/socket closure, Kerberos/session changes and Team Server task audit. In-memory cleanup and ticket purge may be `not_observable`; residual memory visibility is sensor-dependent. **Safe validation:** synthetic teardown and before/after state records.

## Procedure-to-telemetry summary

| Telemetry source | Principal procedures | Required atomic events/types |
|---|---|---|
| endpoint process/EDR | 001, 004, 011-020, 027-034 | process start/stop; effective and creator parent; process/token access; remote thread; executable/private memory; module/CLR load; screen/input/browser events |
| Windows Security | 012, 013, 020, 022, 024-026, 028, 030-032 | 4624, 4648, 4662, 4663, 4672, 4688, 4697, 4768, 4769, 4770, 4771, 4776, 5140, 5145 |
| Windows System and operational providers | 020, 030-032 | System 7035, 7036, 7045; Sysmon 1, 2, 3, 7, 8, 10, 11, 17, 18, 23, 26; PowerShell 400/403/4103/4104; WinRM and WMI-Activity operational events |
| DNS/HTTP/TLS/proxy/firewall/netflow | 002, 005-009, 021, 024, 027-033 | DNS request/response; HTTP transaction; TLS session/certificate; socket listen/connect/accept; flow start/end and bytes |
| directory and authentication | 013, 022, 028, 030-033 | LDAP/RPC operation, DC authentication/TGS/TGT, replication access, SSH authentication/session |
| Team Server/client audit | 003, 010, 016, 029 and compensation for all | operator identity, Beacon ID, task ID/type/state, timestamp, listener/profile/config change, REST endpoint/result |

## Explicit limitations and blocked source

- Beacon source is proprietary and unavailable; internal function call order, error handling, default implementation details, platform/version branches and cleanup guarantees are **blocked_source**. The procedure inventory is comprehensive for the behaviors documented in Fortra 4.13, not a claim of source-code completeness.
- Arbitrary operator-supplied commands, BOFs, BOF-PE modules, Interpreter scripts, assemblies, DLLs, shellcode, Aggressor extensions, elevation/jump/remote-exec plug-ins and user-defined C2 implementations are unbounded. Their dispatch surfaces are covered by CSB-003, 008, 010 and 014-020; each artifact requires a separate pinned analysis.
- Listener/export/user-exploitation features outside Beacon's running payload are excluded except where they change Beacon runtime or produce a documented Beacon-side procedure. MITRE entries describing historic System Profiler, macro, exploit-kit or payload-generation behavior do not establish a Beacon command and therefore are cross-check context, not Beacon implementation facts.
- No telemetry hypothesis is production-ready. All mappings require tenant-specific UDM/parser verification and safe validation against authorized, non-malicious fixtures. Mutable profiles, process targets, argument/parent shaping, custom code and custom transports make fixed names, hashes, pipes, URIs, services or timing unsafe as sole predicates.

## Sources

1. Fortra, [Cobalt Strike 4.13 current user guide — Beacon command behavior](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/appendix-a_beacon-opsec-considerations.htm), documentation build `202606220941`, June 2026; accessed 2026-08-15.
2. Fortra, [Running Commands and Beacon console command table](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_running-commands.htm), version 4.13; accessed 2026-08-15.
3. Fortra, [Cobalt Strike release notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Cobalt_Strike/Cobalt_Strike.htm), 4.13; accessed 2026-08-15.
4. Fortra, [REST API documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html), API 1.0.0-BETA; accessed 2026-08-15.
5. Fortra, [Network and Host Enumeration](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_network-host-enumeration.htm), version 4.13; accessed 2026-08-15.
6. Fortra, [Lateral Movement](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm), version 4.13; accessed 2026-08-15.
7. Fortra, [Beacon Interpreter](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_beacon-interpreter.htm), version 4.13; accessed 2026-08-15.
8. Fortra, [HTTP and HTTPS Beacon](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructure_beacon-http-https.htm), current/review documentation; accessed 2026-08-15.
9. Fortra, [TCP Beacon](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-tcp.htm), accessed 2026-08-15.
10. MITRE ATT&CK, [Cobalt Strike S0154](https://attack.mitre.org/software/S0154/), ATT&CK record version 1.14, modified 2026-04-23; accessed 2026-08-15.
