---
title: AdaptixC2 comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# AdaptixC2 comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `e99535c9ef4642190f7ea125c2983d1611f1a3f3` (committed 2026-09-25) from <https://github.com/Adaptix-Framework/AdaptixC2>, accessed 2026-11-21.
- **Handling:** shallow source clone to `sources/adaptixc2-src/` (gitignored), not built or run. Two compiled shellcode stubs (`beacon_agent/src_beacon/files/stub.x64.bin`, `stub.x86.bin`) were deleted unopened. The analysis uses agent source only.
- **Eligibility:** AdaptixC2 is a C2 framework. Analysis is scoped to the victim-side agents:
  - `beacon_agent`: a C/C++ Windows implant.
  - `gopher_agent`: a cross-platform Go agent.
- **Excluded as operator infrastructure:**
  - the team server (`AdaptixServer` core)
  - the listeners (`beacon_listener_http`, `_dns`, `_smb`, `_tcp`; `gopher_listener_tcp`)
  - the operator client (`AdaptixClient`)
  - Listener source was read only to interpret agent transport options. No server-side procedure or detection is produced.

## Completeness inventory

| Component | Source | Disposition |
| --- | --- | --- |
| Beacon command dispatcher | `src_beacon/beacon/Commander.cpp` (37 commands: cat, cd, cp, disks, download, download_state, exec_bof, getuid, jobs_kill, jobs_list, link, ls, mkdir, mv, pivot_exec, profile, ps_kill, ps_list, ps_run, pwd, rev, rm, savememory, shell_start, shell_write, terminate, tunnel_close, tunnel_pause, tunnel_resume, tunnel_reverse, tunnel_start_tcp, tunnel_start_udp, tunnel_write_tcp, tunnel_write_udp, unlink, upload) | Analyzed |
| Beacon transports | `ConnectorHTTP.cpp` (WinINet `InternetOpenA` with profile user agent and optional proxy, L209-306), `ConnectorDNS.cpp` (raw UDP `sendto` DNS with TXT default, L28, L70, L561), `ConnectorSMB.cpp` (named-pipe server, L80-168), `ConnectorTCP.cpp` | Analyzed |
| Beacon pivoting and tunnels | `Pivotter.cpp` (remote pipe `CreateFileA`, L19; TCP links), `Proxyfire.cpp` (TCP and UDP relays, reverse tunnels) | Analyzed |
| Beacon process execution | `Commander.cpp` (`CreateProcessAsUserA` or `CreateProcessWithTokenW` with a stored token, `CREATE_NO_WINDOW`, pipe-captured output, L863-901; interactive shell, L993-1017) | Analyzed |
| Beacon in-memory execution | `bof_loader.cpp` (COFF sections mapped `PAGE_EXECUTE_READWRITE`, L160, L337), `Boffer.cpp` and `beacon_functions.cpp` (token impersonation API for BOFs, L293) | Analyzed |
| Beacon runtime | `ApiLoader.cpp` (API resolution by hash), `WaitMask.cpp` (sleep and work hours), `MemorySaver.cpp`, `JobsController.cpp`, `Crypt.cpp`, `Encoders.cpp`, `Packer.cpp`, `miniz.cpp`, `crt.cpp` | Analyzed (no independent observable beyond the procedures) |
| Gopher agent | `src_gopher/tasks.go` and `functions/*.go` (cat, cd, cp, download, upload, ls, mkdir, mv, rm, pwd, ps, kill, run, execute, shell with pty, screenshot, zip, socks, tcp, rev, job, exit, Windows BOF through `bof/`) | Analyzed |
| Server, listeners, client, Docker and install scripts | `AdaptixServer` (non-extender), listener extenders, `AdaptixClient`, `Dockerfile`, `docker-compose.yml`, `pre_install_linux_all.sh` | Excluded (operator infrastructure) |

The BOFs themselves are supplied by the operator from separate repositories and are not part of this source. Their execution mechanism is analyzed (AX-P06); their payload behavior is outside this revision.

## Procedure analysis

| ID | Procedure | Ordered behavior and interfaces | Security effect | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| AX-P01 | HTTP(S) transport | WinINet sessions with the profile-defined user agent, hosts and URIs, optional proxy; recurring polling with sleep and jitter | C2 channel | Process-attributed outbound connections and proxy logs; profile values are operator-defined | T1071.001, T1573 | High |
| AX-P02 | DNS transport | Raw UDP DNS queries (TXT by default) sent directly with `sendto`, bypassing the Windows DNS Client | C2 over DNS | Process-attributed UDP/53 egress from a non-system process (Sysmon Event ID 3); Sysmon Event ID 22 does not see raw-socket queries | T1071.004 | High |
| AX-P03 | SMB and TCP peer-to-peer transports and pivots | The beacon creates a named-pipe server or TCP bind listener; a parent beacon links to remote pipes (`CreateFileA` on `\\host\pipe\...`) or TCP ports and relays | Internal C2 chaining | Named-pipe creation and connection (Sysmon Event ID 17 and 18), SMB pipe access 5145, process LISTEN and connections | T1090.001, T1572, T1021.002 | High |
| AX-P04 | Gopher TCP transport | Encrypted TCP session from the Go agent to its listener | C2 channel | Process-attributed outbound connections; recurrence | T1095, T1573 | High |
| AX-P05 | Command and process execution | `ps run` with an optional stored token (`CreateProcessAsUserA`, or `CreateProcessWithTokenW` through the Secondary Logon service), hidden window, pipe-captured output; an interactive shell; Gopher run, execute and shell (pty on Unix) | Arbitrary execution | Process creation from an unsigned network process; seclogon-parented children for token execution | T1059, T1134.002 | High |
| AX-P06 | In-memory BOF execution | Maps COFF sections into RWX memory, resolves symbols and runs them; a BOF API impersonates stored tokens | Fileless capability execution | EDR memory-protection events (private RWX) in a network-active process | T1620, T1106 | High |
| AX-P07 | File operations and transfer | List, read, copy, move, delete, make directories, upload and download; Gopher zip archiving | Collection and staging | File events from a network-active process; archive creation | T1083, T1005, T1105, T1560.001 | High |
| AX-P08 | Process and host discovery | Process list and kill, getuid, disk enumeration, profile changes | Discovery and tampering | Generic API activity; process termination events | T1057, T1033, T1082 | Medium |
| AX-P09 | Tunnels and SOCKS | TCP and UDP relays to operator-chosen destinations; reverse tunnels that listen on the victim | Network pivoting | Internal connection fan-out and listeners from a network-active process | T1090.001, T1572 | High |
| AX-P10 | Screenshot | Gopher screen capture | Collection | Screen-capture telemetry (vendor-specific) followed by egress | T1113 | Medium |
| AX-P11 | Agent lifecycle and runtime | Sleep, jitter and work hours, jobs, memory save, termination; API resolution by hash | Stealth and persistence of the session | Not independently observable; recurrence surfaces through transports | T1029, T1027.007 | High |

## Observed facts versus inference

- **Observed:** command lists, transport implementations, raw-socket DNS, process creation with tokens, RWX COFF loading, and the Gopher command set.
- **Inference:** detection thresholds; seclogon parentage for `CreateProcessWithTokenW` follows documented Windows behavior.
