# Mimikatz comprehensive source analysis

## Scope and completeness

- Revision: `306bc6b43099c7b698f2898401fddbded6a630c8` (2026-04-17); official source, inspected statically on 2026-08-15. Nothing was built or run.
- Confidence: high for code behavior; medium for telemetry until tested against an organization's sensors.
- Method: inventory every `KUHL_M_C` registration table, dispatcher, conditional platform branch, and companion project; trace each command to an OS-observable procedure. Commands are grouped only where observability is equivalent.
- Primary evidence: [pinned tree](https://github.com/gentilkiwi/mimikatz/tree/306bc6b43099c7b698f2898401fddbded6a630c8), [module ABI](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m.h#L9-L27), and [dispatcher](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/mimikatz.c#L20-L119).

## Complete command-to-procedure inventory

| Module | Entire registered command surface | Procedures |
|---|---|---|
| standard | exit, cls, answer, coffee, sleep, log, base64, version, cd, localtime, hostname | P01 |
| privilege | debug, driver, security, tcb, backup, restore, sysenv, id, name | P02 |
| process | list, exports, imports, start, stop, suspend, resume, run, runp | P03-P04 |
| token | whoami, list, elevate, run, revert | P05 |
| service | start, remove, stop, suspend, resume, preshutdown, shutdown, list, +, -, me | P06 |
| sekurlsa | msv, wdigest, kerberos, tspkg, livessp, cloudap, ssp, logonPasswords, process, minidump, bootkey, pth, krbtgt, dpapisystem, trust, backupkeys, tickets, ekeys, dpapi, credman | P07-P09 |
| kerberos | ptt, list, ask, tgt, purge, golden, hash, decrypt, pacinfo, ptc, clist | P10-P11 |
| lsadump | sam, secrets, cache, lsa, trust, backupkeys, rpdata, dcsync, dcshadow, setntlm, changentlm, netsync, packages, mbc, zerologon, postzerologon | P12-P16 |
| dpapi | blob, protect, masterkey, credhist, create, capi, cng, tpm, cred, vault, wifi, wwan, chrome, ssh, rdg, ps, luna, cloudapkd, cloudapreg, sccm, citrix, cache | P17-P19 |
| crypto | providers, stores, certificates, keys, sc, hash, system, scauth, certtohw, capi, cng, extract, kutil, tpminfo | P20-P22 |
| vault / ngc / iis | vault:list,cred; ngc:logondata,pin,sign,decrypt,enum; iis:apphost | P23-P25 |
| event / ts | event:drop,clear; ts:multirdp,sessions,remote,logonpasswords,mstsc | P26-P28 |
| sid / net | sid:lookup,query,modify,add,clear,patch; net:user,group,alias,autoda,session,wsession,tod,stats,share,serverinfo,trust,deleg,if | P29-P30 |
| misc | cmd, regedit, taskmgr, ncroutemon, detours, addsid, memssp, skeleton, compress, lock, wp, mflt, easyntlmchall, clip, xor, aadcookie, ngcsign, spooler, efs, printnightmare, sccm, shadowcopies, djoin, citrix | P31-P37 |
| rpc / sysenv | rpc:server,connect,close,enum; sysenv:list,get,set,del | P38-P39 |
| minesweeper / rdm | minesweeper:infos,bsod; rdm:version,list | P40-P41 |
| hardware | acr:open,close,firmware,info; busylight:list,status,single,off,test; sr98:beep,raw,b0,list,hid,em4100,noralsy,nedap | P42 |
| companions | mimilove DPAPI masterkeys; mimidrv IOCTL surface; mimilib SSP/password-filter/subauth/DHCP entry points; mimispool print-monitor entry points | P43-P46 |

Registration evidence: [standard](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_standard.c#L8-L27), [sekurlsa](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L8-L42), [kerberos](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos.c#L13-L33), [lsadump](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_lsadump.c#L8-L31), [DPAPI](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/dpapi/kuhl_m_dpapi.c#L8-L37), [crypto](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_crypto.c#L10-L33), [misc](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_misc.c#L8-L42), [net](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_net.c#L8-L27), [SID](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_sid.c#L8-L22), [TS](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_ts.c#L8-L19).

## Procedure analysis and telemetry

Each entry gives ordered behavior, effect, ATT&CK, telemetry, gaps, and safe validation.

**P01 local utility/output.** Queries host/time/version, changes console/directory, sleeps, encodes I/O, or writes a transcript. Effect: staging only when output is logged (T1074). Telemetry: 4688/Sysmon 1 plus EDR file create/write (process, parent, user, path, hash); internal console actions are `not_observable`. Validate with synthetic process/file fixtures.

**P02 privilege adjustment.** Resolves and enables token privileges via token APIs (T1134). Telemetry: 4672 and EDR token adjustment (process, token, privilege, state); Windows lacks per-call auditing, so compensate with downstream sensitive behavior. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_privilege.c#L27-L111).

**P03 discovery/parsing.** Enumerates processes/modules and parses PE imports/exports (T1057). Telemetry: EDR enumeration and Sysmon 10 remote-process reads; offline/local parsing is `not_observable`. **P04 process control.** Creates, terminates, suspends/resumes processes or supplies another parent (T1106/T1134.004). Telemetry: 4688/Sysmon 1 and EDR lifecycle/handle data (actual/declared parent, creator, target, access). Validate both with synthetic process graphs. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_process.c#L26-L420).

**P05 tokens.** Enumerates, duplicates, impersonates, reverts, or launches under tokens (T1134.001/.002). Telemetry: 4624/4648/4672/4688 and EDR token events; native gaps require account/process-change correlation. **P06 services.** Queries/creates/deletes/controls local or remote services (T1543.003/T1569.002). Telemetry: 4697, System 7045/7036, service registry/process events. Validate with sanitized fixtures.

**P07 LSASS acquisition.** Opens LSASS for VM read or an existing dump. Effect: credential-memory access (T1003.001). Telemetry: Sysmon 10/EDR Process Access and file-read telemetry; fields source/target/access/call trace/path. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L157-L230). **P08 LSASS parsing.** Per-build parsers enumerate MSV, WDigest, Kerberos, TsPkg, LiveSSP, CloudAP, SSP, Credman, DPAPI, ticket/key/trust/backup material. Parsing is `not_observable`; compensate with P07 and later credential/ticket use. **P09 PTH.** Writes authentication material in a logon session (T1550.002). Telemetry: LSASS write access plus 4624/4688 and subsequent network logons. Validate synthetic correlations only.

**P10 Kerberos cache operations.** Lists/requests/retrieves/injects/purges tickets or imports ccache (T1558/T1550.003). Telemetry: DC 4768/4769/4770/4771, endpoint logons and EDR LSA calls; local cache operations can be invisible. **P11 offline Kerberos construction/parsing.** Builds tickets/PAC, derives keys, parses/decrypts tickets/ccache (T1558.001/.003). Computation is `not_observable`; compensate with file I/O and later anomalous ticket use.

**P12 local secret recovery.** Reads live/supplied SYSTEM, SAM and SECURITY hives; derives keys and decrypts SAM, LSA secrets and cached credentials (T1003.002/.004/.005). Telemetry: 4656/4663 with narrow SACLs and EDR registry/file reads; reads are commonly absent. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_lsadump.c#L32-L405). **P13 LSA query/patch.** Retrieves account/trust/backup/package secrets through APIs or LSASS patch paths (T1003/T1555). Telemetry: Sysmon 10/EDR injection plus object-access events; API reads may resemble administration.

**P14 DCSync.** Discovers/binds to a DC and calls DRSGetNCChanges (T1003.006). Telemetry: DC 4662 with replication SACL/auditing and RPC source; principal, object, property GUIDs, source host. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c#L33-L180). **P15 DCShadow.** Registers replication identity and pushes directory changes (T1207). Telemetry: 4662/5136/5141, SPN/DNS and RPC chains. **P16 SAMR/Netlogon secret changes.** Sets/retrieves password-derived material or manipulates machine secure-channel state. Telemetry: 4723/4724/4742, Netlogon Operational and RPC; some calls require correlation. Validate all with synthetic DC fixtures.

**P17 DPAPI core.** Parses/decrypts/protects/creates blobs, masterkeys and credhist. **P18 application stores.** Reads/decrypts CRED, Vault, Wi-Fi/WWAN, Chrome, SSH, RDG, PowerShell, Luna, CloudAP, SCCM, Citrix and cache artifacts (T1555). **P19 protected keys.** Parses CAPI/CNG/TPM key files (T1649). Telemetry: EDR sensitive file/registry reads, CAPI2/TPM/KSP events; offline crypto is `not_observable`, compensate with multi-store access and outputs. Validate synthetic paths. [Source tree](https://github.com/gentilkiwi/mimikatz/tree/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/dpapi).

**P20 crypto enumeration/export.** Enumerates providers/stores/certificates/readers/keys/TPM and optionally exports. **P21 enrollment/key movement.** Requests certificates or moves keys to hardware (T1649); telemetry AD CS 4886/4887, CAPI2/KSP and file events. **P22 crypto patch/extraction.** Patches CAPI/CNG service memory or extracts provider keys (T1055/T1649); telemetry Sysmon 10/EDR tamper plus export files. Enumeration/offline hash/system parsing is partly `not_observable`. Validate synthetic CA/tamper fixtures.

**P23 Vault/CredMan** enumerates stored secrets (T1555.004); **P24 NGC** enumerates/decrypts/signs with Hello keys and can invoke unprotection in a target process (T1649/T1055); **P25 IIS** parses applicationHost XML and protected fields (T1552.001). Telemetry: EDR credential-store/key/config reads, Hello/TPM/CAPI2 and injection events; standard read auditing is incomplete. Validate synthetic fixtures.

**P26 log impairment.** Clears logs or patches Event Log service (T1070.001/T1562.002). Telemetry: Security 1102, System 104, EDR tamper/Sysmon 10 and remote-forwarding gaps. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_event.c#L8-L120). **P27 TS control.** Patches concurrency policy or controls/enumerates sessions (T1021.001); telemetry TerminalServices Operational, 4624/4778/4779 and process tamper. **P28 RDP credential reads.** Reads TermService/mstsc memory (T1003/T1555); telemetry Sysmon 10/EDR process access. Validate synthetic events.

**P29 SID/directory operations.** Resolves/queries or, on x64, modifies SID/SIDHistory and patches NTDS (T1098). Telemetry: 4662/5136/LDAP and NTDS process tamper; lookups are `not_observable`. **P30 network/domain discovery.** NetAPI/LDAP queries users, groups, sessions, shares, trusts, delegation, interfaces and server data (T1087/T1069/T1135/T1482/T1016). Telemetry: LDAP/RPC/NDR/EDR API metadata; local enumeration is often `not_observable`.

**P31 utility spawning/session lock.** Creates cmd/regedit/taskmgr or locks workstation; telemetry 4688/Sysmon 1 and 4800. **P32 memory patch/injection.** Misc patch helpers alter authentication/security processes (T1055/T1556); telemetry EDR tamper, Sysmon 8/10/7. **P33 file transform/staging.** Cabinet/XOR/join/token artifacts cause EDR file events (T1027/T1074). **P34 clipboard.** Reads/writes clipboard (T1115); `not_observable` without vendor clipboard telemetry. **P35 authentication coercion.** Spooler/EFS RPC causes outbound authentication (T1187); telemetry RPC plus SMB/authentication chains. **P36 print modification.** Print RPC changes drivers/config (T1068 context); telemetry PrintService, registry/file/spooler child events. **P37 SCCM/VSS/Citrix/join discovery.** Reads stores/configuration (T1552); telemetry WMI, VSS, registry/file/application logs. Validate all with synthetic chains.

**P38 RPC control.** Hosts/connects/closes/enumerates RPC/named-pipe control (T1021 context). Telemetry: Sysmon 17/18, EDR listener/connection and firewall metadata; names are mutable. **P39 firmware variables.** Enumerates/gets/sets/deletes UEFI variables (T1542.001). Telemetry: firmware/EDR events and privilege context; native visibility may be absent. [Source](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kuhl_m_sysenvvalue.c#L8-L180).

**P40 Minesweeper memory** reads/writes game state; Sysmon 10/EDR process access. **P41 RDM parsing** reads Remote Desktop Manager stores (T1555); EDR file/database reads, otherwise `not_observable`. **P42 hardware** enumerates/controls ACR/PCSC/NFC, BusyLight HID and SR98/RF devices; telemetry USB/HID/smartcard/device-control, but individual commands are usually `not_observable`. Validate synthetic vendor events.

**P43 mimidrv.** Kernel driver exposes process/memory/module/callback/filter/SSDT IOCTL operations (T1014/T1562.001). Telemetry: CI 3076/3089, 4697/7045, Sysmon 6, EDR driver/IOCTL/tamper; never load for validation. [Source](https://github.com/gentilkiwi/mimikatz/tree/306bc6b43099c7b698f2898401fddbded6a630c8/mimidrv). **P44 mimilib.** SSP, password-filter, subauthentication and DHCP hooks can capture material (T1556/T1547.005); telemetry 4610/4611, registry/module loads and host file writes. **P45 mimispool.** Print-monitor callbacks load in spooler (T1547.010); telemetry PrintService, registry, Sysmon 7. **P46 mimilove.** Legacy launcher plus offline DPAPI masterkey parsing; telemetry process and masterkey-file reads. Never load/run companions; synthetic events only.

## Platform branches and exclusions

- Sekurlsa uses per-build structure helpers; `livessp` and `krbtgt` are excluded on ARM64, while `trust`/`backupkeys` compile on x64/ARM64. Kerberos `decrypt`/`pacinfo` require `KERBEROS_TOOLS`. SID mutation/patch is x64-only. Event/TS/LSA/crypto patch tables contain x86/x64/ARM64 and XP-through-current-build variants. PE/process enumeration accounts for native/WOW64. Vault selects Windows 7 versus 8+ layouts. These change implementation, not the procedure telemetry above.
- Explicitly excluded as non-procedure implementation/build material: solution/project/resource/icon and CI files; build/clean scripts and makefiles; SDK compatibility headers; generated MIDL stubs; protocol structure declarations; SQLite amalgamation; shared ASN.1/crypto/registry/string/XML/memory helpers; signature data; README/list files. Callers and protocol effects were analyzed. Commented-out `standard::test` is not registered.
- No source surface was inaccessible. Generated stubs were not re-derived because they add no operator procedure beyond inventoried callers.

## Conclusion

Every registered command and companion entry surface at the pinned revision maps to P01-P46; every procedure has telemetry, gaps, ATT&CK disposition, and a non-executing validation approach. The source inventory is comprehensive for this revision. Telemetry mappings remain `needs_validation`, and no event by itself attributes behavior to Mimikatz.
