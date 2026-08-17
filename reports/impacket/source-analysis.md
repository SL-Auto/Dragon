# Impacket comprehensive source and procedure analysis

## Scope and provenance

- Tool/revision: Fortra Impacket `c23b3d55bc846a2460a459437601a94bfd25a269`
- Input: static source in `sources/impacket-src-pinned`; never built or run.
- Upstream: <https://github.com/fortra/impacket>
- Analyzed/accessed: 2026-08-15; Detection Research Agent
- Scope: all 69 shipped top-level examples, readable `impacket/examples` helpers, and materially distinct observable library-backed paths.
- Confidence: high for readable code; medium for telemetry hypotheses; explicitly `blocked_source` where endpoint protection denied reads.

This defensive report omits invocation syntax, secrets, and deployment instructions. “Observed” means supported by readable pinned source; inference is labelled.

## Immutable evidence

| ID | Pinned source | Supports |
|---|---|---|
| E01 | [project](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/setup.py) | packaged surface |
| E02 | [smbclient](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/smbclient.py#L31-L101), [attributes](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/attrib.py#L166-L177), [times](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/filetime.py#L87-L110) | SMB file operations |
| E03 | [psexec](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/psexec.py#L244-L487), [service installer](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/impacket/examples/serviceinstall.py) | service execution |
| E04 | [atexec](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/atexec.py#L179-L222) | task execution |
| E05 | [wmiexec](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/wmiexec.py#L73-L123), [wmiquery](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/wmiquery.py#L180-L215) | WMI/DCOM |
| E06 | [wmipersist](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/wmipersist.py#L90-L160) | WMI persistence |
| E07 | [addcomputer](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/addcomputer.py#L252-L359), [net](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/net.py#L134-L333) | SAMR account/group operations |
| E08 | [AD users](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/GetADUsers.py#L81-L145), [delegation](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/findDelegation.py#L120-L220) | LDAP discovery |
| E09 | [DACL](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/dacledit.py), [RBCD](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/rbcd.py), [owner](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/owneredit.py) | AD authorization changes |
| E10 | [TGT](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/getTGT.py#L32-L65), [TGS](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/getST.py#L810-L827), [tickets](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/ticketer.py#L345-L390) | Kerberos paths |
| E11 | [GPP](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/Get-GPPPassword.py#L246-L285), [LAPS](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/GetLAPSPassword.py#L160-L245), [DPAPI](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/dpapidump.py#L75-L240) | secret retrieval |
| E12 | [registry](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/reg.py#L56-L180), [regsecrets](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/regsecrets.py#L85-L175), [ESE](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/esentutl.py#L45-L155) | registry/database access |
| E13 | [MSSQL client](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/mssqlclient.py#L30-L90), [TDS](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/impacket/tds.py) | SQL paths |
| E14 | [RPC dump](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/rpcdump.py#L45-L169), [RPC map](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/rpcmap.py), [architecture](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/getArch.py#L40-L80) | RPC discovery |
| E15 | [services](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/services.py#L75-L250), [Terminal Services](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/tstool.py#L70-L625) | service/session control |
| E16 | [SMB server](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/smbserver.py), [Karma SMB](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/karmaSMB.py), [sniff](https://github.com/fortra/impacket/blob/c23b3d55bc846a2460a459437601a94bfd25a269/examples/sniff.py) | listener/packet paths |
| E17 | [ntlmrelayx tree](https://github.com/fortra/impacket/tree/c23b3d55bc846a2460a459437601a94bfd25a269/impacket/examples/ntlmrelayx) | relay servers, clients, attacks, SOCKS |

## Complete shipped-example inventory

All files found under `examples/*.py` are assigned below. Grouping is by genuinely equivalent host-side observability. `BS` means endpoint protection denied the local source read and no bypass was attempted.

| Procedure | Examples/helpers accounted for |
|---|---|
| IMP-01 SMB file/share | `attrib.py`, `filetime.py`, `smbclient.py`, `ntfs-read.py`, `esentutl.py` |
| IMP-02 SMB listener | `smbserver.py`, `karmaSMB.py` |
| IMP-03 service execution/control | `psexec.py`, `services.py`; `serviceinstall.py`, `remcomsvc.py` helpers |
| IMP-04 scheduled-task execution | `atexec.py`; relay RPC task helper |
| IMP-05 WMI/DCOM execution/query | `wmiexec.py`, `wmiquery.py`; `dcomexec.py` (BS) |
| IMP-06 WMI persistence | `wmipersist.py` |
| IMP-07 account/group change | `addcomputer.py`, `net.py`; `changepasswd.py` (BS) |
| IMP-08 account/system discovery | `netview.py`, `machine_role.py`; `lookupsid.py`, `samrdump.py` (BS) |
| IMP-09 LDAP discovery | `CheckLDAPStatus.py`, `GetADComputers.py`, `GetADUsers.py`, `findDelegation.py`, `GetUserSPNs.py` |
| IMP-10 AD authorization change | `dacledit.py`, `owneredit.py`, `rbcd.py`, `badsuccessor.py` |
| IMP-11 Kerberos request | `getTGT.py`, `getST.py`, `getPac.py`, `GetUserSPNs.py`, `keylistattack.py`; `GetNPUsers.py` (BS) |
| IMP-12 offline Kerberos | `ticketer.py`, `describeTicket.py`; `ticketConverter.py` (BS) |
| IMP-13 secret retrieval | `Get-GPPPassword.py`, `GetLAPSPassword.py`, `dpapidump.py`, `dpapi.py`, `regsecrets.py`; `secretsdump.py` and helper (BS), `raiseChild.py` (BS) |
| IMP-14 registry | `reg.py`, `registry-read.py`, `samedit.py` |
| IMP-15 service authentication | `mssqlclient.py`, `mssqlinstance.py`, `checkMSSQLStatus.py`, `mqtt_check.py`, `rdp_check.py`; `DumpNTLMInfo.py` (BS) |
| IMP-16 RPC discovery/specialized | `rpcdump.py`, `rpcmap.py`, `getArch.py`, `mimikatz.py`, `sambaPipe.py` |
| IMP-17 Exchange | `exchanger.py` (BS) |
| IMP-18 Terminal Services | `tstool.py` |
| IMP-19 network packet/capture | `sniff.py`; `sniffer.py`, `ping.py`, `ping6.py`, `kintercept.py` (BS) |
| IMP-20 local parsing/conversion | `split.py`, `ticketConverter.py` (BS), `describeTicket.py`, `dpapi.py`, `samedit.py`, `filetime.py` |
| IMP-21 authentication relay | `ntlmrelayx.py` (BS), readable/partially blocked `impacket/examples/ntlmrelayx/**` |
| IMP-22 special exploit/privilege paths | `goldenPac.py`, `sambaPipe.py`, `badsuccessor.py`; `raiseChild.py` (BS) |

Library modules under `impacket/` were inventoried as reusable protocol machinery: Ethernet/IP/ICMP/IPv6/802.11, DHCP/DNS/MQTT, SMB/NTLM/SPNEGO, LDAP/TDS/Kerberos, DCOM/WMI, and DCE/RPC interface stubs. They have no independent security effect until called; their materially distinct effects map to IMP-01–22. Tests/fixtures, packaging, docs, constants, codecs, structures, logging and error tables are excluded because they perform no target-side action.

## Procedure-level analysis and telemetry

Safe validation for each observable network procedure is replay of approved packet/event captures or synthetic normalized records—never executing Impacket. Fields/event availability are environment-dependent hypotheses.

| ID | Trigger, ordered behavior, interfaces | Effect, artifacts, ATT&CK | Telemetry assessment, configuration, gaps |
|---|---|---|---|
| IMP-01 | With SMB access, authenticate, tree-connect, enumerate/read/write/delete files or alter attributes/times; ESE/NTFS branches access database/raw-file structures. [E02,E12] | Remote collection/staging or artifact modification; share/file metadata. T1021.002, T1005, T1070.006 | 4624 type 3, 5140/5145, 4663, EDR file/SMB; source, account, share, path, access mask, old/new metadata. Enable object/share auditing; content and offline parsing may be invisible. |
| IMP-02 | Bind a local TCP listener and serve SMB shares/auth exchanges. [E16] | Inbound SMB service/credential exposure. T1021.002, T1557 | Firewall/NDR, process socket, SMB auth; bind/peer/dialect/process. Encrypted SMB hides operations. |
| IMP-03 | SMB/RPC auth → SCM open → service create/change/start/stop/delete; execution variant copies service payload and uses pipes. [E03,E15] | Remote execution; service key/file/pipes/children. T1021.002, T1569.002 | System 7045/7036, Security 4697/4688/4624/5145, Sysmon/EDR file/pipe/network. Require service/process auditing; admin tools are common FPs. |
| IMP-04 | Task Scheduler RPC auth → task XML registration → run → optional output retrieval → delete. [E04] | Remote execution; transient task/output. T1053.005 | TaskScheduler 106/100/200/102/201/141; 4698/4699/4688/4624/5145. Capture task URI/XML/action/user/source; rapid cleanup or disabled logs cause gaps. |
| IMP-05 | DCOM/WMI connection → namespace/service acquisition → WQL or `Win32_Process` creation → optional SMB output. [E05] | Execution/discovery; WmiPrvSE lineage, DCOM, optional file. T1047, T1021.003 | WMI-Activity 5857–5861, 4688/Sysmon 1, RPC/SMB; namespace/query/class/parent/source. WQL and origin often absent. |
| IMP-06 | Create/delete WMI event filter, script consumer and binding. [E06] | Persistent WMI objects. T1546.003 | WMI-Activity, Sysmon 19/20/21, EDR repository; filter/consumer/binding/script. Provider coverage varies; baseline repository. |
| IMP-07 | SAMR/LDAP bind → create/delete user/computer, password reset, enable/disable, membership change. [E07] | Account/privilege change. T1136.002, T1098 | DC 4720–4726, 4738, 4741–4743, 4728–4733, 4756–4757, 5136; actor/target/source. RPC attribution may need network joins. |
| IMP-08 | SAMR/LSA/server/workstation binds → enumerate domains/users/groups/SIDs/shares/sessions/role. [E07,E15] | Discovery. T1087.002, T1069.002, T1018 | RPC ETW/NDR and DC object-access if enabled; UUID/opnum/source/account. Many reads lack audit; network RPC metadata compensates. |
| IMP-09 | LDAP(S) bind → searches for users/computers/SPNs/delegation/LAPS/policy → attribute reads. [E08,E11] | Directory/credential-policy discovery. T1087.002, T1018, T1552.006 | LDAP diagnostic 1644, identity audit/NDR; bind, source, base/filter/attributes. Standard logs omit queries; LDAPS needs server logs. |
| IMP-10 | LDAP read/modify of security descriptor, owner, delegation or dMSA state. [E09] | Authorization/delegation change. T1222.001, T1098, T1484.001 | 5136/5137/5141; actor, DN, attribute, old/new, source. Requires SACL; binary descriptor enrichment. |
| IMP-11 | AS/TGS traffic including SPN, pre-auth-less, S4U/U2U/renewal branches; store returned tickets. [E10] | Ticket acquisition. T1558.003, T1558.004, T1550.003 | DC 4768/4769/4771; client/account/service/encryption/options/status. Local cache write is endpoint-only; baseline normal Kerberos. |
| IMP-12 | Create/describe/convert/import/export ticket/cache artifacts locally; optional supporting KDC requests. [E10] | Forged/reused auth material. T1558.001/.002, T1550.003 | `not_observable` remotely when offline. Endpoint file/process plus anomalous 4768/4769/4624 consistency analytics compensate. |
| IMP-13 | Read GPP XML, privileged LDAP fields, DPAPI/SCCM files, hives/secrets, or replication data. [E11,E12,E17] | Credential collection. T1003, T1552.006, T1555, T1558 | 4662 replication GUID, 5145/4663, registry audit, LDAP 1644, WMI; object/path/source. Local decryption invisible; principal implementations partly BS. |
| IMP-14 | Connect/start RemoteRegistry → enumerate/read/set/delete keys; offline branches read/edit hives. [E12] | Registry discovery/change. T1012, T1112, T1003.002 | RemoteRegistry state, 4657/4663, Sysmon 12–14, RPC; key/value/data/actor/source. SACL required; offline edits endpoint-only. |
| IMP-15 | Negotiate/authenticate to TDS, MQTT, RDP or SMB; enumerate MSSQL/config or issue SQL queries. [E13] | Service discovery/auth/query. T1046, T1078 | SQL Audit/XE/login, broker, RDP 1149/4624, firewall/NDR; source/account/query/TLS/result. Query visibility needs auditing; one source BS. |
| IMP-16 | Query endpoint mapper/interface UUID/architecture/named pipes or specialized Mimikatz RPC. [E14] | RPC discovery/control. T1046, T1012 | RPC ETW/NDR, firewall, pipe telemetry; source/UUID/opnum/pipe/auth. Generic RPC logs omit semantics. |
| IMP-17 | Local source inaccessible; exact Exchange actions not asserted. | `blocked_source`; ATT&CK withheld. | Exchange/IIS/mailbox audit is closest telemetry; actor/client/mailbox/operation. Exact calls remain blocked. |
| IMP-18 | Terminal Services RPC enumerate sessions/processes then connect/disconnect/logoff/change state. [E15] | Session discovery/control. T1033, T1021.001 | TerminalServices Operational, 4624/4634/4778/4779, RPC; session/user/source/action. Some RPC changes lack distinct events. |
| IMP-19 | Construct/capture raw Ethernet/IP/ICMP/IPv6/802.11; blocked intercept branch handles Kerberos-related traffic. [E16] | Network discovery/capture. T1040, T1018 | EDR raw-socket/capture-driver/process and NDR. Packet construction is remotely `not_observable`; BS limits details. |
| IMP-20 | Parse/split/convert local files, hives, DPAPI blobs, tickets or captures. | No independent remote effect. | `not_observable` on target; operator-host file/process telemetry is compensating. Several parsers BS. |
| IMP-21 | Accept inbound auth on protocol server → relay via SMB/HTTP(S)/LDAP(S)/MSSQL/RPC/SMTP/IMAP/DCSYNC clients → dispatch service/file/secret/directory/task/SQL/AD-CS plugins; optional SOCKS reuse. [E17] | Relay then effects in IMP-01/03/04/07/10/13/15. T1557.001, T1187 | Correlate victim outbound and target inbound auth with downstream effects: 4776/4624 plus app/network logs. NAT, encryption, missing workstation fields, BS parts impede attribution. |
| IMP-22 | Special examples combine Kerberos/RPC/SMB or LDAP for PAC, Samba pipe, dMSA or child-domain privilege paths. [E07,E09,E10] | Privilege escalation with downstream ticket/account/service effects. T1068, T1484.001, T1558.001 | Correlate KDC, directory change, RPC/SMB and service/process telemetry. `raiseChild.py` BS prevents exact branch coverage. |

## Platform, cleanup, inaccessible source, and limitations

Platform branches accounted for: SMB1/2/3; NTLM/Kerberos; TCP 445/NetBIOS; RPC over SMB/TCP; DCOM/WMI; LDAP/LDAPS; TDS/TLS; Task Scheduler, SCM, SAMR/LSA, Remote Registry, Terminal Services and replication. Local/offline and listener branches are separately represented. Service/task/WMI/output-file cleanup can fail, so detection must not require cleanup.

Endpoint protection denied: `changepasswd.py`, `dcomexec.py`, `DumpNTLMInfo.py`, `exchanger.py`, `GetNPUsers.py`, `kintercept.py`, `lookupsid.py`, `ntlmrelayx.py`, `ping.py`, `ping6.py`, `raiseChild.py`, `samrdump.py`, `secretsdump.py`, `sniffer.py`, `split.py`, `ticketConverter.py`, `impacket/examples/secretsdump.py`, and at least `impacket/examples/ntlmrelayx/servers/socksplugins/smb.py`. No control was changed and no alternate extraction attempted. These remain explicit `blocked_source`; complete source-level branch coverage cannot truthfully be claimed.

Excluded after inventory: tests/data, packaging/CI, documentation, logging, constants, structures/codecs and error tables because they independently create no target-side action. Reusable libraries were traced through shipped examples and grouped by observable effect.

Defensive conclusion: Impacket is a protocol toolkit, not one behavior. Reliable coverage needs Windows/DC audit, WMI/Task Scheduler logs, EDR process/file/registry/pipe telemetry, network/RPC visibility and directory/SQL/application audit. Tool attribution requires correlated authentication origin and effects. Telemetry and YARA-L mappings remain hypotheses until replayed against authorized representative data; no derived rule is production-ready.
