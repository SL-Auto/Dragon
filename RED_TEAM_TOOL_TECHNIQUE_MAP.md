# Red-Team Tool Technique and Detection Map

_Defender reference; updated 2026-08-15._

## Scope and mapping rules

This report maps six dual-use security tools to ATT&CK techniques only where the tool's official documentation/repository or MITRE ATT&CK makes the behavior defensible. A mapping means the tool **can** perform the behavior; it does not mean every invocation does. This distinction is critical for the modular Impacket and ROADtools suites and for the legitimate administrative use of AD Explorer.

ATT&CK itself says software pages contain only a subset of publicly reported capabilities ([ATT&CK software guidance](https://attack.mitre.org/software/)). Tool-native methods without a clean ATT&CK fit are listed separately rather than forced into a technique. No operational commands or exploitation steps are included.

### Core telemetry assumed

- Windows process creation/ancestry and hashes; process access; file, registry, service, task, WMI, named-pipe and network telemetry. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) provides many of these primitives.
- Domain-controller Kerberos, logon, directory-service, object-access and replication auditing. Microsoft identifies 4768 as TGT requests and 4769 as service-ticket requests ([Kerberos auditing](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
- LDAP query/search telemetry where the directory platform or sensor exposes it; SMB/RPC/WMI flow and endpoint telemetry.
- Entra sign-in, audit, service-principal, device-registration and Microsoft Graph activity, preserving principal, client/app ID, grant type, source, device, resource and correlation/session identifiers.

## 1. Mimikatz

Primary references: [author repository](https://github.com/gentilkiwi/mimikatz), [MITRE ATT&CK S0002](https://attack.mitre.org/software/S0002/).

| ATT&CK technique | Capability | Strongest detection telemetry |
|---|---|---|
| **T1003.001 – OS Credential Dumping: LSASS Memory** | Reads or extracts credential material from LSASS. | Sysmon ProcessAccess/Event 10 or EDR handle telemetry targeting `lsass.exe`; suspicious memory reads/dumps; unsigned or unexpected caller; correlate privilege enablement, dump-file creation and subsequent logons. |
| **T1003.002 – Security Account Manager** | Extracts local account material from SAM. | Registry/file access to SAM and SYSTEM hives, shadow-copy/raw-volume access, unexpected save/export activity and subsequent credential use. |
| **T1003.003 – NTDS** and **T1003.006 – DCSync** | Obtains domain credential material from NTDS or emulates directory replication. | DC file/raw-volume access for NTDS; directory-replication operations from a non-DC host/principal; replication-right changes; unusual source IP followed by broad authentication. |
| **T1003.004 – LSA Secrets** and **T1003.005 – Cached Domain Credentials** | Extracts LSA-protected secrets or cached logon data. | SECURITY/SYSTEM hive access, LSA process access, backup/shadow-copy use, suspicious exports and later authentication by the same source identity. |
| **T1550.002 – Use Alternate Authentication Material: Pass the Hash** | Uses NTLM material without the cleartext password. | NTLM logons from novel source/host combinations; Logon Type 3 patterns; absence of expected interactive precursor; SMB/RPC/service activity after the logon. Baseline scanners and management systems. |
| **T1550.003 – Pass the Ticket** | Injects or uses Kerberos tickets in a logon session. | New ticket/logon-session anomalies, service access lacking the expected TGT sequence, ticket reuse across hosts, unusual client address and follow-on lateral access. |
| **T1558.001 – Golden Ticket** and **T1558.002 – Silver Ticket** | Forges Kerberos TGTs or service tickets when requisite key material is available. | Ticket lifetimes/fields outside policy; service access without matching KDC request (especially silver-ticket cases); anomalous PAC/account data; privileged access from a new host. |
| **T1134.001 – Access Token Manipulation: Token Impersonation/Theft** | Enumerates, duplicates or impersonates Windows access tokens. | Token/handle API telemetry, privileged process access, a process identity changing without normal logon ancestry, and network actions under an unexpected principal. |
| **T1134.005 – SID-History Injection** | Adds SID history or incorporates it into forged tickets. MITRE explicitly maps Mimikatz to this sub-technique. | Directory object changes to `sIDHistory`; change actor/source; replication events; privileged access immediately after the modification. |
| **T1547.005 – Boot or Logon Autostart Execution: Security Support Provider** | Installs or registers an SSP capability. | Changes to LSA security-package registry/configuration, new DLL/module loads into LSASS, signer/path anomalies and reboot/logon correlation. |
| **T1098 – Account Manipulation** | Includes account/hash manipulation and domain authentication changes; MITRE maps the Mimikatz Skeleton Key and hash-change capabilities here. | Directory account changes, DC process/module anomalies, password/hash changes without the expected administrative workflow, and authentication behavior that bypasses normal password state. |
| **T1207 – Rogue Domain Controller** | The DCShadow capability registers and uses a rogue DC-like replication path to introduce directory changes. | New/changed DC computer and server objects, SPNs and replication configuration; directory replication/RPC from a non-DC host; correlate object creation, replication and cleanup. |
| **T1649 – Steal or Forge Authentication Certificates** / **T1552.004 – Unsecured Credentials: Private Keys** | Exports or operates on authentication certificates/private keys when the relevant crypto capabilities are used. | Certificate private-key access/export, certificate-store changes, unusual key-file creation and subsequent certificate-based authentication. |

Tool-native methods without a clean single mapping: cryptographic certificate/key operations, Windows vault/DPAPI parsing, ticket inspection/export, and offline minidump/hive parsing. Detect these through sensitive-file access, dump/archive creation, certificate private-key access, unusual process ancestry and follow-on identity use; avoid assuming inspection alone is adversarial.

## 2. Rubeus

Primary references: [GhostPack Rubeus repository](https://github.com/GhostPack/Rubeus), [MITRE ATT&CK S1071](https://attack.mitre.org/software/S1071/). Rubeus is a focused Kerberos toolkit; the mappings below describe capability families exposed by the project, not a claim that every execution performs them.

| ATT&CK technique | Capability family | Strongest detection telemetry |
|---|---|---|
| **T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting** | Requests service tickets for SPN-bearing accounts for offline password analysis. | 4769 bursts, many distinct SPNs, unusual requesting host/account, encryption downgrade or legacy type relative to baseline, and a low-use user querying high-value services. |
| **T1558.004 – AS-REP Roasting** | Requests AS-REP material for accounts not requiring pre-authentication. | 4768 events with pre-authentication absent, unusual enumeration/request volume, source novelty and targeting of multiple accounts. Configuration scanners are a key false positive. |
| **T1558.001 – Golden Ticket** and **T1558.002 – Silver Ticket** | Creates or manipulates forged TGT/service-ticket material when keys are supplied. | Same ticket-field, lifetime, KDC-sequence and service-access analytics described for Mimikatz; correlate with unusual .NET execution and ticket-file creation. |
| **T1550.003 – Pass the Ticket** | Imports or applies Kerberos ticket material to a logon session. | Ticket cache/session changes, service access without expected preceding ticket requests, cross-host ticket reuse and lateral activity under a new identity. |
| **T1558 – Steal or Forge Kerberos Tickets** | Enumerates, monitors, extracts, renews and manipulates Kerberos ticket material. Some sub-actions do not cleanly fit a narrower current sub-technique. | Access to LSA/Kerberos credential structures, ticket-cache changes, `.kirbi`-like artifact creation, repeated renewals, and short process → ticket → service-access sequences. |

Tool-native methods without a clean single mapping: ticket triage/display, request monitoring, KDC proxy use, delegation/S4U workflow automation, certificate-based Kerberos request workflows and ticket conversion. Detect with Kerberos request fields and sequence analytics, certificate-authentication logs, unusual client/app/process identity, proxy/network metadata and subsequent service access. Do not map all of these generically to credential theft without evidence of theft or forgery.

## 3. Impacket, by capability family

Primary references: [Fortra Impacket repository](https://github.com/fortra/impacket), [MITRE ATT&CK S0357](https://attack.mitre.org/software/S0357/). Impacket is a protocol library plus many examples; **do not attach every technique below to any process merely because it imports Impacket**.

### Remote execution and lateral movement scripts

| Script/capability family | ATT&CK technique | Strongest detection telemetry |
|---|---|---|
| Service-based execution (`psexec`, `smbexec`) | **T1569.002 – System Services: Service Execution**; SMB/admin-share transport can also evidence **T1021.002 – Remote Services: SMB/Windows Admin Shares** when observed. | Remote SCM/RPC calls, 7045/4697 service creation, short-lived or oddly named services, executable/write to admin shares, service child process and source-host/account correlation. |
| WMI/DCOM execution (`wmiexec`, related DCOM examples) | **T1047 – Windows Management Instrumentation**; MITRE also records **T1570 – Lateral Tool Transfer** for observed staging with `wmiexec`. | WMI-Activity logs, DCOM/RPC from non-management hosts, `WmiPrvSE.exe` ancestry/children, remote file creation and authentication from the same source. |
| Scheduled-task execution (`atexec`) | **T1053.005 – Scheduled Task/Job: Scheduled Task**. | Task Scheduler operational log, 4698/4702, remote RPC source, short-lived tasks, unusual principal/target binary and task deletion after execution. |

### Credential and secrets acquisition

| Script/capability family | ATT&CK technique | Strongest detection telemetry |
|---|---|---|
| `secretsdump` local/remote acquisition | **T1003.002 – SAM**, **T1003.003 – NTDS**, **T1003.004 – LSA Secrets**; **T1003.006 – DCSync** when directory replication is the collection method. MITRE additionally lists **T1003.001 – LSASS Memory** for relevant Impacket modules, but do not attribute that to every `secretsdump` use. | RemoteRegistry/service activity, registry hive access, shadow-copy/NTDS access, replication operations from non-DC principals, admin-share/RPC flow and sensitive output-file creation on the operator host. |
| Kerberos SPN request tooling (`GetUserSPNs`) | **T1558.003 – Kerberoasting**. | 4769 volume/cardinality, unusual source/account, legacy encryption deviation and concentration on SPN accounts. |
| Kerberos ticket request/creation and ccache handling (`getTGT`, `getST`, `ticketer`, ticket conversion) | **T1558.005 – Ccache Files** where ccache files are stolen/used; **T1558.001/.002** only when TGT/service tickets are actually forged; **T1550.003** when ticket material is used for authentication. | KDC sequence and ticket-field anomalies, ccache/ticket artifacts, novel Linux/Python source, service access without expected request chain and cross-host ticket reuse. |

### Relay, capture and protocol tooling

| Script/capability family | ATT&CK technique | Strongest detection telemetry |
|---|---|---|
| NTLM relay tooling (`ntlmrelayx`, legacy relay examples) | **T1557.001 – Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay** when coupled to captured/redirected authentication. | LLMNR/NBT-NS/mDNS responses from unauthorized hosts, inbound authentication immediately followed by outbound authentication from the relay, SMB/LDAP signing/channel-binding failures, and one host authenticating to many targets. |
| Packet capture/sniffing examples | **T1040 – Network Sniffing**. | Raw-socket/packet-capture API use, interface promiscuous mode, capture-driver access, pcap artifact creation and execution by a novel Python process/account. |
| SMB/RPC/WMI/MSSQL/LDAP enumeration examples | Map the **observed result**, not the library: e.g. **T1018 – Remote System Discovery**, **T1046 – Network Service Scanning**, **T1135 – Network Share Discovery**, **T1087.002 – Domain Account**, **T1069.002 – Domain Groups** when that specific data is queried. | Source-to-target/port cardinality, SMB share enumeration, RPC endpoint fan-out, LDAP query volume/filter breadth, SQL instance probes and principal/host novelty. |

Tool-native methods without a clean single mapping: protocol implementation, packet construction/parsing, file-format conversion, standalone SMB/MSSQL clients and benign administrative queries. Attribute ATT&CK only after observing the intent-bearing action or result.

## 4. SharpHound

Primary references: [SpecterOps SharpHound CE documentation](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound), [MITRE ATT&CK BloodHound S0521](https://attack.mitre.org/software/S0521/). SpecterOps states that SharpHound uses native Windows APIs and LDAP to collect from DCs and domain-joined systems, including groups, trusts, object rights, GPO links, OU structure, computer/user properties, local groups and active sessions.

| ATT&CK technique | Collection method | Strongest detection telemetry |
|---|---|---|
| **T1087.002 – Account Discovery: Domain Account** | LDAP collection of domain users and account properties. | Broad LDAP searches for user objects/properties from an unusual workstation/process; query rate and scope; process/network correlation. |
| **T1069.002 – Permission Groups Discovery: Domain Groups** | Security-group membership collection. | LDAP group/member query bursts, recursive membership expansion and unusual collector identity. |
| **T1018 – Remote System Discovery** | Enumerates domain computers and DCs. | LDAP computer-object enumeration followed by multi-host SMB/RPC fan-out. |
| **T1482 – Domain Trust Discovery** | Collects domain trust relationships. | LDAP trust-object queries and cross-domain controller contacts from a new source. |
| **T1615 – Group Policy Discovery** | Collects GPO links and policy-derived local-admin relationships. | LDAP queries for GPO/OU/link attributes and SYSVOL access from an atypical endpoint. |
| **T1069.001 – Permission Groups Discovery: Local Groups** | Queries local Administrators, Remote Desktop, DCOM and remote-management groups across computers. | SAMR/NetLocalGroup/RPC fan-out across many endpoints; repeated authentication; endpoint local-group query telemetry. |
| **T1033 – System Owner/User Discovery** | Collects active user sessions, including looped session collection. | Repeated NetSession/registry/API queries across hosts, periodic multi-host RPC/SMB traffic and long-running collector process. |
| **T1087.001 – Account Discovery: Local Account** | Identifies local administrative users/rights as represented by BloodHound. | Local SAM/group enumeration across many endpoints; correlate to source process and RPC fan-out. |
| **T1560 – Archive Collected Data** | Writes collected JSON into a ZIP archive. | Burst of JSON creation followed by ZIP creation in a user-writable path; process/file correlation and subsequent transfer. |
| **T1106 – Native API** | Uses .NET/native Windows and LDAP namespace APIs for collection. | API-level telemetry is supporting context, not a standalone alert; prioritize process identity plus LDAP/RPC behavior. |

Tool-native methods without a clean single mapping: collection of AD object ACLs/abusable rights, OU topology, SQL admin links, certificate-services relationships and other graph edges. Detect through LDAP security-descriptor requests, specific schema/object-class access, breadth of relationship queries and collector archive content metadata. Authorized defensive BloodHound collection is a major false positive; register signed collectors, service accounts and schedules without suppressing equivalent behavior elsewhere.

## 5. ROADtools

Primary references: [ROADtools repository](https://github.com/dirkjanm/ROADtools), [ROADrecon official guide](https://github.com/dirkjanm/ROADtools/wiki/Getting-started-with-ROADrecon), [roadtx official guide](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-%28roadtx%29). ROADtools includes directory exploration (`ROADrecon`), authentication/token libraries (`roadlib`/`roadtx`) and device/application operations.

| ATT&CK technique | Capability (only when that action occurs) | Strongest detection telemetry |
|---|---|---|
| **T1087.004 – Account Discovery: Cloud Account** | Enumerates Entra users and related identity data. | Broad Graph/Azure AD Graph user queries by a low-use principal/client, high pagination volume, novel source/device and cross-object enumeration sequence. |
| **T1069.003 – Permission Groups Discovery: Cloud Groups** | Enumerates groups, memberships and directory roles. | Group/member/role API bursts, unusual app/client ID and subsequent access to privileged identities. |
| **T1526 – Cloud Service Discovery** | Explores tenant applications, service principals and cloud directory resources. | Cross-resource Graph enumeration, many object types in a short interval and client/principal novelty. |
| **T1528 – Steal Application Access Token** | Applies only when ROADtools obtains or consumes a token not legitimately issued to the operator/session. | Token use from a new IP/device, mismatched device/compliance claims, impossible session transition, token replay indicators and sign-in/audit correlation. Possession cannot be inferred from the tool name alone. |
| **T1550.001 – Use Alternate Authentication Material: Application Access Token** | Uses an existing access/refresh token to authenticate to a resource. | Same token/session identifier from multiple sources, resource/client switching, absent expected interactive sign-in, novel app ID and immediate Graph/resource access. |
| **T1098.005 – Account Manipulation: Device Registration** | Registers or joins devices in Entra when roadtx device functions are used. | Entra device-registration audit events, new device credentials, actor/client/source novelty, compliance/ownership changes and token requests immediately after registration. |
| **T1078.004 – Valid Accounts: Cloud Accounts** | Uses legitimately valid Entra credentials/tokens for access. This is contextual, not intrinsic to all ROADtools use. | Risky/novel sign-in, atypical client and grant, source/ASN change, Conditional Access outcome and follow-on enumeration. |

Tool-native methods without a clean single mapping: conditional-access policy parsing, local SQLite collection and GUI exploration, OAuth client/resource alias discovery, token description/conversion, Primary Refresh Token workflow automation, browser SSO automation, Windows Hello provisioning, certificate/device-key operations and BloodHound export. Detect the cloud-side authentication/audit sequence and local token/database/key artifacts; do not label ordinary OAuth or device registration malicious without identity and intent context.

## 6. Microsoft Sysinternals AD Explorer

Primary reference: [Microsoft AD Explorer documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer). Microsoft describes it as an AD viewer/editor that can navigate objects, view attributes/schema, edit permissions, run saved searches, and save/compare offline AD snapshots.

| ATT&CK technique | Defensible use | Strongest detection telemetry |
|---|---|---|
| **T1087.002 – Account Discovery: Domain Account** | Searches or browses user objects. | LDAP search filters/result volume, attributes requested, source host/process and deviation from the user's administrative role. |
| **T1069.002 – Permission Groups Discovery: Domain Groups** | Browses groups and memberships. | LDAP group/member queries, recursion/breadth and unusual endpoint/account. |
| **T1018 – Remote System Discovery** | Searches computer objects. | LDAP computer-object enumeration and any subsequent host fan-out. |
| **T1482 – Domain Trust Discovery** | Views trust/domain configuration. | Trust-object queries and cross-domain/DC access. |
| **T1615 – Group Policy Discovery** | Searches GPO and linked directory objects. | GPO/OU/link LDAP queries and SYSVOL access if it occurs. |
| **T1222.001 – File and Directory Permissions Modification: Windows File and Directory Permissions Modification** is **not** a good general mapping. | AD Explorer can edit **directory object** permissions, but current ATT&CK T1222.001 is framed around Windows file/directory permissions. Record this as a tool-native directory ACL modification unless the exact action matches a more specific ATT&CK behavior. | Directory Service Changes (for example 5136 where configured), changed security descriptors/ACEs, actor/source, target criticality and change-ticket correlation. |

Tool-native methods without a clean single mapping: sophisticated saved LDAP searches, full AD database snapshots, offline browsing, snapshot comparison, schema inspection and directory-object permission editing. Detect broad LDAP reads (including security descriptors/schema), large result/byte volume, creation of snapshot files, repeated baseline snapshots and unauthorized directory changes. AD Explorer is signed Microsoft software and common in administration/IR; signer or filename alone should never be an alert. Validate role, source host, query breadth, target sensitivity and change authorization.

## Procedure-level implementation notes

These notes add the defensively observable mechanism behind each mapping. Source links target current upstream files or official capability documentation; line anchors are used only where stable enough to be useful.

### Mimikatz implementation

- **T1003.001:** the `sekurlsa` module opens LSASS and initializes memory/package parsers, then walks authentication-package structures. The implementation is centered in [`kuhl_m_sekurlsa.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c) and package-specific files in the same directory. Defensively, this manifests as a nonstandard process obtaining query/read access to LSASS, often followed by structured credential-package reads or dump output.
- **T1003.002/.004/.005:** `lsadump` uses registry/LSA-oriented code for SAM, cached-domain and secret material; see [`kuhl_m_lsadump.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c). Remote/offline variants change whether the strongest signal is LSASS access, registry RPC, hive/raw-file access or a copied hive artifact.
- **T1003.003/.006:** NTDS-file parsing and DRS replication are separate paths. DCSync is implemented through the Directory Replication Service Remote Protocol support under [`modules/rpc`](https://github.com/gentilkiwi/mimikatz/tree/master/modules/rpc), using DRSUAPI rather than reading `ntds.dit` locally. This distinction determines whether to hunt file access or `DS-Replication-Get-Changes*` operations from a non-DC principal/source.
- **T1550.002/.003 and T1558.001/.002:** `sekurlsa` supplies alternate NTLM/key material to a logon context for pass-the-hash; the Kerberos module parses, creates, imports and exports Windows KRB-CRED/ticket structures. See [`kuhl_m_kerberos.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_kerberos.c) and [`kuhl_m_sekurlsa.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c). The durable telemetry is LSA/ticket-cache interaction plus AS/TGS/service-access sequencing, not the ticket filename.
- **T1134.001/.005:** token work uses Windows token handles and impersonation/duplication APIs; SID-history work is exposed in the `misc` module and produces an AD attribute change or forged-ticket SID content. Relevant code is in [`kuhl_m_token.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_token.c) and [`kuhl_m_misc.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_misc.c).
- **T1547.005:** the SSP module builds/registers an authentication package that LSASS can load; see [`mimilib/kssp.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kssp.c). Observe LSA package configuration and a new module in LSASS across reboot/logon.
- **T1098 and T1207:** account/hash manipulation is in `lsadump`; DCShadow registers DC-like directory objects/SPNs and drives replication through DRS RPC. MITRE separately documents the [DCShadow detection model](https://attack.mitre.org/detectionstrategies/DET0276/). Join directory-object creation/change, replication configuration, DRS traffic and cleanup rather than treating any one event as conclusive.
- **T1649/T1552.004:** the crypto module enumerates certificate stores and CryptoAPI/CNG key containers and can export certificate/private-key material; see [`kuhl_m_crypto.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_crypto.c). Key-handle/file access and later certificate authentication are stronger than process branding.

### Rubeus implementation and trust-discovery correction

- **Correction — T1482 removed:** source audit at current master commit `74215f6` found no intrinsic trust-list command, LDAP `trustedDomain` query, `DsEnumerateDomainTrusts`, or equivalent. [MITRE S1071](https://attack.mitre.org/software/S1071/) cites two incident reports; in those reports, Rubeus performs Kerberos activity while `nltest`/AdFind perform trust discovery. Rubeus cross-domain S4U consumes operator-supplied target domain/DC values ([`S4U.cs` lines 628–671](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/S4U.cs#L628-L671)); its use of `Forest.GetCurrentForest().RootDomain.Name` selects a configuration naming context rather than enumerating trust relationships ([`ForgeTicket.cs` lines 434–448](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L434-L448)). The T1482 row was therefore removed as an intrinsic-capability mapping.
- **T1558.003:** the roast family identifies SPN-bearing candidates through LDAP and obtains TGS material either through `KerberosRequestorSecurityToken` or raw TGT-backed TGS requests, then parses/formats the encrypted ticket portion ([`Roast.cs` lines 705–843](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L705-L843)). Observe LDAP filters involving user/SPN/account-control categories followed by many TGS-REQ/4769 events and local output artifacts.
- **T1558.004:** the AS-REP family LDAP-selects or accepts accounts lacking pre-authentication, sends an AS-REQ without normal pre-auth data and parses the returned encrypted AS-REP portion ([`Roast.cs` lines 16–174](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L16-L174)). The KDC-visible discriminator is pre-auth state plus account/source breadth, not the executable name.
- **T1558.001/.002:** ticket-generation actions construct PAC/ticket structures and sign/encrypt them with supplied domain or service key material; diamond-ticket logic first acquires a legitimate TGT and then modifies/re-signs it ([`ForgeTicket.cs` lines 17–45](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L17-L45), [lines 1230–1244](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L1230-L1244)). Detect field/lifetime/PAC inconsistencies and service access without the normal KDC chain.
- **T1550.003/T1558 parent:** pass-the-ticket and cache actions use `LsaCallAuthenticationPackage` with Kerberos query/retrieve/submit message families to enumerate, extract or import ticket material ([`LSA.cs` lines 1026–1080](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L1026-L1080)). Raw AS/TGS construction is in [`Ask.cs`](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L37-L57); S4U constructs S4U2Self then S4U2Proxy exchanges ([`S4U.cs` lines 90–192](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/S4U.cs#L90-L192)). S4U, renewal, KDC proxy and PKINIT are native procedures without a dedicated narrower ATT&CK sub-technique.

### Impacket implementation by family

- **T1569.002/T1021.002:** [`psexec.py`](https://github.com/fortra/impacket/blob/master/examples/psexec.py) uses SMB plus Service Control Manager RPC (`svcctl`) to install/start a service; [`smbexec.py`](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) also drives SCMR over SMB while redirecting output through shares. Expect SMB session/admin-share access, `\PIPE\svcctl`, service-create/start calls, service process creation and cleanup.
- **T1047/T1570:** [`wmiexec.py`](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) uses DCOM to obtain WMI objects and invokes process creation through WMI, with optional remote output staging. Join TCP 135/dynamic RPC, WMI-Activity events, `WmiPrvSE.exe` descendants and any share/file artifacts.
- **T1053.005:** [`atexec.py`](https://github.com/fortra/impacket/blob/master/examples/atexec.py) binds the Task Scheduler RPC interface (`tsch`) and creates/runs/deletes a scheduled task. Task Scheduler operational events and 4698/4702/4699, RPC source and target process form the procedure chain.
- **T1021.003:** [`dcomexec.py`](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py) activates selected COM automation objects remotely over DCOM and invokes an execution-capable method. Detect RPC endpoint mapping/DCOM activation, target COM host/process ancestry and source-account novelty.
- **T1003.002/.003/.004/.006:** [`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) selects local files, remote registry/shadow-copy acquisition or DRS replication. Core parsers and remote operations live in [`impacket/examples/secretsdump.py`](https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py). Identify the chosen method through RemoteRegistry/SCMR, hive/NTDS artifacts, shadow-copy access or DRSUAPI replication—not merely Python execution. T1003.001 applies only to a memory/Mimikatz path actually observed.
- **T1558.003/.004:** [`GetUserSPNs.py`](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) performs LDAP SPN/account discovery then requests TGS material; [`GetNPUsers.py`](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) queries/accepts accounts with the relevant account-control state and performs AS exchanges without normal pre-auth. Correlate LDAP categories with 4769 or pre-auth-absent 4768/4771 patterns.
- **T1558.001/.002/.005 and T1550.003:** [`ticketer.py`](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) builds ticket/PAC structures; [`getTGT.py`](https://github.com/fortra/impacket/blob/master/examples/getTGT.py) and [`getST.py`](https://github.com/fortra/impacket/blob/master/examples/getST.py) drive AS/TGS/S4U exchanges; [`ticketConverter.py`](https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py) converts ccache/KRB-CRED representations. Distinguish forging, requesting, conversion and use through KDC presence, cache-file access and subsequent authenticated protocol traffic.
- **T1557.001/T1040:** [`ntlmrelayx.py`](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) hosts protocol listeners and relays captured NTLM negotiations through protocol clients; [`sniff.py`](https://github.com/fortra/impacket/blob/master/examples/sniff.py) uses packet capture/raw sockets. Detect paired inbound/outbound authentication, listener creation, signing/channel-binding outcomes, raw-socket/pcap access and capture artifacts.
- **Discovery mappings:** `lookupsid`, `rpcdump`, `samrdump`, `smbclient`, `netview`, `mssqlinstance` and LDAP examples each bind their native protocol/interface and query specific objects. Source files are indexed in the official [`examples` directory](https://github.com/fortra/impacket/tree/master/examples). Assign T1018/T1046/T1135/T1087.002/T1069.002 only from the actual RPC/SMB/LDAP/TDS query and returned object category.

### SharpHound implementation

- **T1087.002/T1069.002/T1018/T1482/T1615:** SpecterOps states that SharpHound uses native Windows APIs and LDAP namespace functions. The [official collection documentation](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound) identifies DC-sourced groups, trusts, rights, GPO links, OU structure and user/computer properties. These appear as LDAP searches across user, group, computer, trusted-domain, GPO/OU and security-descriptor categories; directory sensors should retain filter, base DN, scope, requested attributes and result count.
- **T1069.001/T1087.001/T1033:** per-host collection queries local group membership and active sessions through Windows networking/SAM/RPC APIs. The implementation is in the official [`SharpHound` source tree](https://github.com/SpecterOps/SharpHound); defensively, the signature is one process/source performing SAMR/NetSession-style RPC and SMB contact across many hosts, optionally in a periodic session loop.
- **T1560:** collection serializes graph records to JSON and packages the output into a ZIP, explicitly documented by SpecterOps and [MITRE S0521](https://attack.mitre.org/software/S0521/). File telemetry should join JSON writes, archive creation, collection process and later transfer.
- **T1106/T1059.001:** native/.NET API usage is an implementation property; PowerShell applies only to the PowerShell-hosted collector form. Prefer .NET/AMSI/process context plus LDAP/RPC behavior over either mapping alone.
- **Native graph data:** ACL/ACE collection requests directory security descriptors/control access rights; OU, certificate-services and SQL relationships use their respective LDAP object/attribute families. ATT&CK lacks a single “attack-path relationship collection” technique, so preserve these attributes as procedure metadata instead of inventing a mapping.

### ROADtools implementation

- **T1087.004/T1069.003/T1526:** ROADrecon authenticates, gathers paginated directory objects and relationships, and stores them in a local SQLite database. Collection logic and object definitions are in [`roadrecon/gather.py`](https://github.com/dirkjanm/ROADtools/blob/master/roadrecon/roadtools/roadrecon/gather.py) and [`roadlib/metadef`](https://github.com/dirkjanm/ROADtools/tree/master/roadlib/roadtools/roadlib/metadef). Observe Graph/Azure AD Graph resource families for users, groups/memberships, directory roles, applications, service principals, devices and policies, plus the resulting `roadrecon.db` artifact.
- **T1528/T1550.001/T1078.004:** `roadlib` and `roadtx` implement OAuth authorization, refresh, device-code, browser/PRT and application flows and then use resulting bearer tokens against selected resources; see [`roadlib/auth.py`](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/auth.py) and [`roadtx`](https://github.com/dirkjanm/ROADtools/tree/master/roadtx/roadtools/roadtx). The technique depends on provenance: the same HTTP token exchange is benign when authorized. Join Entra sign-in grant/client/resource fields, token/session reuse, source/device and follow-on Graph calls.
- **T1098.005:** roadtx's device functions call Entra device-registration/join services and create/store device certificate/private-key material, as described in the [official roadtx guide](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-%28roadtx%29). Detect device audit records, actor/app/source novelty, new key/certificate artifacts and immediate device-bound token use.
- **Native procedures:** Conditional Access parsing, token description/conversion, PRT-cookie preparation, Windows Hello key provisioning and BloodHound export are separate local/authentication transformations. Preserve Graph resource, grant, client ID, token claims, device state and artifacts rather than collapsing them into token theft.

### AD Explorer implementation

- **T1087.002/T1069.002/T1018/T1482/T1615:** AD Explorer performs LDAP binds/searches and renders matching directory objects/attributes. The [Microsoft documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer) confirms object navigation, property/schema viewing and sophisticated saved searches. Technique assignment follows the queried object category: user, group, computer, trusted-domain, or GPO/OU/link—not the presence of `ADExplorer.exe`.
- **Directory ACL editing (no forced T1222.001):** AD Explorer reads/writes LDAP security descriptors on directory objects. Detect Directory Service Changes such as 5136 when configured, changed `nTSecurityDescriptor`/ACE content, actor/source and target criticality. This is not inherently Windows file-permission modification.
- **Snapshots/comparison (no clean ATT&CK mapping):** AD Explorer can save a broad directory snapshot to a local `.dat`-style artifact and compare snapshots offline. Observe unusually broad LDAP result/byte volume and a large snapshot file created by the signed process. Offline comparison generates little or no DC telemetry, making file/process history important.

## Cross-tool detection priorities

1. **Credential/ticket access:** process access to LSASS, sensitive hive/NTDS access, directory replication from non-DC sources, ticket-file artifacts and KDC/service-access sequence anomalies.
2. **Directory collection:** broad LDAP scope, security-descriptor queries, many object classes/attributes, group expansion, repeated session enumeration and source-process identity.
3. **Lateral execution:** remote SCM/task/WMI operations, admin-share writes, remote authentication and target process/service creation as one correlated chain.
4. **Cloud identity:** authentication grant/client/device context joined to Graph enumeration, registration or privilege/control-plane changes.
5. **Avoid brittle branding:** filenames, hashes, signatures and command strings are enrichment. Base alerts on behavior plus principal, host role, source, target cardinality and time.

For authorized security activity, suppress narrowly by **collector/operator identity + approved source + target scope + time window**. Preserve the underlying behavior signal so equivalent activity outside the engagement remains visible.
