# Red-Team Tool Detection Priorities

_Defender-focused shortlist; updated 2026-08-15._

## Scope and ranking caveat

There is no authoritative global usage ranking for red-team tools. This report therefore uses **priority tiers**, based on the tools' established role, broad capabilities, project visibility, and relevance to common enterprise environments. It is a detection-engineering starting point, not a claim that one tool is used more often than another.

Names, hashes, default ports, TLS fingerprints, user agents, and stock URI patterns are useful enrichment, but weak primary detections: operators can rename, recompile, reconfigure, or wrap most tools. Prefer behavior and correlated sequences. The notes below describe telemetry and detection opportunities only; they intentionally omit payload generation and operational instructions.

## Telemetry to have before writing tool detections

- **Windows endpoint:** process creation and ancestry, full command line, signer/hash, image/module loads, process access, service/task/WMI activity, named pipes, DNS and process-attributed network connections. Microsoft documents these primitives in [Sysmon Event IDs 1, 3, 7, 8, 10, 17–18 and 22](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Security Event 4688 can include command lines when explicitly enabled, but Microsoft warns those arguments are stored in clear text ([command-line process auditing](https://learn.microsoft.com/en-gb/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)).
- **Identity and AD:** domain-controller Kerberos, logon, directory-service and object-access auditing; LDAP query telemetry where available. Event 4768 represents TGT requests and 4769 service-ticket requests ([Microsoft Kerberos auditing guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
- **Network:** DNS, proxy, TLS metadata, NetFlow, firewall, IDS and east-west connection telemetry. Preserve source process/device identity and destination novelty/cardinality.
- **Cloud/SaaS:** AWS CloudTrail; Entra sign-in, audit and service-principal logs; Microsoft Graph activity where licensed/available; equivalent GCP audit logs. Normalize principal, source IP/ASN, region, client/application ID, user agent, API action, target resource, result and session/token identifiers.

## Tier 1: build and validate first

### Operator and C2 frameworks

| Tool | Why it matters | High-value detection opportunities | False-positive and resilience notes |
|---|---|---|---|
| **Cobalt Strike Beacon** | A commercial adversary-simulation platform with HTTP/S, DNS and peer-to-peer Beacon channels; MITRE records a wide set of post-exploitation behaviors ([Cobalt Strike Beacon](https://www.cobaltstrike.com/product/features/beacon), [MITRE ATT&CK S0154](https://attack.mitre.org/software/S0154/)). | Correlate unbacked/injected executable memory or suspicious cross-process access with unusual child processes and new egress. Hunt periodic/jittered callbacks, rare destinations, DNS tunneling characteristics, and unexpected SMB/named-pipe peer activity. | Malleable C2 intentionally changes network indicators. Updaters, SaaS agents and remote-management tools can also beacon; alert on a sequence, not periodicity alone. |
| **Sliver** | Bishop Fox describes Sliver as a cross-platform adversary-emulation framework; implants support asynchronous beacon and interactive session behavior ([official repository](https://github.com/BishopFox/sliver), [official getting-started documentation](https://github.com/BishopFox/sliver/wiki/Getting-Started)). | Rare/unsigned executable plus service/task/process creation; anomalous parent-child chains; process-attributed outbound TLS/HTTP/DNS to a novel destination; short-interval discovery or lateral-movement activity after first callback. | Go binaries and encrypted egress are common. Hash and filename detections mainly find stock builds. |
| **Havoc** | A modular post-exploitation C2 with HTTP/S, SMB and external C2 support ([official repository](https://github.com/HavocFramework/Havoc)). | Unbacked executable memory, process injection/access, anomalous child processes, named-pipe/SMB peer behavior and beacon-like egress; correlate with follow-on credential or discovery activity. | The repository is archived, so prioritize historical coverage. Static indicators are especially brittle because agents and profiles are customizable. |
| **MITRE CALDERA** | An adversary-emulation platform with asynchronous C2 and extensible agents/plugins ([official repository](https://github.com/mitre/caldera)). | Unexpected agent execution, new services/tasks, process and script chains, and callbacks to unapproved CALDERA servers; distinguish sanctioned exercise infrastructure by identity and time window. | Often legitimate in purple-team labs. Do not globally suppress its behavior because the same techniques represent real intrusion activity. |

### Credential, identity and AD access

| Tool | Why it matters | High-value detection opportunities | False-positive and resilience notes |
|---|---|---|---|
| **Mimikatz** | The canonical Windows credential and security package ([author's repository](https://github.com/gentilkiwi/mimikatz)). | Suspicious LSASS process access/memory reads, dump creation, access to SAM/SECURITY secrets, privilege enablement, abnormal ticket operations, and directory replication from non-DC identities. Correlate Sysmon ProcessAccess with process signer, ancestry and subsequent authentication. | EDR, backup, crash-dump and identity products may access LSASS or registry secrets. Allowlist narrowly by signer, path, host role and expected time. |
| **Rubeus** | GhostPack's .NET Kerberos interaction and abuse tool ([official repository](https://github.com/GhostPack/Rubeus)). | Baseline 4768/4769 by account, host, service and encryption type; flag unusual service-ticket volume, rare source hosts, anomalous renewals and ticket use followed by new logons or lateral access. Correlate unusual .NET assembly execution. | SSO, service accounts and scanners create heavy Kerberos traffic. Encryption type by itself is not malicious; baseline legacy dependencies. |
| **Impacket** | Fortra's widely used Python implementation of SMB, MSRPC, NTLM, Kerberos, WMI/DCOM and related protocols ([official repository](https://github.com/fortra/impacket)). | Remote service/task creation, SCM/RPC/WMI from non-management hosts, anomalous admin-share access, new service binaries, NTLM/Kerberos use outside the source baseline, and a Python/rare process followed by multi-host SMB/RPC fan-out. | SCCM, backup, vulnerability scanning and IT automation can be behaviorally similar. Source-host role and account context are mandatory. |
| **BloodHound / SharpHound / AzureHound** | BloodHound maps attack paths; its collectors gather AD and Entra data ([official collection overview](https://bloodhound.specterops.io/collect-data/overview), [AzureHound repository](https://github.com/SpecterOps/AzureHound)). | Bursts of LDAP object/property queries, repeated session/local-group enumeration, SMB/RPC fan-out, collector archive creation, or high-volume Graph enumeration of users, groups, apps and roles from a novel host/client. | BloodHound is also a defensive product; IAM governance and inventory tools resemble it. Register approved collectors, identities and windows, while retaining behavior alerts outside them. |

### Network discovery and pivoting

| Tool | Why it matters | High-value detection opportunities | False-positive and resilience notes |
|---|---|---|---|
| **Nmap** | The official project calls Nmap a network-discovery and security-scanning utility used by millions ([official guide](https://nmap.org/book/)). | High destination-host or destination-port cardinality; TCP/UDP/ICMP sweeps; service-probe strings; a new source performing sequential or parallel fan-out. The project itself notes that Internet scans are common and hard to classify ([official detection discussion](https://nmap.org/book/nmap-defenses-detection.html)). | Asset inventory, monitoring and vulnerability scanners generate the same shape. Maintain scanner allowlists, but alert when an approved account/tool appears on a new source. |
| **Chisel** | A single-binary SSH-secured TCP/UDP tunnel transported over HTTP, supporting reverse forwarding, SOCKS and reconnects ([official repository](https://github.com/jpillora/chisel)). | Rare executable plus a long-lived outbound HTTP-like connection, persistent reconnect pattern, local listener/proxy creation, and one endpoint subsequently reaching many internal destinations. | Developer tunnels, remote support, proxies and service meshes can match individual signals. Correlate endpoint listener/process data with network fan-out. |
| **Ligolo-ng** | A TUN-based pivoting tool using reverse TCP/TLS connections and supporting multiple tunnels ([official repository](https://github.com/nicocha30/ligolo-ng)). | New virtual interface or route changes, long-lived encrypted egress, unexpected listener creation, and the host suddenly mediating broad internal connections. | VPN clients, containers and overlay networks create interfaces/routes. Baseline authorized agents and deployment paths. |

## Tier 2: environment-dependent priorities

### Phishing and adversary-in-the-middle access

| Tool | Why it matters | High-value detection opportunities | False-positive and resilience notes |
|---|---|---|---|
| **Evilginx2** | A reverse-proxy phishing framework able to capture credentials and session cookies ([author's repository](https://github.com/kgretzky/evilginx2)). | Lookalike/new domains and certificates; sign-in from a new IP/ASN/device immediately after a user visits a suspicious domain; session-cookie or token reuse; impossible changes in device/session binding; mailbox or app activity immediately after the sign-in. | CDNs, secure web gateways, mobile networks and travel can shift IP/ASN. Require a click/domain + identity/session sequence rather than geolocation alone. |
| **GoPhish** | A widely adopted open-source phishing framework used for authorized simulations ([official repository](https://github.com/gophish/gophish), [campaign documentation](https://docs.getgophish.com/user-guide/documentation/campaigns)). | Campaign bursts, novel sender infrastructure, lookalike domains, redirect/tracking patterns, landing-page submissions, and post-click process/network activity. | Awareness campaigns intentionally produce these signals. Coordinate sender IPs, domains and test windows, but suppress only the engagement identity/infrastructure—not all phishing behavior. |

### Cloud tooling

| Tool | Why it matters | High-value detection opportunities | False-positive and resilience notes |
|---|---|---|---|
| **Pacu (AWS)** | Rhino Security Labs' modular AWS offensive-security framework spans enumeration, privilege escalation and other cloud actions ([official repository](https://github.com/RhinoSecurityLabs/pacu)). | CloudTrail bursts of List/Get/Describe followed by unusual IAM, STS, Lambda, key, policy or logging-control changes; novel source IP/region; low-use principal suddenly crossing many services/regions. | IaC, CSPM, CI/CD and inventory are API-heavy. Baseline role, source, session and approved automation; treat user agent as enrichment only. |
| **CloudFox (AWS/Azure/GCP)** | Bishop Fox's cloud situational-awareness and enumeration tool ([official repository](https://github.com/BishopFox/cloudfox)). | Broad cross-service/cross-region inventory, access to secrets/configuration metadata, and uncommon API combinations by a principal with little historical use. | CSPM, CMDB, cost and compliance tools look similar. Focus on principal novelty and follow-on sensitive access. |
| **ROADtools (Entra ID)** | A toolkit for Entra authentication/token flows and directory reconnaissance ([official repository](https://github.com/dirkjanm/ROADtools), [official wiki](https://github.com/dirkjanm/ROADtools/wiki)). | Unusual client IDs or grant flows, token use from a new IP/device, Graph enumeration bursts, suspicious app/device registration, and risky sign-in followed by directory or resource access. | First-party clients and admin automation can overlap. Correlate client ID, grant type, resource, device compliance, principal and source. |
| **ScoutSuite** | NCC Group's multi-cloud security-auditing tool ([official repository](https://github.com/nccgroup/ScoutSuite)). | Read-heavy inventory bursts across services and regions from a new principal/host; unexpected local report artifacts on endpoints; access outside scheduled assessment windows. | This is primarily defensive and resembles CSPM by design. Prioritize unauthorized identity/source/window detection over tool branding. |

## Recommended detection backlog

1. **Behavioral primitives:** process creation/ancestry, suspicious process access, injected/unbacked memory, service/task/WMI creation, named pipes/listeners, LDAP/RPC/SMB fan-out, Kerberos anomalies, rare egress and cloud control-plane changes.
2. **Sequences:** new or rare process → novel callback → discovery fan-out → credential access → lateral authentication; or cloud enumeration burst → privilege/policy change → new key/session → sensitive-resource access.
3. **Environment context:** host role, principal history, signer, source network, management tooling, maintenance window and approved red-team engagement metadata.
4. **Tool-specific enrichment:** stock filenames, hashes, certificates, protocol fingerprints, default URIs and user agents. Keep these modular and expiring.
5. **Purple-team validation:** exercise each behavior with authorized emulation, confirm required logs arrive, measure signal latency, record expected benign collisions, and test renamed/reconfigured variants.

## Suppression policy

Suppress authorized testing using a conjunction of **engagement identity + source infrastructure + target scope + time window**. Avoid broad exclusions for a tool name, interpreter, protocol, user agent or red-team subnet. Log and periodically review every suppression, because an attacker can deliberately imitate approved tooling.

## Practical takeaway

For most Windows-heavy enterprises, begin with Cobalt Strike/Sliver-like C2 behavior, Mimikatz-style credential access, Rubeus/Impacket/BloodHound identity and lateral-movement patterns, and Nmap/tunnel fan-out. Add Evilginx-style identity sequences and cloud API behavior wherever Entra, Microsoft 365, AWS or multi-cloud services are material. Detection of a branded tool is a bonus; detection of the underlying behavior is the durable control.
