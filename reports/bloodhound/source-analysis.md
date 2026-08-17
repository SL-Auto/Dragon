# BloodHound collectors comprehensive source analysis

## Scope and safety

This report covers the BloodHound collector family: SharpHound, its official SharpHoundCommon implementation dependency, and AzureHound. BloodHound CE v9.5.1 is included only to pin the collector-output ecosystem; its server and UI are excluded from collector procedure coverage. Revisions and provenance are recorded in `sources/bloodhound-manifest.md`. Analysis was static only: nothing was built or executed.

The official SharpHound dispatcher exposes 27 named collection-method options plus `None` and composite presets ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Client/Enums.cs#L6-L38)); its resolver maps every option to a concrete common-library collection flag and changes active methods under stealth mode ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Options.cs#L165-L295)). AzureHound registers 71 root/list commands in the pinned `cmd` tree, with the aggregate Entra and ARM pipelines explicitly composing the individual collectors ([Entra pipeline](https://github.com/SpecterOps/AzureHound/blob/23735c8af6b03a677a3c40e8d274316504ea07ab/cmd/list-azure-ad.go#L64-L139), [ARM pipeline](https://github.com/SpecterOps/AzureHound/blob/23735c8af6b03a677a3c40e8d274316504ea07ab/cmd/list-azure-rm.go#L66-L223)).

## Completeness inventory

SharpHound methods accounted for: Group, Session, LoggedOn, Trusts, ACL, ObjectProps, RDP, DCOM, LocalAdmin, PSRemote, SPNTargets, Container, GPOLocalGroup, LocalGroup, UserRights, Default, DCOnly, ComputerOnly, CARegistry, DCRegistry, CertServices, WebClientService, LdapServices, SmbInfo, NTLMRegistry, All, and None. Options controlling forest/domain recursion, LDAP filters/base DN, computer-file input, LDAP/LDAPS, alternate credentials, port checks, cache/output, loop/throttle, and filename behavior are included in BH-001, BH-002, BH-006, BH-014, and BH-015 ([options](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Options.cs#L15-L162)).

AzureHound commands accounted for: configure/install/start/uninstall; aggregate `list azure-ad` and `list azure-rm`; Entra tenants, users, groups/members/owners, devices, applications/owners/federated credentials, service principals/owners/app-role assignments, roles/assignments/eligibility/policies; ARM management groups/descendants, subscriptions, resource groups, key vaults/access policies, virtual machines, scale sets, function apps, web apps, automation accounts, container registries, logic apps, managed clusters, storage accounts/containers; and every registered owner/contributor/user-access-administrator/role-assignment projection for those resources. These 71 registrations are grouped only where the remote API, audit surface, and defensive observability are equivalent.

## Procedure analysis

### BH-001 — collector initialization, configuration and targeting

SharpHound parses collection methods, domain/forest scope, LDAP connection settings, alternate identities, host filters and output controls before resolving flags. AzureHound loads tenant, client, token/certificate/secret, proxy, output and service settings. Security effect is preparation for broad identity discovery; configuration parsing itself is not attributable. Observe process creation, sensitive configuration-file reads and the subsequent LDAP/cloud network context. Telemetry: Windows 4688 or Sysmon 1/EDR process launch; EDR file-read events for collector configuration; proxy/EDR connections. Gap: renamed/in-process collectors defeat name attribution. ATT&CK: T1087, T1482. Safe validation: sanitized process and configuration-read fixtures only.

### BH-002 — LDAP directory object and property enumeration

The LDAP producer constructs default and configuration naming-context queries, tests connectivity and performs paged searches ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Producers/LdapProducer.cs#L24-L139)). It enumerates users, computers, groups, domains, OUs and other directory objects. Observe process-attributed LDAP_SEARCH, DC LDAP diagnostic event 1644 when enabled, network connections to DCs, query scope/filter/attributes and result counts. Gap: ordinary LDAP reads are not represented by Security 4662 unless SACL/access semantics apply. ATT&CK: T1087.002, T1018, T1069.002. Safe validation: synthetic LDAP-search logs against a lab directory.

### BH-003 — ACL and security descriptor collection

When ACL collection is selected, processors request and parse security descriptors, including AdminSDHolder and directory object ACLs ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Producers/LdapProducer.cs#L62-L101)). Observe LDAP filters/attribute lists containing security-descriptor controls, 4662 only where relevant SACLs produce it, and high-volume directory reads. Gap: standard domain audit policy does not reliably log every read. ATT&CK: T1222.001, T1087.002. Safe validation: sanitized LDAP query metadata.

### BH-004 — group, trust, container, GPO and SPN topology

The Group, Trusts, Container, GPOLocalGroup, SPNTargets and ObjectProps methods build relationship edges from LDAP objects; the object processor dispatches by object label and invokes group, trust, container, GPO and SPN processors ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L49-L113)). Observe broad LDAP object-class/filter diversity and distinct result categories from one process/account. ATT&CK: T1482, T1069.002, T1615. Safe validation: multi-category directory-query fixtures.

### BH-005 — AD certificate services collection

CertServices expands configuration-NC LDAP queries for CAs, templates, issuance policies, NTAuth stores and ACLs; CARegistry adds host registry reads. The object processor explicitly handles enterprise CAs, templates and enrollment permissions ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L746-L885)). Observe configuration-NC LDAP searches for PKI classes/attributes plus remote registry telemetry on CA hosts. ATT&CK: T1649, T1018. Safe validation: synthetic PKI LDAP query events.

### BH-006 — DNS resolution and SMB reachability discovery

Computer targeting resolves hosts and checks availability, including SMB/445 unless disabled; computer-file input resolves supplied names to LDAP objects ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Producers/ComputerFileProducer.cs#L28-L100)). Observe process-attributed DNS and high-cardinality network attempts to many hosts on SMB/RPC ports, Windows Filtering Platform 5156, firewall/NDR flows and EDR network events. ATT&CK: T1018, T1046. Safe validation: non-executing flow fixtures.

### BH-007 — remote session enumeration

Session collection invokes NetSessionEnum-style RPC against reachable computers and records session relationships; the orchestration labels this task `NetSessionEnum` ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L324-L347)). Observe process-attributed RPC/SMB fanout, SRVSVC interface calls and target share/logon context where available. There is no reliable native Windows event dedicated to a successful NetSessionEnum query. ATT&CK: T1033, T1049. Safe validation: sanitized RPC metadata.

### BH-008 — remote logged-on user registry collection

LoggedOn collection supplements session enumeration with remote-registry user-session reads unless disabled ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L349-L368)). Observe RemoteRegistry service state, RPC/SMB, scoped registry object access/SACL events and EDR registry-read telemetry with remote source correlation. ATT&CK: T1033, T1012. Safe validation: representative remote-registry audit fixtures.

### BH-009 — SAMR local group and remote-access rights enumeration

LocalAdmin, RDP, DCOM, PSRemote and LocalGroup resolve local group membership through common-library SAMR/RPC processors. Observe SAMR interface calls, process-attributed SMB/RPC fanout, target account/group identifiers and source identity. Standard events may expose authentication but not the exact read operation. ATT&CK: T1069.001. Safe validation: sanitized SAMR call metadata.

### BH-010 — local user-rights assignment collection

UserRights invokes policy/rights processors to identify principals assigned sensitive local rights. Observe LSA policy RPC calls and the same source-to-many-host correlation; normal Security logs generally do not identify a rights-query operation. ATT&CK: T1069.001, T1087.001. Safe validation: synthetic LSA RPC records.

### BH-011 — SYSVOL GPO policy file collection

GPOLocalGroup resolves policy paths and reads GPO artifacts to derive local group changes; the object processor invokes GPO local-group processing for domains/OUs/GPOs ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L558-L632)). Observe DC 5140/5145 for SYSVOL, EDR file reads and process-attributed SMB. ATT&CK: T1615. Safe validation: sanitized SYSVOL read events.

### BH-012 — remote security-configuration registry collection

CARegistry, DCRegistry and NTLMRegistry read certificate mapping, channel binding, Netlogon and NTLM-related settings from remote hosts; explicit DC and NTLM registry branches are visible in the object processor ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L378-L446)). Observe remote registry RPC, sensitive key reads, RemoteRegistry service transitions and source fanout. ATT&CK: T1012, T1552. Safe validation: synthetic registry-read and service events.

### BH-013 — WebClient, LDAP and SMB capability probing

WebClientService, LdapServices and SmbInfo actively query service/protocol properties; LDAP service scanning records LDAP/LDAPS availability and signing/channel-binding posture ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/ObjectProcessors.cs#L390-L459)). Observe high-cardinality WebDAV/SMB/LDAP connection attempts and RPC service queries from one process. ATT&CK: T1046, T1018. Safe validation: flow-only fixtures.

### BH-014 — looped and throttled collection

Loop mode repeats computer collection for a configured duration/interval; only LocalGroups, LoggedOn and Session remain in loop scope ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/BaseContext.cs#L95-L102)). Detect recurrence across repeated windows rather than assuming a fixed rate; delay and jitter make a single threshold fragile. ATT&CK: T1033. Safe validation: reordered periodic event fixtures.

### BH-015 — cache and output artifacts

SharpHound writes typed JSON, optional CSV/metrics and cache data, then creates a ZIP and deletes intermediate files; loop output follows the same archive lifecycle ([source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/OutputWriter.cs#L173-L226), [loop source](https://github.com/SpecterOps/SharpHound/blob/a2f843593a5b55ea645ab466f5c91effeda52dda/src/Runtime/LoopManager.cs#L83-L123)). Observe same-process creation of multiple JSON files followed by archive creation and rapid deletion, using Sysmon 11/23/26 or EDR file lifecycle telemetry. Filenames are mutable and must not be required. ATT&CK: T1005, T1560.001. Safe validation: benign synthetic file-lifecycle events.

### BH-016 — AzureHound configuration, authentication and token acquisition

AzureHound supports JWT, refresh token, client secret, certificate, username/password and managed identity configuration, plus proxy and cloud-region selection ([source](https://github.com/SpecterOps/AzureHound/blob/23735c8af6b03a677a3c40e8d274316504ea07ab/config/config.go#L101-L198)). Observe Entra sign-in/service-principal sign-in logs, token endpoint requests, process/config-file reads and subsequent Graph/ARM activity. Authentication alone is not malicious. ATT&CK: T1528, T1087.004. Safe validation: sanitized sign-in and token-request fixtures.

### BH-017 — Microsoft Graph Entra enumeration

The aggregate pipeline enumerates tenants, applications and federated credentials, devices, groups/members/owners, service principals/owners/app-role assignments, users, roles/assignments, eligibility schedules and policies ([source](https://github.com/SpecterOps/AzureHound/blob/23735c8af6b03a677a3c40e8d274316504ea07ab/cmd/list-azure-ad.go#L64-L139)). Observe Microsoft Graph activity logs with one principal/app accessing many directory resource types and pagination-heavy GET activity, correlated to sign-ins. ATT&CK: T1087.004, T1069.003, T1526. Safe validation: sanitized GraphActivityLogs fixtures.

### BH-018 — Azure Resource Manager hierarchy and resource enumeration

The ARM aggregate pipeline enumerates management groups, subscriptions, resource groups, key vaults, VMs, scale sets, storage, web/function/logic apps, automation, registries and clusters ([source](https://github.com/SpecterOps/AzureHound/blob/23735c8af6b03a677a3c40e8d274316504ea07ab/cmd/list-azure-rm.go#L136-L223)). Observe AzureActivity/read-plane audit where available, ARM gateway/proxy logs and one principal reading many resource providers/scopes. AzureActivity may not contain every successful GET, so API gateway/cloud audit coverage must be verified. ATT&CK: T1526, T1580. Safe validation: synthetic ARM request metadata.

### BH-019 — Azure RBAC, ownership and access-policy enumeration

Dedicated commands project role assignments into owners, contributors, user-access administrators and resource-specific roles at management-group, subscription, resource-group and individual-resource scopes; key-vault access policies and Entra role eligibility are also collected. Observe Microsoft.Authorization roleAssignments/read and roleDefinitions/read activity, Graph role-management reads, target scopes and high distinct-object counts. ATT&CK: T1069.003, T1087.004. Safe validation: sanitized cloud audit fixtures.

### BH-020 — AzureHound output and service lifecycle

AzureHound streams JSON output and supports configure/start plus Windows service install/uninstall commands; local configuration may contain sensitive authentication material. Observe process/file creation, service installation/removal, configuration writes and sustained Graph/ARM egress. Service events alone are not tool-specific. ATT&CK: T1543.003, T1005. Safe validation: benign service/configuration fixtures without running AzureHound.

## Defensive conclusion

BloodHound collector activity is a multi-protocol discovery workflow, not a stable process name or filename. Strong coverage correlates directory/cloud enumeration breadth, one-source-to-many-target RPC/SMB behavior, sensitive registry/SYSVOL reads and collection artifact lifecycle. All rules are behavioral hypotheses and deliberately non-attributive. Tenant parser mapping and authorized fixtures are required before deployment.
