# Rubeus Source and Detection Deep Dive

_Defensive source audit; 2026-08-15._

## Audit identity and method

- **Official repository:** [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- **Pinned HEAD:** [`74215f68ea70bd6a66c008da91bf5fe21d20b154`](https://github.com/GhostPack/Rubeus/tree/74215f68ea70bd6a66c008da91bf5fe21d20b154), independently verified with `git ls-remote` on 2026-08-15.
- **Method:** direct review of the pinned C# source, cross-checked against Microsoft event/API documentation and [MITRE ATT&CK S1071](https://attack.mitre.org/software/S1071/).

Every source citation below is an immutable GitHub blob URL. **Fact** means directly present in source. **Defensive inference** means a likely observable derived from that implementation; it is not a claim that Windows emits a dedicated event for the API call.

This report omits execution syntax, credential examples and operational abuse steps.

## Executive findings

1. Rubeus is a managed .NET command dispatcher around three main subsystems: raw Kerberos/ASN.1 and crypto, Windows LSA ticket-cache APIs, and selective LDAP/domain discovery.
2. Raw AS/TGS traffic goes directly to a chosen/discovered DC over TCP/88; an alternative path wraps KDC messages in MS-KKDCP over HTTP(S). Network telemetry can therefore identify the process-to-KDC relationship when endpoint attribution exists.
3. Cache extraction, injection and purge use `LsaCallAuthenticationPackage` Kerberos protocol messages. Default Windows logs do not provide a simple “ticket imported” event; EDR API telemetry, LUID/session correlation and subsequent service access are stronger.
4. Roasting is a two-stage procedure: LDAP candidate discovery followed by AS-REQ or TGS-REQ activity. Joining LDAP breadth to DC 4768/4769 telemetry is substantially stronger than either signal alone.
5. Ticket forging occurs locally and can leave no KDC request for the forged ticket. Service-side logon and ticket/PAC anomalies, plus process/artifact context, are therefore more useful than looking only for KDC events.
6. The source contains explicit “opsec” branches and a net-only process/logon-session helper, but no built-in AMSI/ETW patching or general process injection in this commit.
7. **Correction retained from the broader tool map:** current source has no intrinsic domain-trust enumeration implementation. MITRE's T1482 citation reflects incident co-occurrence, not a source-backed Rubeus capability.

## Telemetry semantics used in this report

- Microsoft defines Security **4768** as a TGT request and **4769** as a service-ticket request ([Microsoft Kerberos auditing guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
- **4771** is a KDC failure to issue a TGT; it is generated on DCs and is not generated for accounts configured without Kerberos pre-authentication ([Microsoft event 4771](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)).
- Security **4624 Logon Type 9 (`NewCredentials`)** means the caller clones its local token but supplies different credentials for outbound connections ([Microsoft event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [logon-type API](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-security_logon_type)).
- Sysmon **1, 3, 10 and 11** cover process creation, process-attributed network connections, cross-process access and file creation respectively. Microsoft notes Event 3 is disabled by default and Event 10 can be noisy ([Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).

## 1. Entry point, parsing and dispatch

### Source facts

- `Main` joins the process arguments, parses them, recognizes `/consoleoutfile`, and passes the first positional token as the command name ([`Program.cs` lines 107–136](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Program.cs#L107-L136)).
- `MainString` and `MainExecute` also support in-process invocation, and the dispatcher instantiates `CommandCollection` then invokes the selected `ICommand` with a string dictionary ([`Program.cs` lines 7–61](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Program.cs#L7-L61)).
- The parser treats slash-prefixed tokens as case-insensitive keys, with optional values, rather than using a shell or PowerShell interpreter ([`ArgumentParser.cs` lines 7–43](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Domain/ArgumentParser.cs#L7-L43)).
- Command registration is explicit in the constructor, producing a finite action surface ([`CommandCollection.cs` lines 7–61](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Domain/CommandCollection.cs#L7-L61)).

### Defensive inference and detections

- **High confidence:** on-disk execution is visible in 4688/Sysmon 1 with image, parent, signer/hash and command line when enabled. Argument names are useful enrichment but are easy to change or omit through in-process execution.
- **Medium confidence:** .NET runtime/assembly-load telemetry can reveal an unusual managed assembly even when executed in-memory. Capture CLR assembly/module loads, image provenance and calling process; exact provider availability depends on the EDR.
- **False positives:** legitimate red-team validation, malware-analysis sandboxes and custom programs embedding the library. Do not alert solely on CLR use or slash-style arguments.

## 2. ASN.1 and Kerberos object model

### Source facts

- Rubeus includes its own ASN.1 encoder/decoder (`AsnElt`) and many message classes for AS-REQ/REP, TGS-REQ/REP, KRB-CRED, AP-REQ, KRB-ERROR, encrypted reply parts, PAC buffers and PKINIT structures ([`AsnElt.cs` lines 1–53](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Asn1/AsnElt.cs#L1-L53), [`AS_REQ.cs` lines 1–45](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/AS_REQ.cs#L1-L45), [`TGS_REQ.cs` lines 1–48](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/TGS_REQ.cs#L1-L48)).
- Constructors assemble pre-authentication data, request bodies, ticket flags, encryption-type lists and optional S4U/PKINIT data; reply classes decode application tags and nested fields ([`PA_DATA.cs` lines 94–157](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/PA_DATA.cs#L94-L157), [`AS_REP.cs` lines 15–71](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/AS_REP.cs#L15-L71)).

### Defensive inference and detections

- **High confidence at the DC:** parse 4768/4769 ticket options, advertised/requested and selected encryption types, client address, service, result/failure code and pre-authentication type. Baseline per account, host and service.
- **Medium confidence on network:** full Kerberos decoders can inspect message types, PA-DATA, option flags and request cardinality where traffic is visible; KKDCP hides inner details from ordinary TLS sensors.
- **Low confidence alone:** ASN.1 object allocation and managed byte-array transformations are memory/EDR research signals, not standard Windows events.

## 3. KDC discovery, TCP transport and KKDCP

### Source facts

- `GetDCName` calls `DsGetDcName` with directory-service, DNS-name and IP requirements, removes the leading UNC marker, resolves the DC and returns its address ([`Networking.cs` lines 18–96](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Networking.cs#L18-L96)).
- Raw Kerberos transport uses `TcpClient`, connects to port 88, prepends the four-byte TCP record length, writes the request and reads the framed response ([`Networking.cs` lines 116–160](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Networking.cs#L116-L160)).
- The KDC proxy path creates an `HttpWebRequest`, sets `application/kerberos`, serializes a `KDC_PROXY_MESSAGE`, and parses the proxy response ([`Networking.cs` lines 564–612](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Networking.cs#L564-L612)).

### Defensive inference and detections

- **High confidence:** Sysmon 3/EDR network events showing an unusual managed process connecting directly to DC TCP/88, especially without normal LSASS mediation. Correlate process start → DNS/DC discovery → TCP/88 → 4768/4769.
- **High confidence for proxy use:** proxy/WAF logs for `application/kerberos` POSTs to an uncommon endpoint, joined to client process and identity sign-in activity.
- **False positives:** Java/Linux Kerberos clients, domain utilities and legitimate KKDCP clients. Process identity and source-host baseline matter more than TCP/88 alone.

## 4. LSA handles, cache enumeration, extraction, submission and purge

### Source facts

- Elevated collection registers/connects as a logon process and enumerates logon sessions; non-elevated collection uses `LsaConnectUntrusted`. It queries the Kerberos package with `KerbQueryTicketCacheMessage` and retrieves encoded tickets with `KerbRetrieveEncodedTicketMessage` ([`LSA.cs` lines 190–230](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L190-L230), [lines 300–343](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L300-L343)).
- Ticket submission builds a `KERB_SUBMIT_TKT_REQUEST`, sets `KerbSubmitTicketMessage`, optionally targets another LUID, and calls `LsaCallAuthenticationPackage` ([`LSA.cs` lines 1026–1096](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L1026-L1096)).
- Purge similarly uses `KerbPurgeTicketCacheMessage`; another LUID requires high integrity ([`LSA.cs` lines 1108–1174](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L1108-L1174)).
- Harvest/monitor paths repeatedly enumerate caches and can write ticket material into an HKLM registry location ([`LSA.cs` lines 870–921](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L870-L921)).

### Defensive inference and detections

- **High confidence with advanced EDR:** calls to `LsaRegisterLogonProcess`, `LsaEnumerateLogonSessions`, `LsaCallAuthenticationPackage` with Kerberos query/retrieve/submit/purge message values from a nonstandard process. Standard Security logs do not reliably expose these calls.
- **Medium confidence:** a process accessing LSASS/token state (Sysmon 10 or vendor telemetry), immediately followed by service authentication under a different or newly active LUID.
- **High confidence artifact:** registry writes containing ticket blobs under a newly created HKLM path, or `.kirbi`/KRB-CRED file creation by the process. Hash/contents should be handled as sensitive evidence.
- **False positives:** `klist`, Windows authentication components, SSO/identity software and IR tooling. Caller signer, process ancestry, LUID target and message sequence are essential.

## 5. Net-only process and logon-session manipulation

### Source facts

- `CreateProcessNetOnly` calls `CreateProcessWithLogonW` with `LOGON_NETCREDENTIALS_ONLY` and `CREATE_SUSPENDED`, creating a Logon Type 9 process ([`Helpers.cs` lines 241–279](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Helpers.cs#L241-L279)).
- It opens the child token, derives its LUID, can duplicate/impersonate that token, apply a ticket to the target LUID, then resumes the thread ([`Helpers.cs` lines 280–344](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Helpers.cs#L280-L344)).
- A separate `GetSystem` helper opens a SYSTEM process token, duplicates it and calls `ImpersonateLoggedOnUser` ([`Helpers.cs` lines 150–198](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Helpers.cs#L150-L198)).

### Defensive inference and detections

- **High confidence:** 4624 Logon Type 9 plus 4688/Sysmon 1 for a suspended/new child, followed quickly by ticket-cache submission and network authentication. Microsoft confirms Type 9 clones local identity while changing outbound credentials.
- **Medium/high confidence EDR:** `CreateProcessWithLogonW` → `OpenProcessToken`/`DuplicateToken` → `ImpersonateLoggedOnUser` → LSA submit → `ResumeThread` from the same process.
- **False positives:** `runas /netonly`, administrators and credential-isolation/SSO tools. Require the full chain and unusual parent/caller rather than Type 9 alone.

## 6. Crypto and key derivation

### Source facts

- `Crypto.KerberosPasswordHash` supports RC4, AES128, AES256 and DES derivation, with AES using PBKDF2-style iteration/salt logic and Kerberos-specific derivation ([`Crypto.cs` lines 9–84](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Crypto.cs#L9-L84)).
- Encryption/decryption and checksums branch by Kerberos etype and use native/managed implementations ([`Crypto.cs` lines 86–183](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Crypto.cs#L86-L183)).

### Defensive inference and detections

- **Low confidence:** PBKDF2/AES/HMAC/MD4-like computation in a .NET process is common. Memory inspection or API tracing may identify high-volume derivation, but it is not suitable alone.
- **Higher confidence:** join crypto-heavy execution to LDAP account enumeration, KDC failures/successes, ticket construction, and sensitive stdout/file output.
- **Data-handling risk:** source paths can print derived keys or passwords to console in some actions. Capture/transcript systems may inadvertently retain secrets; restrict access and redact investigations.

## 7. LDAP and domain queries actually present

### Source facts

- `GetLdapSearchRoot` builds LDAP/LDAPS `DirectoryEntry` paths from domain, OU and DC inputs, optionally with alternate credentials ([`Networking.cs` lines 168–307](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Networking.cs#L168-L307)).
- `GetDomainSearcher` wraps `DirectorySearcher`, sets the filter and requested properties, and supports paging/results ([`Networking.cs` lines 340–431](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Networking.cs#L340-L431)).
- Roast filters query **user** objects and categories including `servicePrincipalName`, `samAccountName`, `distinguishedName`, `pwdLastSet`, `userAccountControl`, `msDS-SupportedEncryptionTypes`, delegation/account-control flags and optional caller filters ([`Roast.cs` lines 395–548](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L395-L548)).
- Brute/pre-auth paths also use `DirectorySearcher` for user candidates ([`Brute.cs` lines 232–263](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Commands/Brute.cs#L232-L263)).
- Ticket forging may query configuration/claims and account attributes needed to populate ticket/PAC data ([`ForgeTicket.cs` lines 378–473](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L378-L473)).
- **No trust enumeration:** the forest-root call selects a configuration naming context; it does not enumerate `trustedDomain` objects ([`ForgeTicket.cs` lines 434–448](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L434-L448)).

### Defensive inference and detections

- **High confidence:** LDAP query telemetry showing a workstation process searching many user objects for SPNs, pre-auth/account-control states, encryption support and password-age attributes, followed by KDC requests.
- **Medium confidence:** broad configuration/claims queries followed by local ticket forging; legitimate IAM and inventory tools can request the same attributes.
- **False positives:** AD administration, IAM governance, vulnerability assessment and sanctioned BloodHound/Rubeus tests. Baseline service accounts, source hosts, filter breadth and timing.

## 8. AS-REQ/TGT, PKINIT and certificate paths

### Source facts

- `Ask.TGT` constructs AS-REQs from password-derived/supplied keys or PKINIT certificate material and handles KDC replies/errors ([`Ask.cs` lines 37–57](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L37-L57), [lines 223–275](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L223-L275)).
- PKINIT creates `PA_PK_AS_REQ` around a signed `KrbAuthPack`, an X.509 certificate and Diffie-Hellman agreement ([`Ask.cs` lines 354–410](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L354-L410), [`PA_PK_AS_REQ.cs` lines 7–44](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/PA_PK_AS_REQ.cs#L7-L44)).
- Certificate inputs can be loaded from file/base64 or certificate stores by thumbprint, then used for PKINIT ([`Asktgt.cs` lines 73–152](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Commands/Asktgt.cs#L73-L152)).

### Defensive inference and detections

- **High confidence DC:** 4768 with certificate fields/pre-authentication type, client address and account/device context; detect certificate use by an identity or source that normally uses password/Windows Hello flows.
- **High confidence endpoint:** certificate/private-key file or store access followed by TCP/88/KKDCP and a new TGT/session. EDR may expose CryptoAPI/CNG or private-key handle use.
- **False positives:** smart cards, Windows Hello for Business, ADFS/identity infrastructure and legitimate certificate authentication. Certificate authentication is not inherently suspicious.

## 9. Roasting

### AS-REP roasting — T1558.004

**Fact:** Rubeus either accepts a named account or uses LDAP to find accounts without required pre-authentication, builds an AS-REQ without normal pre-auth data, parses the AS-REP encrypted part and can append formatted output to a file ([`Roast.cs` lines 16–101](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L16-L101), [lines 101–266](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L101-L266)).

**Detection:** 4768 requests for no-pre-auth accounts from a novel source, especially across multiple accounts; LDAP account-control discovery immediately before the requests; output-file creation. Do not require 4771—Microsoft states it is not generated for accounts configured without pre-authentication.

### Kerberoasting — T1558.003

**Fact:** Rubeus identifies SPN-bearing user accounts via LDAP, then obtains a service ticket using either `KerberosRequestorSecurityToken.GetRequest` or a raw TGT-backed TGS request and extracts/formats the encrypted ticket portion ([`Roast.cs` lines 299–395](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L299-L395), [lines 705–843](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L705-L843)). The source includes delay/jitter and encryption-selection branches.

**Detection:** 4769 service-ticket cardinality, unusual SPN/account/source combinations, requested/selected etype deviation, LDAP SPN discovery and local output artifacts. RC4 alone is not malicious; Microsoft documents legitimate legacy RC4 conditions.

## 10. TGS requests, renewal and S4U/delegation

### Source facts

- `Ask.TGS` builds a TGS-REQ from a supplied TGT and session key, sends it to a DC/proxy and handles TGS-REP/KRB-ERROR responses ([`Ask.cs` lines 485–579](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L485-L579)).
- Renewal submits a TGS request for the renewal service and can loop until renewal limits ([`Renew.cs` lines 13–110](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Renew.cs#L13-L110)).
- S4U performs S4U2Self then S4U2Proxy, carrying `PA-FOR-USER`, evidence tickets and PAC options; cross-domain variants use operator-supplied target domain/DC and referral exchanges ([`S4U.cs` lines 90–192](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/S4U.cs#L90-L192), [lines 440–524](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/S4U.cs#L440-L524), [lines 628–671](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/S4U.cs#L628-L671)).
- The delegation helper uses SSPI (`AcquireCredentialsHandle`/`InitializeSecurityContext`) to request a delegated GSS-API context and extracts the delegated ticket from the output ([`LSA.cs` lines 1280–1519](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L1280-L1519)).

### Defensive inference and detections

- **High confidence DC:** 4769 sequences for S4U2Self and S4U2Proxy, transited services, requester/service identity, ticket options and target SPN that deviate from the service account's normal delegation graph.
- **Medium confidence:** repeated renewal events (4770 where collected) or unusual long-running process-to-KDC pattern.
- **Medium/high EDR:** SSPI delegation calls and LSA retrieval from a nonstandard process, followed by service-ticket submission.
- **False positives:** constrained delegation, protocol-transition services, web front ends and identity gateways. Model allowed service-account → target-SPN edges rather than blocking S4U globally.

## 11. Ticket forging and mutation

### Source facts

- `ForgeTicket` builds `EncTicketPart`, PAC buffers, validation/group/SID data, checksums and encrypted ticket/KRB-CRED output for golden and silver ticket families ([`ForgeTicket.cs` lines 17–116](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L17-L116), [lines 565–742](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L565-L742)).
- Diamond-ticket flow first acquires a legitimate TGT, decrypts/modifies PAC/ticket data and re-signs it ([`ForgeTicket.cs` lines 1230–1244](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L1230-L1244), [`Diamond.cs` lines 135–194](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Commands/Diamond.cs#L135-L194)).
- `tgssub` mutates ticket service names and re-encodes the KRB-CRED without contacting a KDC ([`LSA.cs` lines 1525–1577](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L1525-L1577)).

### Defensive inference and detections

- **Golden:** privileged TGT/service use with ticket lifetime, account/domain/SID/PAC or encryption characteristics inconsistent with policy; TGT may have no corresponding 4768.
- **Silver/service mutation:** service logon with no matching 4769 on a DC, or service name/PAC properties inconsistent with normal issuance. Account for DC log gaps and ticket caching before alerting.
- **Diamond:** a legitimate 4768 may exist, so absence-of-KDC logic is insufficient; correlate PAC/account anomalies, unusual source process, ticket-cache submission and privileged service access.
- **False positives:** ticket caches, DC audit loss, cross-realm referrals and long-lived services can break naive event joins. Treat “no matching request” as a scored feature, not proof.

## 12. Output, file, registry and memory artifacts

### Source facts

- `consoleoutfile` redirects console output to a caller-selected file ([`Program.cs` lines 15–34](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Program.cs#L15-L34)).
- `Helpers.WriteBytesToFile` writes byte arrays directly, and action families also append text outputs ([`Helpers.cs` lines 448–466](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Helpers.cs#L448-L466), [`Roast.cs` lines 255–266](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L255-L266)).
- Ticket data is commonly represented as KRB-CRED bytes/Base64 and may be printed to stdout, written to a file, submitted directly to LSA, or stored temporarily in registry by harvesting paths ([`LSA.cs` lines 511–591](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L511-L591), [lines 870–921](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/LSA.cs#L870-L921)).

### Defensive inference and detections

- Sysmon 11/EDR for ticket-like binary files, console captures and roast output created by an unusual managed process; registry-set telemetry for large encoded values in a novel HKLM path.
- Memory scanners may identify Kerberos ASN.1/KRB-CRED structures or command strings, but strings and YARA signatures are version/build sensitive.
- Treat stdout, transcripts, crash dumps and EDR captures as credential-sensitive. Preserve only what investigation policy permits.

## 13. ETW, AMSI and evasion-relevant behavior

### Direct source facts

- A full pinned-source search found **no AMSI patch, ETW patch, `EventWrite` suppression, process hollowing, remote-thread injection or unmanaged shellcode loader** in this commit.
- The project is a normal .NET executable and therefore may be observable through CLR providers and endpoint scanning. The source includes optional “opsec” branches that alter Kerberos request construction/selection and explicit delay/jitter in roasting ([`Roast.cs` lines 328–339](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Roast.cs#L328-L339), [`Ask.cs` lines 485–579](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/Ask.cs#L485-L579)).
- In-process entry points make it possible for another host process to invoke the library without a conventional `Rubeus.exe` command line ([`Program.cs` lines 7–40](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Program.cs#L7-L40)). That is an invocation property, not a built-in injection mechanism.

### Defensive inference

- Do not rely on PowerShell Script Block Logging or AMSI alone; Rubeus is C# and can be loaded by another managed host.
- CLR assembly-load telemetry, in-memory module metadata, network-to-DC behavior and LSA API calls are more durable than filename/hash/command line.
- Jitter weakens fixed-rate thresholds. Use longer windows, distinct-SPN/account cardinality and LDAP→KDC sequences.
- **False-positive caution:** “opsec” is a source option name, not a detectable event and not proof of malicious intent.

## Detection matrix

| Behavior | Strongest correlated signal | Confidence | Main false positives |
|---|---|---:|---|
| Raw AS/TGS | Unusual process → DC TCP/88 + 4768/4769 with matching client | High | Kerberos utilities, non-Windows clients |
| KKDCP | `application/kerberos` HTTP(S) + KDC request identity context | High | Legitimate KDC proxy clients |
| Ticket cache dump | Nonstandard LSA query/retrieve API chain + ticket artifact | High with EDR | `klist`, SSO, IR tools |
| Ticket submission | `KerbSubmitTicketMessage` + new LUID/service access | High with EDR | SSO/identity components |
| Cache purge | `KerbPurgeTicketCacheMessage` from unusual caller | High with EDR | `klist purge`, support workflows |
| Net-only process | 4624 Type 9 + new suspended child + LSA submit | High | `runas /netonly`, admin workflows |
| AS-REP roast | LDAP pre-auth-state discovery + multi-account 4768/no-pre-auth | High | Account/configuration audits |
| Kerberoast | LDAP SPN discovery + 4769 cardinality/etype anomaly | High | Service inventory, monitoring |
| S4U | Abnormal service-account S4U2Self→S4U2Proxy target edge | Medium-high | Legitimate constrained delegation |
| Forged golden ticket | Privileged service use/PAC anomaly without credible 4768 | Medium-high | Missing DC logs, cached tickets |
| Forged silver/tgssub | Service use with no credible 4769 and service/PAC mismatch | Medium | Missing DC logs, referrals |
| PKINIT | Novel certificate/private-key access + certificate 4768 | High | Smart card/WHfB/identity systems |
| File/registry output | Ticket/roast artifact written by unusual managed process | Medium-high | Labs, IR and authorized tests |

## ATT&CK cross-check

- [MITRE S1071](https://attack.mitre.org/software/S1071/) directly maps Rubeus to **T1558.001 Golden Ticket**, **T1558.002 Silver Ticket**, **T1558.003 Kerberoasting** and **T1558.004 AS-REP Roasting**.
- Pass-the-ticket behavior is defensibly **[T1550.003](https://attack.mitre.org/techniques/T1550/003/)** because the source submits existing ticket material to an LSA logon session.
- Ticket cache enumeration/extraction, S4U workflow automation, renewal, KDC proxy transport, ticket description/conversion and ticket service-name substitution do not each have a clean dedicated sub-technique; preserve them as procedure metadata.
- **T1482 Domain Trust Discovery is not mapped here.** MITRE's S1071 citations are incident reports in which other utilities perform trust discovery; current Rubeus source contains no trust enumeration command/filter/API.

## Limitations

- The audit is pinned to one commit; later upstream changes require a new diff-based review.
- GitHub line anchors are stable for the pinned commit, but some behavior spans helper and structure files beyond the cited core range.
- Standard Windows logs do not expose all LSA/SSPI/CryptoAPI calls. Several strongest signals require EDR user-mode/API, kernel, CLR or memory telemetry whose schemas vary by vendor.
- DC Security events depend on audit policy, OS version and log integrity. Absence of 4768/4769 is not proof of ticket forgery.
- LDAP visibility is product-dependent; encrypted LDAPS limits network inspection unless directory-side query telemetry exists.
- This is static analysis. No binary was built or executed, so runtime-only behavior, compiler transformations and third-party loader effects were not measured.
- Exact detections must be baselined against legitimate Kerberos clients, delegation services, identity software and authorized security testing.

## Comprehensive command-to-procedure reconciliation

The pinned dispatcher registers a finite command surface in [`CommandCollection.cs` lines 18–49](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/Domain/CommandCollection.cs#L18-L49). The following reconciliation accounts for every registered command and the `spray` alias. Supporting ASN.1, NDR, PAC, crypto and networking classes are implementation dependencies of these procedures rather than independently triggerable capabilities.

| Procedure | Registered commands/variants | Primary observable behavior | Telemetry disposition |
|---|---|---|---|
| PROC-001 AS/TGT acquisition and authentication probing | `asktgt`, `brute`, `spray`, `preauthscan` | Direct AS exchanges, repeated principals, pre-auth results, optional PKINIT | Detected through 4768/client-network correlation; single normal-looking request remains attribution-limited |
| PROC-002 TGS acquisition and renewal | `asktgs`, `renew` | TGS/renewal traffic and ticket lifecycle | Detected through 4769/4770 plus client context |
| PROC-003 AS-REP roasting | `asreproast` | LDAP discovery and no-preauthentication AS requests | Detected through LDAP plus 4768 sequence |
| PROC-004 Kerberoasting | `kerberoast` | SPN discovery and service-ticket request fan-out | Detected through LDAP plus 4769 sequence |
| PROC-005 S4U and delegation workflows | `s4u`, `tgtdeleg` | S4U2Self/S4U2Proxy and delegation-related ticket requests | Detected through service-account ticket sequences; exact S4U semantics require DC/parser support |
| PROC-006 Ticket cache/session discovery and extraction | `currentluid`, `logonsession`, `klist`, `triage`, `dump`, `monitor`, `harvest` | LSA logon-session and Kerberos cache query/retrieve calls | Detected with EDR/API telemetry; standard Windows logs alone are not observable |
| PROC-007 Ticket submission, purge and isolated net-only session | `ptt`, `purge`, `createnetonly` | LSA submit/purge calls and Type 9 logon/process creation | Detected through EDR API plus 4624/process correlation |
| PROC-008 Ticket forging | `golden`, `silver`, `diamond` | Offline ticket/PAC construction and later anomalous use | Construction is not directly observable; detected through artifact creation and service-use/DC-ticket inconsistencies |
| PROC-009 Ticket mutation | `tgssub` | Offline service-name mutation and later use | Mutation is not directly observable; detected through use/PAC/service inconsistency and absent credible 4769 |
| PROC-010 Ticket parsing and conversion | `describe`, `kirbi`, `asrep2kirbi` | Local read/parse/encode/write of ticket material | Only file/process/EDR content-access telemetry; no unique standard-log signal |
| PROC-011 Key derivation | `hash` | Local password-to-Kerberos-key derivation | Not uniquely observable without content-sensitive EDR; process/file context is compensating telemetry |
| PROC-012 Password change | `changepw` | Kerberos password-change exchange | Detected through account-management and Kerberos password-change telemetry, correlated to client process/network context |
| PROC-013 Alternate KDC transport and output artifacts | Cross-cutting `/proxyurl`, `/outfile`, `/consoleoutfile` and ticket/roast output | KKDCP HTTP content type and local ticket/hash artifacts | Detected through HTTP proxy/process and file-creation telemetry |

Completeness statement: all 29 dispatcher entries (28 distinct command names plus the `spray` alias) at commit `74215f68ea70bd6a66c008da91bf5fe21d20b154` are mapped above. All source directories were inspected as command implementations or dependencies. Generated project metadata and assembly properties contain no additional operator-triggerable procedure. No source path was excluded for safety, and the source was not built or executed.
