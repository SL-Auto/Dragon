---
title: ROADtools comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# ROADtools comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `792708365789be4e6f58db65c3f90701159fd0ea` (committed 2026-11-20) from <https://github.com/dirkjanm/ROADtools>, accessed 2026-11-21.
- **Handling:** shallow source clone to `sources/roadtools-src/` (gitignored), not built or run; no binaries present.
- **Eligibility:** `roadtx` and `roadrecon` run either on operator infrastructure with stolen credentials, tokens or device keys, or on a compromised Windows endpoint (`browsercore`, `winhello_assertion`). Their effects are recorded in the victim tenant (Entra sign-in and audit logs, Microsoft Graph activity logs, ADFS and on-premises Kerberos) and on endpoints.
- **Excluded:**
  - `roadoidc`: an attacker-hosted OIDC issuer for federated credentials. It is attacker infrastructure; its victim-side effect is the federated service-principal sign-in in RT-P07.
  - `roadrecon` plugins, GUI and export (`plugins/`, `server.py`, `dist_gui`): offline analysis of a local database.
  - `roadtx decrypt`, `describe`, `listaliases`, `getotp`, `decryptadfskey`: local cryptographic or display operations with no victim-side effect at the time they run.

## Completeness inventory

Every subcommand registered in `roadtx/roadtools/roadtx/main.py` (40) and `roadrecon/roadtools/roadrecon/main.py` (8), the `roadlib` authentication library (`auth.py`, `asyncauth.py`, `deviceauth.py`, `asyncdeviceauth.py`, `webauthn.py`) and the endpoint helpers were mapped.

| Procedure | Subcommands and code |
| --- | --- |
| RT-P01 | `gettokens` (password ROPC, device code, refresh token, client credentials), `codeauth`, `clicodeauth`, `interactiveauth`, `keepassauth`, `owalogin`, `sharepointlogin` |
| RT-P02 | `refreshtokento`, `getscope`, `findscope` (family-of-client-IDs refresh-token exchange across client and resource pairs) |
| RT-P03 | `device`, `hybriddevice` (device registration; default name `DESKTOP-<RANDOM>`, `main.py` L103, L119), `bulkenrollmenttoken` |
| RT-P04 | `prt`, `prtauth`, `prtenrich`, `prtcookie`, `browserprtauth`, `browserprtinject`, `devicelessprt`, `deviceauth` (Primary Refresh Token acquisition and use; PRT-cookie requests with a fixed legacy user agent, `asyncauth.py` L935-937) |
| RT-P05 | `winhello`, `genhellokey`, `fidoauth`, `registerpasskey` (Windows Hello key and software passkey registration; default passkey name `roadtx`, `main.py` L1200; `deviceauth.py` L282; `webauthn.py` L414) |
| RT-P06 | `desktopsso` and autologon flows (`asyncauth.py` L713-735: `autologon.microsoftazuread-sso.com` usernamemixed and windowstransport) |
| RT-P07 | `appauth`, `appauthobo`, `federatedappauth`, `agentauth` (service-principal client credentials, on-behalf-of and federated assertions) |
| RT-P08 | `actortoken`, `impersonationtoken` (service actor and impersonation tokens) |
| RT-P09 | `samltoken` (SAML token generation from signing material) |
| RT-P10 | `graphrequest` (arbitrary Microsoft Graph requests) |
| RT-P11 | `roadrecon gather` and `gatherall` (Azure AD Graph dump via `graph.windows.net`, `api-version=1.61-internal`, `gather.py` L46, L116, L338), `iggather`, `pimgather`, `azgather`, `auth` |
| RT-P12 | `browsercore/` (fake `com.microsoft.browsercore` native-messaging host, `manifest.json` and `browsercore.py`) |
| RT-P13 | `winhello_assertion/` (PowerShell Windows Hello assertion proofs of concept) |

## Procedure analysis

| ID | Procedure | Ordered behavior and interfaces | Security effect | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| RT-P01 | Token acquisition flows | ROPC, device-code, authorization-code, refresh-token and Selenium-driven interactive flows against `login.microsoftonline.com`; default HTTP user agent unless `-ua` is given | Tokens for victim identities | Entra sign-in logs (authenticationProtocol, appId, resource, userAgent, IP) | T1078.004, T1528 | High |
| RT-P02 | FOCI refresh-token pivot | Redeems one refresh token for many first-party client and resource combinations | Expands token scope without re-authentication | Non-interactive sign-ins: many distinct appIds from one user and session in a short window | T1550.001, T1528 | High |
| RT-P03 | Device registration | Registers or hybrid-joins a device object and obtains a device certificate and transport key; bulk enrollment tokens | Persistent device identity for PRT and compliance abuse | Entra audit logs (Device Registration Service: Register device, Add device) | T1098.005 | High |
| RT-P04 | PRT acquisition and use | Requests a PRT with the device certificate, derives session keys, signs PRT cookies (`x-ms-RefreshTokenCredential`), enriches MFA claims and injects the cookie into browsers | SSO tokens with device and MFA claims | Sign-in logs with incoming token type primaryRefreshToken and device IDs; the PRT-cookie request carries a `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...)` user agent | T1550.001, T1606 | High |
| RT-P05 | Windows Hello and passkey persistence | Generates a Windows Hello key and registers it on the user (`searchableDeviceKey`), or registers a software passkey (default name `roadtx`) | Phishing-resistant credential under attacker control | Entra audit logs (security information or key registration); device registration context | T1098.005, T1556 | High |
| RT-P06 | Seamless SSO and autologon | Kerberos-based desktop SSO token and autologon usernamemixed or windowstransport endpoints | Tokens via on-premises SSO trust; password validation | Sign-in logs (Seamless SSO, autologon); Windows 4769 for `AZUREADSSOACC$` | T1550.003, T1110 | Medium |
| RT-P07 | Service-principal authentication | Client secret, certificate, federated assertion and on-behalf-of flows | Application-level access | Service-principal sign-in logs (credential type, IP, user agent) | T1078.004, T1550.001 | High |
| RT-P08 | Actor and impersonation tokens | Requests service actor tokens and builds impersonation tokens for first-party services | User impersonation in services | Issuance is largely not logged; downstream service activity only | T1550.001 | Medium |
| RT-P09 | SAML token generation | Builds and signs SAML assertions with obtained signing material | Federated sign-in as any user | Federated sign-ins without a matching IdP issuance event | T1606.002 | High |
| RT-P10 | Graph requests | Arbitrary Graph REST calls with obtained tokens | Directory and data access | `MicrosoftGraphActivityLogs` (diagnostic setting required) | T1087.004 | High |
| RT-P11 | Directory dump | Azure AD Graph batched dump of users, groups, devices, applications, service principals, roles and policies; PIM, governance and ARM gathers | Complete tenant map | Sign-ins for the Azure AD Graph resource (`00000002-0000-0000-c000-000000000000`); Graph activity and ARM read telemetry for the other gathers | T1087.004, T1069.003, T1526 | High |
| RT-P12 | BrowserCore native-host hijack | Registers a fake `com.microsoft.browsercore` native-messaging host (`BrowserCore.py`) for the Windows Accounts extension IDs, which signs PRT cookies from a stolen PRT | Browser SSO with stolen PRT | Endpoint registry (`NativeMessagingHosts\com.microsoft.browsercore`) and file creation of the manifest and script | T1550.001, T1112 | High |
| RT-P13 | Windows Hello assertion scripts | PowerShell proofs of concept requesting Hello assertions on an endpoint | Assertion generation with local keys | PowerShell script-block logging (4104), process creation | T1059.001, T1556 | Medium |

## Observed facts versus inference

- **Observed:** subcommand list, endpoints, default device and passkey names, the legacy user agent and the native-messaging manifest.
- **Inference:**
  - The default HTTP library user agent appears in sign-in logs unless overridden.
  - Thresholds are detection hypotheses.
