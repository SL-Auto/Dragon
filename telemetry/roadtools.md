# ROADtools telemetry requirements

Scope: victim-tenant and endpoint records of ROADtools activity at revision `792708365789be4e6f58db65c3f90701159fd0ea`.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RT-TEL-01 | Microsoft Entra ID sign-in logs | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs` | user or service principal, IP, userAgent, appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, resultType, clientCredentialType, federated issuer | Diagnostic settings exporting all three sign-in categories | 1 hour per user; retain 30 days | Mutable user agents (RT-DR-01) | Most rules; RT-P01 to RT-P07, RT-P09, RT-P11 |
| RT-TEL-02 | Microsoft Entra ID audit logs | `Register device`, `Add device`, security-info, passkey and Windows Hello key registrations | activity, initiator, target user or device, initiating app, modifiedProperties | Export AuditLogs | 1 hour per user | Enrollment overlap (RT-DR-04) | device and key rules; RT-P03, RT-P05 |
| RT-TEL-03 | Microsoft Graph activity logs | `MicrosoftGraphActivityLogs` | user or service principal, request URI, user agent | Enable the Graph activity log diagnostic setting | 10 minutes per identity | Azure AD Graph calls are not in this log | `roadtools_graph_directory_bulk_read`, scripting user agent; RT-P10, RT-P11 |
| RT-TEL-08 | Azure AD Graph activity logs | `AADGraphActivityLogs` | caller, api-version, request URI, user agent | Enable the AADGraphActivityLogs diagnostic category | 1 hour per caller | New log category; not exported by default | `roadtools_aad_graph_internal_api_version`; RT-P11 |
| RT-TEL-04 | AD FS auditing | AD FS Security 1200 and 1202 (token issued) | user, relying party, time | Enable AD FS success auditing and forward it | 10 minutes per user | Non-AD FS identity providers (RT-DR-06) | `roadtools_federated_signin_without_idp_issuance`; RT-P09 |
| RT-TEL-05 | Windows domain controllers | Security 4769 | service name, account, client address | Kerberos service-ticket auditing | 10 minutes per account | Needs a sign-in sAMAccountName enrichment (RT-DR-07) | Seamless SSO rule; RT-P06 |
| RT-TEL-06 | Endpoint registry and file | Sysmon Event ID 13 / `REGISTRY_MODIFICATION`; Sysmon Event ID 11 / `FILE_CREATION` | key, value data, file path, host, process | Monitor `NativeMessagingHosts` keys in HKCU and HKLM | 1 hour per host | none | `roadtools_browsercore_native_host_hijack`; RT-P12 |
| RT-TEL-07 | PowerShell | Script-block logging 4104 | ScriptBlockText, host, user | Enable script-block logging | 1 hour per host | Obfuscation | `roadtools_hello_assertion_script`; RT-P13 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `roadtools_device_code_or_ropc_signin` | RT-P01 | RT-TEL-01 | Sign-ins with authenticationProtocol and resultType | approved app list | Protocol field not exported |
| `roadtools_foci_refresh_token_client_hopping` | RT-P02 | RT-TEL-01 | Non-interactive sign-ins with incomingTokenType and appId | none | Non-interactive logs not exported |
| `roadtools_scripting_user_agent_signin` | RT-P01, P04, P06, P07, P10, P11 | RT-TEL-01, 03 | User agent on sign-ins and Graph requests | automation allowlist | Overridden user agent (RT-DR-01) |
| `roadtools_prt_cookie_legacy_user_agent` | RT-P04 | RT-TEL-01 | User agent on sign-ins | none | Overridden user agent |
| `roadtools_device_registration_then_prt_signin` | RT-P03, P04 | RT-TEL-01, 02 | Device registration audit and PRT sign-ins | device inventory | incomingTokenType not exported |
| `roadtools_registered_device_default_name` | RT-P03 | RT-TEL-02 | Device registration with display name and initiating app | none | Custom device name |
| `roadtools_passkey_default_name_registration` | RT-P05 | RT-TEL-02 | Key-registration audit with modifiedProperties | none | Custom passkey name |
| `roadtools_device_registration_then_hello_key` | RT-P03, P05 | RT-TEL-02 | Device and key audit events for one user | device inventory | Enrollment overlap (RT-DR-04) |
| `roadtools_aad_graph_resource_token` | RT-P11 | RT-TEL-01 | Sign-ins with resourceId | legacy-app list | none |
| `roadtools_graph_directory_bulk_read` | RT-P10, P11 | RT-TEL-03 | Graph activity with request URI | sync-app list | Graph activity log disabled |
| `roadtools_browsercore_native_host_hijack` | RT-P12 | RT-TEL-06 | Registry and file events | none | NativeMessagingHosts not monitored |
| `roadtools_seamless_sso_ticket_from_unusual_process` | RT-P06 | RT-TEL-01, 05 | 4769 and sign-ins with account enrichment | onPremSamAccountName | Enrichment missing (RT-DR-07) |
| `roadtools_federated_credential_sp_signin` | RT-P07 | RT-TEL-01 | Service-principal sign-ins with credential type and issuer | approved issuers | Issuer field not exported |
| `roadtools_federated_signin_without_idp_issuance` | RT-P09 | RT-TEL-01, 04 | Federated sign-ins and AD FS 1200/1202 | none | Incomplete AD FS audit (RT-DR-06) |
| `roadtools_aad_graph_internal_api_version` | RT-P11 | RT-TEL-08 | Azure AD Graph activity with api-version | none | Log category not exported |
| `roadtools_broker_client_device_code_signin` | RT-P01, P03, P04 | RT-TEL-01 | Sign-ins with authenticationProtocol and appId | none | Fields not exported |
| `roadtools_hello_assertion_script` | RT-P13 | RT-TEL-07 | 4104 script blocks | none | Script-block logging disabled |

## Deployment order

1. Export all sign-in and audit categories (RT-TEL-01, RT-TEL-02).
2. Enable Graph activity logs (RT-TEL-03) and the endpoint registry monitoring (RT-TEL-06).
3. Enable AD FS auditing and the Kerberos account enrichment.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] Sign-in and audit field normalization was verified.
- [ ] AD FS audit coverage was confirmed.

## Unresolved telemetry gaps

- Actor-token issuance (RT-P08) is not logged; compensating signals are named in `reviews/roadtools/detection-review.md`.
