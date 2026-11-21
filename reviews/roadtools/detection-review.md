# ROADtools adversarial detection-logic review

## Review scope

- Revision `792708365789be4e6f58db65c3f90701159fd0ea`, procedures RT-P01 to RT-P13 in `reports/roadtools/source-analysis.md`.
- Rules under `detections/roadtools/yaral/`, plus any added after public comparison (see the comparison-driven findings below).
- Method: every rule was assumed wrong until supported. Sign-in and audit field semantics, joins, absence logic and user-agent dependencies were traced against `roadlib`, `roadtx` and `roadrecon`.

## Overall assessment

The strongest signals do not depend on the tool's user agent:
- Endpoint artifacts: the BrowserCore native-host hijack.
- Persistence sequences: device registration followed by PRT use or a Hello key.
- Token-pivot breadth: FOCI client hopping.

The user-agent rules are useful defaults but operator-mutable. No blocker remains.

## Findings

### RT-DR-01 — user-agent rules are operator-mutable

- Severity: `medium`
- Rules: `roadtools_scripting_user_agent_signin`, `roadtools_prt_cookie_legacy_user_agent`
- Assumption challenged: that the default library user agent and the hard-coded legacy user agent always reach the logs.
- Gap or failure mode: `-ua` and user-agent aliases (`lookup_user_agent`) replace both.
- Resolution: `accepted_gap`. Both rules are medium severity and corroborating. The behavioral rules (FOCI hopping, device-to-PRT, device-to-key, BrowserCore) do not depend on the user agent.

### RT-DR-02 — device-code and ROPC flows have legitimate users

- Severity: `medium`
- Rule: `roadtools_device_code_or_ropc_signin`
- Gap or failure mode: TVs, conference devices, CLIs and legacy scripts use these protocols.
- Resolution: `accepted_gap`. The rule is medium severity, and triage inventories the approved appIds. Conditional Access authentication-flow policies are the preventive complement.

### RT-DR-03 — FOCI hopping overlaps Office bootstrap

- Severity: `medium`
- Rule: `roadtools_foci_refresh_token_client_hopping`
- Gap or failure mode: a new Office installation refreshes tokens for several first-party apps at first sign-in.
- Resolution: `accepted_gap` with a four-app threshold, joined on user and IP. The incoming token type must be `refreshToken` on non-interactive sign-ins.

### RT-DR-04 — the device chains overlap legitimate enrollment

- Severity: `medium`
- Rules: `roadtools_device_registration_then_prt_signin`, `roadtools_device_registration_then_hello_key`, `roadtools_registered_device_default_name`
- Gap or failure mode: new corporate devices register, obtain a PRT and provision Windows Hello within the hour.
- Resolution: `accepted_gap`. The default-name rule excludes Intune and Autopilot initiators and is low severity. The chains are medium or high and need location and device context in triage.

### RT-DR-05 — the original Hello rule matched every enrollment

- Severity: `high`
- Rule: the initial `roadtools_hello_or_passkey_registration`
- Assumption challenged: that `searchableDeviceKey` changes are rare.
- Gap or failure mode: every Windows Hello enrollment modifies `searchableDeviceKey`. The description also promised a device correlation that the logic did not implement.
- Resolution: `fixed`. The rule was split into `roadtools_passkey_default_name_registration` (the `roadtx` default name, high) and `roadtools_device_registration_then_hello_key` (registration followed by key addition, medium).

### RT-DR-06 — SAML forgery absence depends on AD FS audit completeness

- Severity: `high`
- Rule: `roadtools_federated_signin_without_idp_issuance`
- Gap or failure mode: missing AD FS auditing, multiple identity providers or clock skew create false positives. Third-party identity providers have no 1200/1202 events.
- Resolution: `accepted_gap`. The rule is medium severity and requires confirmed AD FS audit coverage (stated in its prerequisites and validation method). It does not apply to non-AD FS federation.

### RT-DR-07 — Seamless SSO correlation depends on account enrichment

- Severity: `medium`
- Rule: `roadtools_seamless_sso_ticket_from_unusual_process`
- Gap or failure mode: sign-in logs do not carry `sAMAccountName` natively, so the join needs an `onPremSamAccountName` enrichment.
- Resolution: `accepted_gap`. Prerequisites state the enrichment. Without it, the scripting user-agent rule remains as compensation.

### RT-DR-08 — actor-token issuance is not logged

- Severity: `medium`
- Procedure: RT-P08.
- Gap or failure mode: service actor-token issuance and impersonation-token use produce no tenant sign-in records.
- Resolution: `accepted_gap`. RT-P08 is `not_observable`. Compensating signals: service-principal sign-ins (`roadtools_federated_credential_sp_signin`, scripting user agent) and downstream service audit logs.

## Comparison-driven additions (2026-11-21)

### RT-DR-09 — internal Azure AD Graph API version

- Severity: `medium`
- Rule: new `roadtools_aad_graph_internal_api_version`
- Assumption challenged: that the directory dump is only visible through token issuance for the Azure AD Graph resource.
- Gap or failure mode: the token rule fires once per session and cannot separate ROADrecon from other legacy Azure AD Graph clients.
- Resolution: `compensating_signal`. The Azure AD Graph activity log records `api-version`, and ROADrecon hard-codes `1.61-internal` (`gather.py` L116, L338). The rule does not depend on the user agent. It requires the `AADGraphActivityLogs` diagnostic category.

### RT-DR-10 — device-code sign-ins to the broker client

- Severity: `medium`
- Rule: new `roadtools_broker_client_device_code_signin`
- Assumption challenged: that the generic device-code rule distinguishes PRT phishing.
- Gap or failure mode: device-code use by TVs and CLIs dilutes the generic rule. `roadlib` uses the Microsoft Authentication Broker client (`constants.py` L31-32; `deviceauth.py` L851, L991) for device registration and PRT flows.
- Resolution: `compensating_signal`. A device-code sign-in to the broker appId, at high severity.

## Not observable or excluded

- RT-P08 is not observable.
- `roadoidc`, the `roadrecon` plugins and GUI, and the local `roadtx` utilities are excluded in the report.

## Re-review of revised rules

- All 17 rules were re-traced after RT-DR-05, RT-DR-09 and RT-DR-10.
- Sequences are ordered.
- Absence logic uses `!$a` with a bounded window.
- Escaped backslashes in registry paths are literal, and exclusions fail open.
- No unresolved `blocker` remains.

## Required follow-up

- Confirm the normalization of sign-in fields (authenticationProtocol, incomingTokenType, appId, resourceId, clientCredentialType) and audit `modifiedProperties`.
- Enable Graph activity logs and AD FS auditing.
- Keep all rules experimental.
