# ROADtools public-rule comparison index

Pinned public revision: Elastic `9d792a8f6731542935156db61eaba88bf337e819`.

Five rules have meaningful public counterparts, each ending in a terminal decision. Adopted proposals were implemented independently as `roadtools_aad_graph_internal_api_version` and `roadtools_broker_client_device_code_signin`.

No closer public candidate exists for these rules, so they have no comparison:
- `roadtools_aad_graph_internal_api_version`
- `roadtools_broker_client_device_code_signin`
- `roadtools_browsercore_native_host_hijack`
- `roadtools_device_registration_then_hello_key`
- `roadtools_federated_credential_sp_signin`
- `roadtools_federated_signin_without_idp_issuance`
- `roadtools_foci_refresh_token_client_hopping`
- `roadtools_graph_directory_bulk_read`
- `roadtools_hello_assertion_script`
- `roadtools_prt_cookie_legacy_user_agent`
- `roadtools_registered_device_default_name`
- `roadtools_seamless_sso_ticket_from_unusual_process`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`roadtools_aad_graph_resource_token`](./roadtools_aad_graph_resource_token.md) | `RT-P11` | Elastic Azure AD Graph ROADrecon aiohttp enumeration | new_rule | modify |
| [`roadtools_device_code_or_ropc_signin`](./roadtools_device_code_or_ropc_signin.md) | `RT-P01` | Elastic device code with broker client; ROPC unknown client ID | new_rule | modify |
| [`roadtools_device_registration_then_prt_signin`](./roadtools_device_registration_then_prt_signin.md) | `RT-P03,RT-P04` | Elastic PRT from unusual device IP | new_rule | reject |
| [`roadtools_passkey_default_name_registration`](./roadtools_passkey_default_name_registration.md) | `RT-P05` | Elastic potential passkey downgrade | new_rule | reject |
| [`roadtools_scripting_user_agent_signin`](./roadtools_scripting_user_agent_signin.md) | `RT-P01..P11` | Elastic Azure AD Graph suspicious user agent | patch | reject |
