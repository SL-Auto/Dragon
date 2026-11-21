# ROADtools procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: roadtools
- Revision: 792708365789be4e6f58db65c3f90701159fd0ea
- Lifecycle: analyzed
- Full evidence: reports/roadtools/source-analysis.md
- Coverage ledger: coverage/roadtools.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| RT-P01 | token acquisition flows | assessed | detected | roadtools_device_code_or_ropc_signin, roadtools_scripting_user_agent_signin, roadtools_broker_client_device_code_signin |
| RT-P02 | FOCI refresh-token pivot | assessed | detected | roadtools_foci_refresh_token_client_hopping |
| RT-P03 | device registration | assessed | detected | roadtools_device_registration_then_prt_signin, roadtools_device_registration_then_hello_key, roadtools_registered_device_default_name |
| RT-P04 | PRT acquisition and use | assessed | detected | roadtools_device_registration_then_prt_signin, roadtools_prt_cookie_legacy_user_agent, roadtools_scripting_user_agent_signin, roadtools_broker_client_device_code_signin |
| RT-P05 | Windows Hello and passkey persistence | assessed | detected | roadtools_passkey_default_name_registration, roadtools_device_registration_then_hello_key |
| RT-P06 | Seamless SSO and autologon | assessed | detected | roadtools_seamless_sso_ticket_from_unusual_process, roadtools_scripting_user_agent_signin |
| RT-P07 | service-principal authentication | assessed | detected | roadtools_federated_credential_sp_signin, roadtools_scripting_user_agent_signin |
| RT-P08 | actor and impersonation tokens | not_observable | not_observable |  |
| RT-P09 | SAML token generation | assessed | detected | roadtools_federated_signin_without_idp_issuance |
| RT-P10 | Graph requests | assessed | detected | roadtools_graph_directory_bulk_read, roadtools_scripting_user_agent_signin |
| RT-P11 | directory dump | assessed | detected | roadtools_aad_graph_resource_token, roadtools_graph_directory_bulk_read, roadtools_scripting_user_agent_signin, roadtools_aad_graph_internal_api_version |
| RT-P12 | BrowserCore native-host hijack | assessed | detected | roadtools_browsercore_native_host_hijack |
| RT-P13 | Windows Hello assertion scripts | assessed | detected | roadtools_hello_assertion_script |
