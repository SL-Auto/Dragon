# Impacket procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: impacket
- Revision: c23b3d55bc846a2460a459437601a94bfd25a269
- Lifecycle: analyzed
- Full evidence: reports/impacket/source-analysis.md
- Coverage ledger: coverage/impacket.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| IMP-01 | SMB file and share operations | assessed | detected | impacket_smb_sensitive_file_activity |
| IMP-02 | SMB listener | assessed | detected | impacket_unusual_protocol_listener |
| IMP-03 | service execution and control | assessed | detected | impacket_remote_service_binary_sequence, impacket_suspicious_service_control |
| IMP-04 | scheduled task execution | assessed | detected | impacket_rapid_scheduled_task_create_and_run |
| IMP-05 | WMI and DCOM execution or query | assessed | detected | impacket_remote_wmi_activity, impacket_wmi_activity_operational_class_signal |
| IMP-06 | WMI persistence | assessed | detected | impacket_wmi_subscription_change |
| IMP-07 | account and group change | assessed | detected | impacket_remote_account_or_group_change |
| IMP-08 | account and system discovery | assessed | detected | impacket_remote_rpc_discovery |
| IMP-09 | LDAP discovery | assessed | detected | impacket_sensitive_ldap_search |
| IMP-10 | AD authorization change | assessed | detected | impacket_ad_authorization_change |
| IMP-11 | Kerberos ticket request | assessed | detected | impacket_suspicious_kerberos_requests |
| IMP-12 | offline Kerberos artifacts | assessed | not_observable |  |
| IMP-13 | credential and secret retrieval | assessed | detected | impacket_sensitive_file_or_replication_access |
| IMP-14 | registry access and change | assessed | detected | impacket_remote_registry_activity |
| IMP-15 | service authentication and query | assessed | detected | impacket_unusual_service_authentication |
| IMP-16 | RPC discovery and specialized interfaces | assessed | detected | impacket_remote_rpc_discovery |
| IMP-17 | Exchange operations | assessed | blocked_source |  |
| IMP-18 | Terminal Services control | assessed | detected | impacket_terminal_services_control, impacket_terminal_services_session_control_by_other_actor |
| IMP-19 | packet construction and capture | assessed | detected | impacket_packet_capture_or_raw_socket |
| IMP-20 | local parsing and conversion | assessed | not_observable |  |
| IMP-21 | authentication relay | assessed | detected | impacket_cross_source_ntlm_relay, impacket_ntlm_relay_with_privileged_effect |
| IMP-22 | special exploit and privilege paths | assessed | detected | impacket_privilege_path_effects |
