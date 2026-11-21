# BloodHound collectors procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: bloodhound
- Revision: bloodhound-v9.5.1_sharphound-a2f8435_common-fcb6cb9_azurehound-23735c8
- Lifecycle: analyzed
- Full evidence: reports/bloodhound/source-analysis.md
- Coverage ledger: coverage/bloodhound.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| BH-001 | collector initialization configuration and targeting | assessed | detected | bloodhound_collector_process_network_context, bloodhound_process_to_directory_effect |
| BH-002 | LDAP directory object and property enumeration | assessed | detected | bloodhound_ldap_directory_discovery_fanout, bloodhound_ldap_deep_single_category_enumeration |
| BH-003 | directory ACL and security descriptor collection | assessed | detected | bloodhound_sensitive_directory_attribute_reads |
| BH-004 | group trust container GPO and SPN topology collection | assessed | detected | bloodhound_ldap_directory_discovery_fanout, bloodhound_ldap_deep_single_category_enumeration |
| BH-005 | AD certificate services object collection | assessed | detected | bloodhound_sensitive_directory_attribute_reads |
| BH-006 | DNS resolution and SMB reachability discovery | assessed | detected | bloodhound_smb_rpc_host_sweep |
| BH-007 | remote session enumeration | assessed | detected | bloodhound_remote_session_registry_collection |
| BH-008 | remote logged-on user registry collection | assessed | detected | bloodhound_remote_session_registry_collection |
| BH-009 | SAMR local group and remote access rights enumeration | assessed | detected | bloodhound_samr_local_group_enumeration, bloodhound_samr_alias_membership_fanout |
| BH-010 | local user-rights assignment collection | assessed | detected | bloodhound_samr_local_group_enumeration |
| BH-011 | SYSVOL GPO local-group policy collection | assessed | detected | bloodhound_sysvol_policy_file_collection |
| BH-012 | CA DC and NTLM remote-registry security configuration collection | assessed | detected | bloodhound_remote_security_configuration_reads, bloodhound_remote_security_configuration_value_reads |
| BH-013 | WebClient LDAP and SMB service capability probing | assessed | detected | bloodhound_service_protocol_probe_fanout |
| BH-014 | looped and throttled host collection | assessed | detected | bloodhound_recurrent_collection_activity |
| BH-015 | cache JSON CSV metrics and ZIP artifact output | assessed | detected | bloodhound_collection_archive_creation |
| BH-016 | AzureHound configuration authentication and token acquisition | assessed | detected | bloodhound_azure_authentication_context |
| BH-017 | Microsoft Graph Entra directory enumeration | assessed | detected | bloodhound_azure_graph_enumeration_fanout, bloodhound_graph_deep_relationship_enumeration |
| BH-018 | Azure Resource Manager hierarchy and resource enumeration | assessed | detected | bloodhound_azure_resource_enumeration_fanout |
| BH-019 | Azure RBAC ownership access policy and eligibility enumeration | assessed | detected | bloodhound_azure_rbac_enumeration |
| BH-020 | AzureHound output service lifecycle and local configuration artifacts | assessed | detected | bloodhound_cloud_collection_output |
