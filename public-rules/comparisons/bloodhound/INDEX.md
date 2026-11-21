# BloodHound public-rule comparison index

Pinned public revisions: Elastic `9d792a8f6731542935156db61eaba88bf337e819`; Chronicle `dbc9beb79597b519be086fce082214494d75b6a8`.

All 16 canonical BloodHound rules were compared at procedure-branch level. Public coverage is sparse for RPC, remote registry and endpoint collector behavior, so closest candidates are explicitly treated as compensating or different-scope evidence. Proposal blocks remain `unvalidated_proposal`. Each comparison ends in a terminal decision, listed below; adopted proposals were implemented independently in canonical YARA-L after adversarial review. Compensating rules added later are compared within the comparison whose branch they close.

| Internal rule | Procedures | Headline conclusion | Proposed change | Decision |
| --- | --- | --- | --- | --- |
| [bloodhound_collector_process_network_context](./bloodhound_collector_process_network_context.md) | BH-001 | complementary | compensating_rule | modify |
| [bloodhound_ldap_directory_discovery_fanout](./bloodhound_ldap_directory_discovery_fanout.md) | BH-002,BH-004 | complementary | compensating_rule | modify |
| [bloodhound_sensitive_directory_attribute_reads](./bloodhound_sensitive_directory_attribute_reads.md) | BH-003,BH-005 | ours_stronger | rewrite | modify |
| [bloodhound_smb_rpc_host_sweep](./bloodhound_smb_rpc_host_sweep.md) | BH-006 | ours_stronger | patch | modify |
| [bloodhound_remote_session_registry_collection](./bloodhound_remote_session_registry_collection.md) | BH-007,BH-008 | ours_stronger | rewrite | modify |
| [bloodhound_samr_local_group_enumeration](./bloodhound_samr_local_group_enumeration.md) | BH-009,BH-010 | ours_stronger | split | modify |
| [bloodhound_sysvol_policy_file_collection](./bloodhound_sysvol_policy_file_collection.md) | BH-011 | ours_stronger | patch | modify |
| [bloodhound_remote_security_configuration_reads](./bloodhound_remote_security_configuration_reads.md) | BH-012 | ours_stronger | rewrite | modify |
| [bloodhound_service_protocol_probe_fanout](./bloodhound_service_protocol_probe_fanout.md) | BH-013 | different_scope | rewrite | modify |
| [bloodhound_recurrent_collection_activity](./bloodhound_recurrent_collection_activity.md) | BH-014 | public_stronger | rewrite | reject |
| [bloodhound_collection_archive_creation](./bloodhound_collection_archive_creation.md) | BH-015 | complementary | rewrite | modify |
| [bloodhound_azure_authentication_context](./bloodhound_azure_authentication_context.md) | BH-016 | complementary | rewrite | accept |
| [bloodhound_azure_graph_enumeration_fanout](./bloodhound_azure_graph_enumeration_fanout.md) | BH-017 | complementary | compensating_rule | modify |
| [bloodhound_azure_resource_enumeration_fanout](./bloodhound_azure_resource_enumeration_fanout.md) | BH-018 | complementary | rewrite | modify |
| [bloodhound_azure_rbac_enumeration](./bloodhound_azure_rbac_enumeration.md) | BH-019 | ours_stronger | rewrite | reject |
| [bloodhound_cloud_collection_output](./bloodhound_cloud_collection_output.md) | BH-020 | public_stronger | rewrite | modify |

## Cross-rule findings

- Strong internal branches are process-attributed RPC/LDAP/network effects and ordered cloud-read-to-output correlations when the required fields exist.
- Weak branches rely on generic path regexes, host/user joins, raw cardinality, mutable process prevalence or broad common ports.
- Material gaps recur around stable entity joins, single-target deep collection, distributed and low-and-slow activity, cloud application identity, provider collection health and authoritative RPC/LDAP normalization.
- Public rules add useful AzureHound user-agent, AD-property volume, Graph endpoint and SYSVOL/compression signals, but none covers the whole collector procedure inventory.

## Review status

Threat-detection comparison complete for 16/16 BloodHound rules. Each document includes actual YARA-L 2.0 proposal code and required telemetry. Acceptance requires the separate canonical improvement workflow.
