# Impacket public-rule comparison index

All 20 canonical Impacket YARA-L rules have procedure-branch comparisons. Public rules are untrusted comparative evidence. Every proposed code block is an `unvalidated_proposal` and no canonical rule was changed by this comparison pass.

| Internal rule | Procedures | Proposal | Decision |
| --- | --- | --- | --- |
| [`impacket_ad_authorization_change`](./impacket_ad_authorization_change.md) | `IMP-10` | patch | deferred_pending_rule_improvement_run |
| [`impacket_cross_source_ntlm_relay`](./impacket_cross_source_ntlm_relay.md) | `IMP-21` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_packet_capture_or_raw_socket`](./impacket_packet_capture_or_raw_socket.md) | `IMP-19` | compensating_rule | deferred_pending_rule_improvement_run |
| [`impacket_privilege_path_effects`](./impacket_privilege_path_effects.md) | `IMP-22` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_rapid_scheduled_task_create_and_run`](./impacket_rapid_scheduled_task_create_and_run.md) | `IMP-04` | compensating_rule | deferred_pending_rule_improvement_run |
| [`impacket_remote_account_or_group_change`](./impacket_remote_account_or_group_change.md) | `IMP-07` | patch | deferred_pending_rule_improvement_run |
| [`impacket_remote_registry_activity`](./impacket_remote_registry_activity.md) | `IMP-14` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_remote_rpc_discovery`](./impacket_remote_rpc_discovery.md) | `IMP-08,IMP-16` | compensating_rule | deferred_pending_rule_improvement_run |
| [`impacket_remote_service_binary_sequence`](./impacket_remote_service_binary_sequence.md) | `IMP-03` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_remote_wmi_activity`](./impacket_remote_wmi_activity.md) | `IMP-05` | compensating_rule | deferred_pending_rule_improvement_run |
| [`impacket_sensitive_file_or_replication_access`](./impacket_sensitive_file_or_replication_access.md) | `IMP-13` | split | deferred_pending_rule_improvement_run |
| [`impacket_sensitive_ldap_search`](./impacket_sensitive_ldap_search.md) | `IMP-09` | patch | deferred_pending_rule_improvement_run |
| [`impacket_short_lived_command_service`](./impacket_short_lived_command_service.md) | `IMP-03` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_smb_sensitive_file_activity`](./impacket_smb_sensitive_file_activity.md) | `IMP-01,IMP-13` | patch | deferred_pending_rule_improvement_run |
| [`impacket_suspicious_kerberos_requests`](./impacket_suspicious_kerberos_requests.md) | `IMP-11` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_suspicious_service_control`](./impacket_suspicious_service_control.md) | `IMP-03` | rewrite | deferred_pending_rule_improvement_run |
| [`impacket_terminal_services_control`](./impacket_terminal_services_control.md) | `IMP-18` | patch | deferred_pending_rule_improvement_run |
| [`impacket_unusual_protocol_listener`](./impacket_unusual_protocol_listener.md) | `IMP-02` | patch | deferred_pending_rule_improvement_run |
| [`impacket_unusual_service_authentication`](./impacket_unusual_service_authentication.md) | `IMP-15` | compensating_rule | deferred_pending_rule_improvement_run |
| [`impacket_wmi_subscription_change`](./impacket_wmi_subscription_change.md) | `IMP-06` | rewrite | deferred_pending_rule_improvement_run |

## Portfolio findings

- Strong internal branches include target-side service, task, WMI, directory, replication and SMB effects.
- Recurring weaknesses are host-only joins, count-only conditions, missing stable session/object identity, conflated signals, and absent result/cleanup confirmation.
- Public rules add useful adjacent signals and telemetry-specific branches but frequently have narrower procedure scope or mutable-name assumptions.
- Adoption requires source and telemetry verification plus the full canonical review and downstream regeneration workflow.
