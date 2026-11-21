# Sliver public-rule comparison index

All 14 canonical Sliver rules have threat-detection comparisons. Public rules are untrusted comparative inputs; every proposal block remains an `unvalidated_proposal`. Each comparison's decision trail records whether canonical logic was changed; current decisions are listed below.

| Internal rule | Procedures | Proposal | Decision |
| --- | --- | --- | --- |
| [`sliver_browser_debugging_from_network_process`](./sliver_browser_debugging_from_network_process.md) | `PROC-022` | rewrite | modify |
| [`sliver_cleanup_after_egress`](./sliver_cleanup_after_egress.md) | `PROC-002,PROC-026` | rewrite | modify |
| [`sliver_dns_or_udp_process_egress`](./sliver_dns_or_udp_process_egress.md) | `PROC-004` | compensating_rule | modify |
| [`sliver_file_activity_from_network_process`](./sliver_file_activity_from_network_process.md) | `PROC-007,PROC-008,PROC-009` | split | modify |
| [`sliver_identity_or_service_from_network_process`](./sliver_identity_or_service_from_network_process.md) | `PROC-016,PROC-017,PROC-019` | split | modify |
| [`sliver_listener_with_egress`](./sliver_listener_with_egress.md) | `PROC-005,PROC-021` | rewrite | modify |
| [`sliver_parent_egress_with_spawned_interpreter`](./sliver_parent_egress_with_spawned_interpreter.md) | `PROC-010` | rewrite | reject |
| [`sliver_process_access_from_network_process`](./sliver_process_access_from_network_process.md) | `PROC-011,PROC-012,PROC-015` | split | modify |
| [`sliver_process_behavior_cluster`](./sliver_process_behavior_cluster.md) | `PROC-001` | rewrite | modify |
| [`sliver_recurrent_process_egress`](./sliver_recurrent_process_egress.md) | `PROC-002,PROC-003` | rewrite | modify |
| [`sliver_registry_from_network_process`](./sliver_registry_from_network_process.md) | `PROC-018` | patch | modify |
| [`sliver_remote_admin_sequence`](./sliver_remote_admin_sequence.md) | `PROC-020` | rewrite | modify |
| [`sliver_screen_capture_process_egress`](./sliver_screen_capture_process_egress.md) | `PROC-014` | patch | reject |

## Portfolio findings

- Internal rules benefit from process-attributed network correlation, but many joins need sensor-issued process/session identity rather than PID, host or account alone.
- Weak recurring branches include raw connection counts, broad file/registry activity and conflated identity/service/process-access signals.
- Stronger coverage requires verified security effects, procedure-specific splits, first-seen/role context and collection-health awareness.
- Public candidates provide useful adjacent signals but do not establish complete Sliver procedures or justify blind predicate adoption.
