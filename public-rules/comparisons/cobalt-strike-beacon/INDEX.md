# Cobalt Strike Beacon public-rule comparison index

Pinned revisions: Elastic `7e91c156324cdc64cda27f7fec7067b1148074ef`; Chronicle community `234e9223c3b8f3d1c30209d9663797ba69057533`; Microsoft Sentinel `5f947544657288586559c41b218eaaf182636728`.

All 21 canonical rules were compared by procedure branch and observable effect. Proposals are `unvalidated_proposal` inputs and no public logic has been adopted automatically.

| Internal rule | Procedures | Headline conclusion |
| --- | --- | --- |
| [cobalt_strike_alternate_identity_process](./cobalt_strike_alternate_identity_process.md) | CSB-012 | complementary; proposed compensating_rule |
| [cobalt_strike_credential_access_effect](./cobalt_strike_credential_access_effect.md) | CSB-028 | complementary; proposed split |
| [cobalt_strike_cross_process_injection](./cobalt_strike_cross_process_injection.md) | CSB-018,CSB-019 | complementary; proposed rewrite |
| [cobalt_strike_directory_discovery](./cobalt_strike_directory_discovery.md) | CSB-022 | complementary; proposed compensating_rule |
| [cobalt_strike_discovery_fanout](./cobalt_strike_discovery_fanout.md) | CSB-021 | complementary; proposed compensating_rule |
| [cobalt_strike_dns_process_context](./cobalt_strike_dns_process_context.md) | CSB-006 | complementary; proposed compensating_rule |
| [cobalt_strike_file_cleanup_or_timestomp](./cobalt_strike_file_cleanup_or_timestomp.md) | CSB-026,CSB-034 | complementary; proposed compensating_rule |
| [cobalt_strike_named_pipe_peer_activity](./cobalt_strike_named_pipe_peer_activity.md) | CSB-007 | complementary; proposed compensating_rule |
| [cobalt_strike_powershell_or_clr_in_unusual_host](./cobalt_strike_powershell_or_clr_in_unusual_host.md) | CSB-015,CSB-017 | complementary; proposed compensating_rule |
| [cobalt_strike_privileged_context_change](./cobalt_strike_privileged_context_change.md) | CSB-011 | complementary; proposed rewrite |
| [cobalt_strike_process_network_context](./cobalt_strike_process_network_context.md) | CSB-001,CSB-002,CSB-005 | complementary; proposed compensating_rule |
| [cobalt_strike_remote_management_execution](./cobalt_strike_remote_management_execution.md) | CSB-031,CSB-032,CSB-033 | complementary; proposed rewrite |
| [cobalt_strike_remote_service_sequence](./cobalt_strike_remote_service_sequence.md) | CSB-030 | complementary; proposed rewrite |
| [cobalt_strike_sensitive_file_activity](./cobalt_strike_sensitive_file_activity.md) | CSB-024,CSB-025 | complementary; proposed compensating_rule |
| [cobalt_strike_sensitive_registry_read](./cobalt_strike_sensitive_registry_read.md) | CSB-023 | complementary; proposed compensating_rule |
| [cobalt_strike_service_or_integrity_transition](./cobalt_strike_service_or_integrity_transition.md) | CSB-020 | complementary; proposed rewrite |
| [cobalt_strike_socket_fanout_or_forwarding](./cobalt_strike_socket_fanout_or_forwarding.md) | CSB-009 | complementary; proposed rewrite |
| [cobalt_strike_socket_listen_or_rare_egress](./cobalt_strike_socket_listen_or_rare_egress.md) | CSB-008 | complementary; proposed compensating_rule |
| [cobalt_strike_suspicious_process_lineage_or_memory](./cobalt_strike_suspicious_process_lineage_or_memory.md) | CSB-004,CSB-014,CSB-016 | complementary; proposed rewrite |
| [cobalt_strike_unusual_authentication_material_use](./cobalt_strike_unusual_authentication_material_use.md) | CSB-013 | complementary; proposed compensating_rule |
| [cobalt_strike_user_data_collection](./cobalt_strike_user_data_collection.md) | CSB-027 | complementary; proposed rewrite |

## Cross-rule findings

- Strongest internal signals are ordered security effects: dangerous cross-process access plus execution, remote staging plus service creation, remote session plus child execution, and collection plus egress.
- Weakest internal signals are standalone rarity, unsigned-process context, generic fan-out, broad 4672 privilege assignment, and unqualified file deletion.
- Recurring gaps are causal confirmation, source-to-target joins, process-to-resource outcome correlation, collection-health gating, low-and-slow aggregation, and multi-process/session grouping.
- Public rules are strongest when they add concrete effect telemetry, access rights, ancestry, timing periodicity, or protocol-specific context. They are weaker when they depend on mutable command text, default names, opaque vendor classifications, or a single implementation.

## Review status

Threat-detection comparison complete for 21/21 Cobalt Strike Beacon rules. Every document contains an actual YARA-L proposal; all proposals remain deferred until independently verified and passed through the canonical adversarial-review workflow.
