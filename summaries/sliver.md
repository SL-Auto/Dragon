# Sliver procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: sliver
- Revision: 13c2d3344927429cf55f6f7212499087e804bf47
- Lifecycle: analyzed
- Full evidence: reports/sliver/source-analysis.md
- Coverage ledger: coverage/sliver.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| PROC-001 | initialization identity limits | assessed | detected | sliver_process_behavior_cluster, sliver_unsigned_process_novel_egress |
| PROC-002 | session beacon reconnect kill | assessed | detected | sliver_recurrent_process_egress, sliver_cleanup_after_egress, sliver_self_delete_after_egress |
| PROC-003 | mtls http c2 | assessed | detected | sliver_recurrent_process_egress |
| PROC-004 | dns wireguard c2 | assessed | detected | sliver_dns_or_udp_process_egress, sliver_low_and_slow_udp_beacon |
| PROC-005 | pivot c2 | assessed | detected | sliver_listener_with_egress, sliver_relay_to_novel_destination |
| PROC-006 | discovery | assessed | not_observable |  |
| PROC-007 | file reads collection | assessed | detected | sliver_file_activity_from_network_process, sliver_credential_file_access_from_network_process |
| PROC-008 | file mutation transfer deletion | assessed | detected | sliver_file_activity_from_network_process, sliver_credential_file_access_from_network_process |
| PROC-009 | metadata memfiles | assessed | detected | sliver_file_activity_from_network_process |
| PROC-010 | child and shell execution | assessed | detected | sliver_parent_egress_with_spawned_interpreter |
| PROC-011 | task shellcode migration | assessed | detected | sliver_process_access_from_network_process, sliver_lsass_access_from_network_process |
| PROC-012 | assembly library native extension | assessed | detected | sliver_process_access_from_network_process, sliver_lsass_access_from_network_process |
| PROC-013 | wasm execution | assessed | not_observable |  |
| PROC-014 | screen capture | assessed | detected | sliver_screen_capture_process_egress |
| PROC-015 | process dump | assessed | detected | sliver_process_access_from_network_process, sliver_lsass_access_from_network_process |
| PROC-016 | tokens alternate credentials | assessed | detected | sliver_identity_or_service_from_network_process, sliver_explicit_credential_service_creation |
| PROC-017 | system acquisition | assessed | detected | sliver_identity_or_service_from_network_process, sliver_explicit_credential_service_creation |
| PROC-018 | registry operations | assessed | detected | sliver_registry_from_network_process, sliver_registry_persistence_key_from_network_process |
| PROC-019 | service operations | assessed | detected | sliver_identity_or_service_from_network_process, sliver_explicit_credential_service_creation |
| PROC-020 | remote service ssh execution | assessed | detected | sliver_remote_admin_sequence |
| PROC-021 | tunnels forwards socks | assessed | detected | sliver_listener_with_egress, sliver_relay_to_novel_destination |
| PROC-022 | browser instrumentation modules | assessed | detected | sliver_browser_debugging_from_network_process |
| PROC-026 | cleanup teardown | assessed | detected | sliver_cleanup_after_egress |
