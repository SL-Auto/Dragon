# Cobalt Strike Beacon procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: cobalt-strike-beacon
- Revision: 4.13-docs-202606220941
- Lifecycle: analyzed
- Full evidence: reports/cobalt-strike-beacon/source-analysis.md
- Coverage ledger: coverage/cobalt-strike-beacon.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| CSB-001 | initialization identity and guardrails | assessed | detected | cobalt_strike_process_network_context, cobalt_strike_process_network_context_compensating_signal |
| CSB-002 | asynchronous tasking sleep jitter retries and exit | assessed | detected | cobalt_strike_process_network_context, cobalt_strike_process_network_context_compensating_signal |
| CSB-003 | runtime C2 BeaconGate syscall and host configuration | assessed | not_observable |  |
| CSB-004 | sleep masking argument parent and spawn shaping | assessed | detected | cobalt_strike_suspicious_process_lineage_or_memory, cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal |
| CSB-005 | HTTP and HTTPS C2 | assessed | detected | cobalt_strike_process_network_context, cobalt_strike_process_network_context_compensating_signal |
| CSB-006 | DNS family C2 | assessed | detected | cobalt_strike_dns_process_context, cobalt_strike_dns_process_context_compensating_signal |
| CSB-007 | SMB named pipe peer C2 | assessed | detected | cobalt_strike_named_pipe_peer_activity, cobalt_strike_named_pipe_peer_activity_compensating_signal |
| CSB-008 | TCP bind External C2 and UDC2 | assessed | detected | cobalt_strike_socket_listen_or_rare_egress, cobalt_strike_socket_listen_or_rare_egress_compensating_signal |
| CSB-009 | SOCKS reverse forwarding spunnel and VPN pivoting | assessed | detected | cobalt_strike_socket_fanout_or_forwarding, cobalt_strike_socket_fanout_or_forwarding_compensating_signal |
| CSB-010 | in-memory data imports payload store and variables | assessed | not_observable |  |
| CSB-011 | identity privilege discovery and token enablement | assessed | detected | cobalt_strike_privileged_context_change, cobalt_strike_privileged_context_change_compensating_signal |
| CSB-012 | token creation theft storage impersonation and credentialed execution | assessed | detected | cobalt_strike_alternate_identity_process |
| CSB-013 | Kerberos ticket cache purge and pass the hash | assessed | detected | cobalt_strike_unusual_authentication_material_use |
| CSB-014 | native child execution and command shell | assessed | detected | cobalt_strike_suspicious_process_lineage_or_memory, cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal |
| CSB-015 | PowerShell and unmanaged PowerShell | assessed | detected | cobalt_strike_powershell_or_clr_in_unusual_host, cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal |
| CSB-016 | BOF BOF-PE and Beacon Interpreter execution | assessed | detected | cobalt_strike_suspicious_process_lineage_or_memory, cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal |
| CSB-017 | dotnet assembly execution | assessed | detected | cobalt_strike_powershell_or_clr_in_unusual_host, cobalt_strike_powershell_or_clr_in_unusual_host_compensating_signal |
| CSB-018 | DLL reflective load shellcode and execute DLL | assessed | detected | cobalt_strike_cross_process_injection |
| CSB-019 | spawn and inject session creation and termination | assessed | detected | cobalt_strike_cross_process_injection |
| CSB-020 | privilege elevation and SYSTEM acquisition | assessed | detected | cobalt_strike_service_or_integrity_transition, cobalt_strike_service_or_integrity_transition_compensating_signal |
| CSB-021 | process identity drive time network and port discovery | assessed | detected | cobalt_strike_discovery_fanout, cobalt_strike_discovery_fanout_compensating_signal |
| CSB-022 | AD account group trust session share and host discovery | assessed | detected | cobalt_strike_directory_discovery, cobalt_strike_directory_discovery_compensating_signal |
| CSB-023 | registry discovery | assessed | detected | cobalt_strike_sensitive_registry_read, cobalt_strike_sensitive_registry_read_compensating_signal |
| CSB-024 | file and directory discovery and collection | assessed | detected | cobalt_strike_sensitive_file_activity, cobalt_strike_sensitive_file_activity_compensating_signal |
| CSB-025 | file ingress copy move and directory creation | assessed | detected | cobalt_strike_sensitive_file_activity, cobalt_strike_sensitive_file_activity_compensating_signal |
| CSB-026 | file deletion and timestamp replacement | assessed | detected | cobalt_strike_file_cleanup_or_timestomp, cobalt_strike_file_cleanup_or_timestomp_compensating_signal |
| CSB-027 | screen desktop clipboard browser and input collection | assessed | detected | cobalt_strike_user_data_collection, cobalt_strike_user_data_collection_compensating_signal |
| CSB-028 | credential dumping and directory replication | assessed | detected | cobalt_strike_credential_access_effect, cobalt_strike_credential_access_effect_compensating_signal |
| CSB-029 | operator housekeeping queue history and task cancellation | assessed | not_observable |  |
| CSB-030 | service remote execution and admin share staging | assessed | detected | cobalt_strike_remote_service_sequence, cobalt_strike_remote_service_sequence_compensating_signal |
| CSB-031 | WinRM remote execution | assessed | detected | cobalt_strike_remote_management_execution |
| CSB-032 | WMI remote execution | assessed | detected | cobalt_strike_remote_management_execution |
| CSB-033 | SSH remote execution | assessed | detected | cobalt_strike_remote_management_execution |
| CSB-034 | teardown cleanup termination and residual memory | assessed | detected | cobalt_strike_file_cleanup_or_timestomp, cobalt_strike_file_cleanup_or_timestomp_compensating_signal |
