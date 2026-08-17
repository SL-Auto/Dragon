# Havoc procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: havoc
- Revision: c84f7755a8b1c0f737576bdd3a0e982a296012f1
- Lifecycle: analyzed
- Full evidence: reports/havoc/source-analysis.md
- Coverage ledger: coverage/havoc.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| HV-P01 | lifecycle and HTTP check-in | assessed | detected | havoc_recurrent_process_egress, havoc_stable_destination_beaconing |
| HV-P02 | SMB named-pipe transport | assessed | detected | havoc_named_pipe_network_context |
| HV-P03 | sleep kill-date working-hours runtime configuration | assessed | detected | havoc_recurrent_process_egress, havoc_stable_destination_beaconing |
| HV-P04 | process discovery and module inspection | assessed | detected | havoc_discovery_fanout |
| HV-P05 | process creation and command execution | assessed | detected | havoc_spawned_command_execution |
| HV-P06 | filesystem discovery and reads | assessed | detected | havoc_file_activity_from_network_process |
| HV-P07 | file transfer and staging | assessed | detected | havoc_file_activity_from_network_process |
| HV-P08 | file mutation and cleanup | assessed | detected | havoc_file_activity_from_network_process |
| HV-P09 | COFF BOF inline execution | assessed | detected | havoc_memory_execution_from_network_process |
| HV-P10 | CLR dotnet assembly execution | assessed | detected | havoc_memory_execution_from_network_process |
| HV-P11 | DLL and shellcode execution injection | assessed | detected | havoc_memory_execution_from_network_process |
| HV-P12 | token discovery and manipulation | assessed | detected | havoc_token_authentication_sequence |
| HV-P13 | network and directory discovery | assessed | detected | havoc_discovery_fanout |
| HV-P14 | screen capture | assessed | detected | havoc_screen_capture_then_egress |
| HV-P15 | SMB pivot management | assessed | detected | havoc_named_pipe_network_context |
| HV-P16 | port forwarding and SOCKS proxy | assessed | detected | havoc_listener_and_forwarding |
| HV-P17 | Kerberos ticket operations | assessed | detected | havoc_kerberos_ticket_effect |
| HV-P18 | memory-file staging | assessed | not_observable |  |
| HV-P19 | job and transfer control | assessed | not_observable |  |
| HV-P20 | exit and teardown | assessed | detected | havoc_cleanup_after_network_activity |
