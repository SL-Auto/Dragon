# Mimikatz procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: mimikatz
- Revision: 306bc6b43099c7b698f2898401fddbded6a630c8
- Lifecycle: analyzed
- Full evidence: reports/mimikatz/source-analysis.md
- Coverage ledger: coverage/mimikatz.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| P01 | local utility and output | assessed | detected | mimikatz_process_file_context |
| P02 | privilege adjustment | assessed | detected | mimikatz_token_process_control |
| P03 | process discovery | assessed | detected | mimikatz_token_process_control |
| P04 | process control | assessed | detected | mimikatz_token_process_control |
| P05 | token manipulation | assessed | detected | mimikatz_token_process_control |
| P06 | service control | assessed | detected | mimikatz_service_driver_module_change, mimikatz_module_load_into_lsass_or_spooler |
| P07 | LSASS acquisition | assessed | detected | mimikatz_lsass_memory_access |
| P08 | LSASS offline parsing | assessed | not_observable |  |
| P09 | pass the hash memory modification | assessed | detected | mimikatz_lsass_memory_access |
| P10 | Kerberos cache operations | assessed | detected | mimikatz_kerberos_activity |
| P11 | offline Kerberos construction | assessed | not_observable |  |
| P12 | local hive secret recovery | assessed | detected | mimikatz_protected_sam_system_access_sequence |
| P13 | LSA query or patch | assessed | detected | mimikatz_lsass_memory_access |
| P14 | DCSync | assessed | detected | mimikatz_directory_replication_right_access |
| P15 | DCShadow | assessed | detected | mimikatz_directory_mutation |
| P16 | SAMR Netlogon secret change | assessed | detected | mimikatz_account_secret_change |
| P17 | offline DPAPI core | assessed | not_observable |  |
| P18 | DPAPI application stores | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P19 | protected key stores | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P20 | crypto enumeration export | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P21 | certificate enrollment key movement | assessed | detected | mimikatz_certificate_key_operation |
| P22 | crypto patch extraction | assessed | detected | mimikatz_cross_process_tamper |
| P23 | Vault CredMan | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P24 | Hello NGC key access | assessed | detected | mimikatz_certificate_key_operation |
| P25 | IIS configuration credentials | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P26 | event log impairment | assessed | detected | mimikatz_event_log_impairment |
| P27 | terminal service control | assessed | detected | mimikatz_cross_process_tamper |
| P28 | RDP credential memory | assessed | detected | mimikatz_cross_process_tamper |
| P29 | SID directory mutation | assessed | detected | mimikatz_directory_mutation |
| P30 | network domain discovery | assessed | detected | mimikatz_directory_network_discovery |
| P31 | utility spawn session lock | assessed | detected | mimikatz_process_file_context |
| P32 | user mode patch injection | assessed | detected | mimikatz_cross_process_tamper |
| P33 | file transform staging | assessed | detected | mimikatz_process_file_context |
| P34 | clipboard collection | assessed | detected | mimikatz_clipboard_device_access |
| P35 | authentication coercion | assessed | detected | mimikatz_rpc_pipe_activity |
| P36 | print modification | assessed | detected | mimikatz_service_driver_module_change, mimikatz_module_load_into_lsass_or_spooler |
| P37 | SCCM VSS Citrix discovery | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P38 | RPC pipe control | assessed | detected | mimikatz_rpc_pipe_activity |
| P39 | firmware variables | assessed | detected | mimikatz_firmware_driver_operation |
| P40 | Minesweeper memory | assessed | detected | mimikatz_cross_process_tamper |
| P41 | RDM artifact access | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
| P42 | hardware access | assessed | detected | mimikatz_clipboard_device_access |
| P43 | mimidrv kernel operations | assessed | detected | mimikatz_firmware_driver_operation |
| P44 | mimilib extensions | assessed | detected | mimikatz_service_driver_module_change, mimikatz_module_load_into_lsass_or_spooler |
| P45 | mimispool monitor | assessed | detected | mimikatz_service_driver_module_change, mimikatz_module_load_into_lsass_or_spooler |
| P46 | mimilove DPAPI | assessed | detected | mimikatz_sensitive_store_access, mimikatz_sensitive_store_multi_family_access |
