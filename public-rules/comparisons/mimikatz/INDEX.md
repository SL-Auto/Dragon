# Mimikatz public-rule comparison index

Pinned Elastic revision: `9d792a8f6731542935156db61eaba88bf337e819`.

All 17 canonical Mimikatz rules were compared at procedure-branch and signal-strength level. Public rules are independent evidence only; proposed code remains `unvalidated_proposal` and canonical detections were not changed.

| Internal rule | Procedures | Headline conclusion | Proposed change |
| --- | --- | --- | --- |
| [mimikatz_account_secret_change](./mimikatz_account_secret_change.md) | P16 | insufficient_evidence | rewrite |
| [mimikatz_certificate_key_operation](./mimikatz_certificate_key_operation.md) | P21,P24 | insufficient_evidence | compensating_rule |
| [mimikatz_clipboard_device_access](./mimikatz_clipboard_device_access.md) | P34,P42 | insufficient_evidence | split |
| [mimikatz_cross_process_tamper](./mimikatz_cross_process_tamper.md) | P22,P27,P28,P32,P40 | complementary | rewrite |
| [mimikatz_directory_mutation](./mimikatz_directory_mutation.md) | P15,P29 | insufficient_evidence | rewrite |
| [mimikatz_directory_network_discovery](./mimikatz_directory_network_discovery.md) | P30 | insufficient_evidence | compensating_rule |
| [mimikatz_directory_replication_right_access](./mimikatz_directory_replication_right_access.md) | P14 | equivalent | rewrite |
| [mimikatz_event_log_impairment](./mimikatz_event_log_impairment.md) | P26 | insufficient_evidence | compensating_rule |
| [mimikatz_firmware_driver_operation](./mimikatz_firmware_driver_operation.md) | P39,P43 | insufficient_evidence | rewrite |
| [mimikatz_kerberos_activity](./mimikatz_kerberos_activity.md) | P10 | complementary | rewrite |
| [mimikatz_lsass_memory_access](./mimikatz_lsass_memory_access.md) | P07,P09,P13 | complementary | rewrite |
| [mimikatz_process_file_context](./mimikatz_process_file_context.md) | P01,P31,P33 | complementary | compensating_rule |
| [mimikatz_protected_sam_system_access_sequence](./mimikatz_protected_sam_system_access_sequence.md) | P12 | ours_stronger | rewrite |
| [mimikatz_rpc_pipe_activity](./mimikatz_rpc_pipe_activity.md) | P35,P38 | insufficient_evidence | rewrite |
| [mimikatz_sensitive_store_access](./mimikatz_sensitive_store_access.md) | P18,P19,P20,P23,P25,P37,P41,P46 | complementary | rewrite |
| [mimikatz_service_driver_module_change](./mimikatz_service_driver_module_change.md) | P06,P36,P44,P45 | complementary | rewrite |
| [mimikatz_token_process_control](./mimikatz_token_process_control.md) | P02,P03,P04,P05 | complementary | rewrite |

## Cross-rule findings

- Strong signals are successful LSASS/replication/key/store operations, resolved cross-process writes, protected-state mutations and resulting authentication or module-load effects.
- Weak signals are filenames, command fragments, generic process opens, service installs and single path reads without result or caller context.
- Recurring internal gaps are stable entity joins, explicit success/granted rights, non-default APIs, distributed activity and authoritative trust/collection-health enrichment.
- Public coverage is strongest for LSASS access, DCSync, DPAPI backup keys, ticket artifacts, SeDebug, hive movement and LSA packages; it is sparse for several RPC, firmware, clipboard and multi-store branches.

## Review status

Threat-detection comparison complete for 17/17 rules with concrete YARA-L proposals. Adoption remains a separate canonical improvement workflow.
