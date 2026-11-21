# Nmap public-rule comparison index

Pinned public revisions: Elastic `9d792a8f6731542935156db61eaba88bf337e819`; Splunk `21509485465aaed2cfa4604e3d2ab5ee52975f0a`.

Five rules have meaningful public counterparts, each ending in a terminal decision. Two adopted proposals were implemented independently as `nmap_binary_identity_execution` and `ncat_socket_bound_shell_child`.

No meaningful public candidate exists in the pinned snapshots for these rules, so they have no comparison:
- `nmap_reverse_dns_ptr_burst`
- `nmap_auth_failure_fanout_from_source` (generic brute-force rules exist but key on unrelated sources)
- `nmap_broadcast_discovery_ports`
- `nmap_output_file_artifacts`
- `nmap_npcap_driver_install`
- `nmap_tcpip_performance_tweak`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`nmap_cli_option_grammar`](./nmap_cli_option_grammar.md) | `NM-P01..P13,NM-P16` | Elastic Linux Nmap activity (deprecated) | new_rule | modify |
| [`nmap_process_connect_scan_fanout`](./nmap_process_connect_scan_fanout.md) | `NM-P02,NM-P05,NM-P08` | Elastic port scanning from compromised Linux host | patch | reject |
| [`nmap_network_scan_flow_pattern`](./nmap_network_scan_flow_pattern.md) | `NM-P01,NM-P03,NM-P04,NM-P06` | Splunk internal horizontal and vertical port scans | split | reject |
| [`ncat_exec_or_broker_grammar`](./ncat_exec_or_broker_grammar.md) | `NM-P15` | Elastic reverse shell via netcat | new_rule | modify |
| [`nmap_nse_http_default_user_agent`](./nmap_nse_http_default_user_agent.md) | `NM-P08,NM-P10` | Elastic web server unusual user agents | patch | reject |
