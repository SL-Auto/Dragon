# Nmap procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: nmap
- Revision: 80dd68b8d88cbc89e584941e9ba68e57247d2230
- Lifecycle: analyzed
- Full evidence: reports/nmap/source-analysis.md
- Coverage ledger: coverage/nmap.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| NM-P01 | host discovery | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_network_scan_flow_pattern |
| NM-P02 | TCP connect scan | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_process_connect_scan_fanout |
| NM-P03 | raw port scans | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_network_scan_flow_pattern |
| NM-P04 | idle and FTP bounce scans | assessed | detected | nmap_cli_option_grammar, nmap_network_scan_flow_pattern |
| NM-P05 | service and version detection | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_process_connect_scan_fanout |
| NM-P06 | OS fingerprinting and traceroute | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_network_scan_flow_pattern |
| NM-P07 | reverse DNS resolution | assessed | detected | nmap_reverse_dns_ptr_burst, nmap_cli_option_grammar, nmap_binary_identity_execution |
| NM-P08 | NSE discovery safe default and version scripts | assessed | detected | nmap_cli_option_grammar, nmap_binary_identity_execution, nmap_process_connect_scan_fanout, nmap_nse_http_default_user_agent |
| NM-P09 | NSE brute and auth scripts | assessed | detected | nmap_cli_option_grammar, nmap_auth_failure_fanout_from_source |
| NM-P10 | NSE vuln exploit intrusive dos fuzzer and malware scripts | assessed | detected | nmap_cli_option_grammar, nmap_nse_http_default_user_agent |
| NM-P11 | NSE broadcast scripts | assessed | detected | nmap_cli_option_grammar, nmap_broadcast_discovery_ports |
| NM-P12 | NSE external scripts | assessed | detected | nmap_cli_option_grammar |
| NM-P13 | output files | assessed | detected | nmap_cli_option_grammar, nmap_output_file_artifacts |
| NM-P14 | Windows installation artifacts | assessed | detected | nmap_npcap_driver_install, nmap_tcpip_performance_tweak |
| NM-P15 | Ncat | assessed | detected | ncat_exec_or_broker_grammar, ncat_socket_bound_shell_child |
| NM-P16 | Nping | assessed | detected | nmap_cli_option_grammar |
