# Nmap telemetry requirements

Scope: Nmap, Ncat and Nping executed on a monitored or compromised host, plus their network and authentication effects on targets, at revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NM-TEL-01 | Process creation | Sysmon Event ID 1, Security 4688 with command line, Linux auditd EXECVE, EDR `PROCESS_LAUNCH` | command line, image path, PE OriginalFileName, parent command line, user, host | Enable command-line capture; map Sysmon OriginalFileName and ParentCommandLine | 1 hour per host and image | Portable or renamed Linux binaries lack PE metadata | `nmap_cli_option_grammar`, `nmap_binary_identity_execution`, `ncat_exec_or_broker_grammar`, `ncat_socket_bound_shell_child`, `nmap_tcpip_performance_tweak`; NM-P01 to P16 |
| NM-TEL-02 | Process-attributed network | Sysmon Event ID 3 / `NETWORK_CONNECTION` | host, process ID, image, destination IP and port, signature status | Log all destinations, including multicast and broadcast UDP | 5 minutes per process | Raw packets are not attributed (NM-DR-01) | `nmap_process_connect_scan_fanout`, `nmap_broadcast_discovery_ports`; NM-P02, P05, P08, P11 |
| NM-TEL-03 | Network flows | NDR, firewall or flow `NETWORK_FLOW` / `NETWORK_CONNECTION` without process | source and destination IP and port, action | Retain denied and reset flows; no sampling on internal segments | 5 minutes per source IP | NAT collapses sources | `nmap_network_scan_flow_pattern`; NM-P01, P03, P04, P06 |
| NM-TEL-04 | Process-attributed DNS | Sysmon Event ID 22 / `NETWORK_DNS` | host, process ID, query name | Enable DnsQuery with PTR queries retained | 5 minutes per process | High volume; cached results are not logged | `nmap_reverse_dns_ptr_burst`; NM-P07 |
| NM-TEL-05 | Web, proxy or NDR HTTP | `NETWORK_HTTP` | source IP, User-Agent, target host | Log the User-Agent on internal web servers and reverse proxies | 1 hour per source | Overridable string (NM-DR-04) | `nmap_nse_http_default_user_agent`; NM-P08, P10 |
| NM-TEL-06 | Authentication failures on targets | Windows Security 4625 and 4771; normalized `USER_LOGIN` failures from service logs | source IP, target account, target host, action | Enable logon-failure auditing; normalize SSH, RDP, SMB, web and database authentication logs | 10 minutes per source IP | NAT and shared sources (NM-DR-06) | `nmap_auth_failure_fanout_from_source`; NM-P09 |
| NM-TEL-07 | File creation | Sysmon Event ID 11 / `FILE_CREATION` | path, host, creating process | Enable file creation for user-writable paths | 1 hour | `-oG` accepts any name | `nmap_output_file_artifacts`; NM-P13 |
| NM-TEL-08 | Driver and service installation | Windows System 7045; Sysmon Event ID 6 (`DRIVER_LOAD`) | service name, image path, signer | Collect the System log and Sysmon DriverLoad | 1 hour per host | Npcap pre-installed by Wireshark (NM-DR-07) | `nmap_npcap_driver_install`; NM-P14 |
| NM-TEL-09 | Registry modification | Sysmon Event ID 13 / `REGISTRY_MODIFICATION` | key, value name, process | Monitor `Services\Tcpip\Parameters` | 1 hour per host | Optional installer section (NM-DR-07) | `nmap_tcpip_performance_tweak`; NM-P14 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `nmap_cli_option_grammar` | NM-P01 to P13, P16 | NM-TEL-01 | Process command line | approved scanner hosts | No command line, no match; default invocations need NM-DR-08 |
| `nmap_binary_identity_execution` | NM-P01 to P03, P05 to P08 | NM-TEL-01 | Image path and PE OriginalFileName | approved scanner hosts | Without OriginalFileName, renamed Windows binaries are missed |
| `nmap_process_connect_scan_fanout` | NM-P02, P05, P08 | NM-TEL-02 | Process network events with destination IP and port | signature status | Raw scans are not attributed (NM-DR-01) |
| `nmap_network_scan_flow_pattern` | NM-P01, P03, P04, P06 | NM-TEL-03 | Flows with denied and reset outcomes | scanner IP list | Sampled or allow-only flows undercount |
| `nmap_reverse_dns_ptr_burst` | NM-P07 | NM-TEL-04 | Process DNS with query names | none | `-n` disables resolution |
| `nmap_nse_http_default_user_agent` | NM-P08, P10 | NM-TEL-05 | HTTP User-Agent | none | Overridden string (NM-DR-04) |
| `nmap_auth_failure_fanout_from_source` | NM-P09 | NM-TEL-06 | Failed authentication with source IP and account | NAT inventory | Unnormalized service logs |
| `nmap_broadcast_discovery_ports` | NM-P11 | NM-TEL-02 | UDP to multicast and broadcast ports per process | none | Sensors that drop multicast destinations |
| `nmap_output_file_artifacts` | NM-P13 | NM-TEL-07 | File creation path | none | Custom `-oG` names |
| `nmap_npcap_driver_install` | NM-P14 | NM-TEL-08 | 7045 or Sysmon Event ID 6 with name or signer | approved capture hosts | Pre-installed Npcap (NM-DR-07) |
| `nmap_tcpip_performance_tweak` | NM-P14 | NM-TEL-01, NM-TEL-09 | Registry value writes or the `regedt32 /S` command line | none | Section not selected |
| `ncat_exec_or_broker_grammar` | NM-P15 | NM-TEL-01 | Process command line | none | Renamed netcat variants with other grammar (NM-DR-09) |
| `ncat_socket_bound_shell_child` | NM-P15 | NM-TEL-01 | Child image and parent command line | none | No parent command line in telemetry |

## Deployment order

1. Process creation with command line, OriginalFileName and parent command line (NM-TEL-01). It feeds six rules.
2. Unfiltered process network and flow telemetry with denied flows (NM-TEL-02, NM-TEL-03).
3. Authentication-failure normalization on targets (NM-TEL-06).
4. DNS, file, driver and registry sources as corroboration.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] OriginalFileName and ParentCommandLine mapping was verified.
- [ ] Denied and reset flows are retained.
- [ ] Approved scanners were baselined.

## Unresolved telemetry gaps

- Raw-packet attribution (NM-DR-01) and per-script exploit signatures are inherent limits. Compensating signals are named in `reviews/nmap/detection-review.md`.
