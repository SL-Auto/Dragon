# AdaptixC2 procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: adaptixc2
- Revision: e99535c9ef4642190f7ea125c2983d1611f1a3f3
- Lifecycle: analyzed
- Full evidence: reports/adaptixc2/source-analysis.md
- Coverage ledger: coverage/adaptixc2.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| AX-P01 | HTTP(S) transport | assessed | detected | adaptix_recurrent_process_egress |
| AX-P02 | raw-socket DNS transport | assessed | detected | adaptix_raw_socket_dns_from_user_process |
| AX-P03 | SMB and TCP peer-to-peer transports and pivots | assessed | detected | adaptix_named_pipe_server_with_network_peer, adaptix_tcp_bind_listener_with_internal_peer |
| AX-P04 | Gopher TCP transport | assessed | detected | adaptix_recurrent_process_egress |
| AX-P05 | command and process execution | assessed | detected | adaptix_network_process_spawns_child, adaptix_secondary_logon_hidden_interpreter |
| AX-P06 | in-memory BOF execution | assessed | detected | adaptix_rwx_memory_in_network_process |
| AX-P07 | file operations and transfer | assessed | detected | adaptix_network_process_archive_staging |
| AX-P08 | process and host discovery | not_observable | not_observable |  |
| AX-P09 | tunnels and SOCKS | assessed | detected | adaptix_tunnel_internal_fanout, adaptix_tcp_bind_listener_with_internal_peer |
| AX-P10 | screenshot | assessed | detected | adaptix_screen_capture_then_egress |
| AX-P11 | agent lifecycle and runtime | not_observable | not_observable |  |
