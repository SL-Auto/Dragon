# Ligolo-ng procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: ligolo-ng
- Revision: e543732f4be6dc899096ae322ae620bf010bfbfc
- Lifecycle: analyzed
- Full evidence: reports/ligolo-ng/source-analysis.md
- Coverage ledger: coverage/ligolo-ng.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| LG-P01 | outbound tunnel transport and reconnect | assessed | detected | ligolo_tunnel_process_internal_fanout, ligolo_websocket_default_user_agent, ligolo_agent_command_line_trust_flags |
| LG-P02 | bind mode inbound tunnel | assessed | detected | ligolo_bind_listener_internal_fanout, ligolo_process_internal_admin_port_sweep |
| LG-P03 | host and interface reporting | not_observable | not_observable |  |
| LG-P04 | TCP and UDP pivot connections | assessed | detected | ligolo_tunnel_process_internal_fanout, ligolo_bind_listener_internal_fanout, ligolo_process_internal_admin_port_sweep |
| LG-P05 | agent-host loopback access via magic range | assessed | detected | ligolo_tunnel_process_internal_fanout, ligolo_bind_listener_internal_fanout |
| LG-P06 | ICMP host discovery | assessed | detected | ligolo_agent_ping_probe_children |
| LG-P07 | agent-side listeners for reverse forwarding and chaining | assessed | detected | ligolo_agent_listener_with_tunnel_egress |
| LG-P08 | teardown and agent kill | not_observable | not_observable |  |
| LG-P09 | TLS trust configuration | assessed | detected | ligolo_agent_command_line_trust_flags |
