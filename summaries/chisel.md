# Chisel procedure summary

Generated context view. Use the coverage ledger and cited report as authoritative evidence.

- Tool ID: chisel
- Revision: 6d283495b5e3eff76841038d679fcc53a57ba7dd
- Lifecycle: analyzed
- Full evidence: reports/chisel/source-analysis.md
- Coverage ledger: coverage/chisel.yml

| Procedure | Summary | Telemetry | Detection | Canonical rules |
| --- | --- | --- | --- | --- |
| CH-P01 | persistent WebSocket SSH client transport | assessed | detected | chisel_recurrent_encrypted_process_egress |
| CH-P02 | forward TCP proxy | assessed | detected | chisel_listener_with_tunnel_egress |
| CH-P03 | forward UDP proxy | assessed | detected | chisel_udp_bind_with_tunnel_egress |
| CH-P04 | reverse TCP and UDP proxy | assessed | detected | chisel_listener_with_tunnel_egress, chisel_udp_bind_with_tunnel_egress |
| CH-P05 | SOCKS5 dynamic forwarding | assessed | detected | chisel_proxy_destination_fanout |
| CH-P06 | stdio tunnel bridge | assessed | detected | chisel_stdio_network_bridge |
| CH-P07 | upstream HTTP or SOCKS proxy chain | assessed | detected | chisel_proxy_destination_fanout |
| CH-P08 | server listener and HTTP camouflage | assessed | detected | chisel_listener_with_tunnel_egress |
| CH-P09 | authentication and authorization state | assessed | not_observable |  |
| CH-P10 | keepalive reconnect and teardown | assessed | detected | chisel_recurrent_encrypted_process_egress |
