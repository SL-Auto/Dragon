# AdaptixC2 public-rule comparison index

Pinned public revision: Elastic `9d792a8f6731542935156db61eaba88bf337e819`. No public rule in the pinned Elastic, Sentinel, Splunk or Chronicle snapshots targets AdaptixC2 specifically. Two rules have meaningful generic counterparts.

No closer public candidate exists for these rules, so they have no comparison:
- `adaptix_named_pipe_server_with_network_peer`
- `adaptix_network_process_archive_staging`
- `adaptix_network_process_spawns_child`
- `adaptix_recurrent_process_egress`
- `adaptix_rwx_memory_in_network_process`
- `adaptix_screen_capture_then_egress`
- `adaptix_tcp_bind_listener_with_internal_peer`
- `adaptix_tunnel_internal_fanout`

| Internal rule | Procedures | Closest public candidate | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`adaptix_raw_socket_dns_from_user_process`](./adaptix_raw_socket_dns_from_user_process.md) | `AX-P02` | Elastic DNS tunnelling via nslookup | patch | reject |
| [`adaptix_secondary_logon_hidden_interpreter`](./adaptix_secondary_logon_hidden_interpreter.md) | `AX-P05` | Elastic privilege escalation via token theft | patch | reject |
