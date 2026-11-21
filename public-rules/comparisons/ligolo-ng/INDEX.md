# Ligolo-ng public-rule comparison index

Pinned public revisions: Elastic `9d792a8f6731542935156db61eaba88bf337e819`; Microsoft Sentinel `c3361d9ff34320e7fe3314d5f9063e15470ca53e`; Splunk `21509485465aaed2cfa4604e3d2ab5ee52975f0a`.

Public coverage of the Ligolo-ng agent is sparse: one antivirus-verdict rule, plus generic sweep, tunnelling-tool and default-User-Agent rules. Every comparison ends in a terminal decision. Adopted proposals were implemented independently as `ligolo_process_internal_admin_port_sweep` and `ligolo_agent_command_line_trust_flags`, and those two rules are compared within the comparison whose branch they close.

| Internal rule | Procedures | Closest public candidates | Proposal | Decision |
| --- | --- | --- | --- | --- |
| [`ligolo_tunnel_process_internal_fanout`](./ligolo_tunnel_process_internal_fanout.md) | `LG-P01,LG-P04,LG-P05` | Elastic network sweep; Sentinel Tarrask/Ligolo AV verdict | compensating_rule | modify |
| [`ligolo_bind_listener_internal_fanout`](./ligolo_bind_listener_internal_fanout.md) | `LG-P02,LG-P04,LG-P05` | Elastic network sweep | compensating_rule | accept |
| [`ligolo_agent_ping_probe_children`](./ligolo_agent_ping_probe_children.md) | `LG-P06` | Elastic delayed ping LOLBin execution | patch | reject |
| [`ligolo_agent_listener_with_tunnel_egress`](./ligolo_agent_listener_with_tunnel_egress.md) | `LG-P07` | Elastic Linux tunnelling and port forwarding | new_rule | modify |
| [`ligolo_websocket_default_user_agent`](./ligolo_websocket_default_user_agent.md) | `LG-P01` | Splunk HTTP C2 framework User-Agent | patch | reject |
