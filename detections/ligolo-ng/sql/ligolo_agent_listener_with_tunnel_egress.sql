-- source_yaral: detections/ligolo-ng/yaral/ligolo_agent_listener_with_tunnel_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: ligolo_agent_listener_with_tunnel_egress
-- severity: medium
-- procedure_ids: LG-P07
-- description: Detects a process that opens a listening socket and accepts an inbound connection while also holding an outbound connection to a non-internal destination. This is the host effect of an agent-side listener used for reverse port forwarding or chaining a second agent.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry with LISTEN (or bind) and INBOUND accept events for the local process, and OUTBOUND events with destination IP, host and stable process ID.
-- false_positives: Peer-to-peer clients, collaboration and conferencing software, remote-support tools, developer servers and update caches; approve by signer and image path.
-- references: reports/ligolo-ng/source-analysis.md#procedure-analysis; reviews/ligolo-ng/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'ligolo_agent_listener_with_tunnel_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
