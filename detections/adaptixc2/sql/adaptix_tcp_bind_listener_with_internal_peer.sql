-- source_yaral: detections/adaptixc2/yaral/adaptix_tcp_bind_listener_with_internal_peer.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_tcp_bind_listener_with_internal_peer
-- severity: medium
-- procedure_ids: AX-P03,AX-P09
-- description: Detects an unverified process that opens a listening TCP socket and accepts a connection from an internal host within 30 minutes, the TCP bind transport used for chaining agents.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with direction, protocol, destination IP and port, host and stable process ID; optional signature verification status. LISTEN and INBOUND events must be logged.
-- false_positives: Developer tools, peer-to-peer and collaboration software.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'adaptix_tcp_bind_listener_with_internal_peer' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
