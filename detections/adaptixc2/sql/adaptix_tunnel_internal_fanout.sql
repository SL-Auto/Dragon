-- source_yaral: detections/adaptixc2/yaral/adaptix_tunnel_internal_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_tunnel_internal_fanout
-- severity: high
-- procedure_ids: AX-P09
-- description: Detects an unverified process that holds external egress while connecting to ten or more distinct internal hosts or ports within 15 minutes, the effect of agent SOCKS or port-forward tunnels.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with direction, protocol, destination IP and port, host and stable process ID; optional signature verification status.
-- false_positives: Unsigned management agents and scanners with internet egress.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'adaptix_tunnel_internal_fanout' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
