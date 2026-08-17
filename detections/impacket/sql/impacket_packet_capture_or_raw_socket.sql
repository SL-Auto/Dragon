-- source_yaral: detections/impacket/yaral/impacket_packet_capture_or_raw_socket.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_packet_capture_or_raw_socket
-- severity: medium
-- procedure_ids: IMP-19
-- description: Detects unexpected packet capture driver or raw socket use.
-- log_source_prerequisites: EDR process, driver and raw-socket telemetry.
-- false_positives: Network troubleshooting, monitoring and security sensors.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_packet_capture_or_raw_socket' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('DRIVER_LOAD', 'NETWORK_CONNECTION', 'PROCESS_LAUNCH') OR event_type IN ('DRIVER_LOAD', 'NETWORK_CONNECTION', 'PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
