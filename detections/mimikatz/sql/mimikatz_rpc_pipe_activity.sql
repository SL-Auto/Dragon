-- source_yaral: detections/mimikatz/yaral/mimikatz_rpc_pipe_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_rpc_pipe_activity
-- severity: medium
-- procedure_ids: P35,P38
-- description: Surfaces named-pipe or RPC activity associated with authentication coercion or remote control context.
-- log_source_prerequisites: Sysmon 17/18 or EDR RPC and network telemetry with process, endpoint and peer.
-- false_positives: Normal Windows RPC, print, EFS and management traffic.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_rpc_pipe_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('17', '18') OR event_type IN ('17', '18')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
