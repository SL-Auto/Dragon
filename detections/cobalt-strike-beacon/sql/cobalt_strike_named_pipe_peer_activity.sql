-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_named_pipe_peer_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_named_pipe_peer_activity
-- severity: medium
-- procedure_ids: CSB-007
-- description: Surfaces named-pipe create/connect activity from an unsigned or rare process, including SMB peer-channel hypotheses without relying on mutable pipe names.
-- log_source_prerequisites: Normalize Sysmon 17/18 or EDR PIPE_CREATE/PIPE_CONNECT with process path, signer/prevalence, host, pipe and peer when networked.
-- false_positives: Browsers, management agents, database clients, service frameworks and endpoint security.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_named_pipe_peer_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('17', '18', 'PIPE_CONNECT', 'PIPE_CREATE') OR event_type IN ('17', '18', 'PIPE_CONNECT', 'PIPE_CREATE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
