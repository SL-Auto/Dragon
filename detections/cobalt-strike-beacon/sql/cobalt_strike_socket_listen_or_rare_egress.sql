-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_socket_listen_or_rare_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_socket_listen_or_rare_egress
-- severity: medium
-- procedure_ids: CSB-008
-- description: Detects socket listen or egress from a rare unsigned process as coverage for bind TCP, External C2 and user-defined transports.
-- log_source_prerequisites: Normalize endpoint SOCKET_LISTEN and NETWORK_CONNECTION with process signer/prevalence, host, direction and local/remote endpoints.
-- false_positives: Developer tools, local service hosts, peer-to-peer clients, remote support and ephemeral test servers.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_socket_listen_or_rare_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'SOCKET_LISTEN') OR event_type IN ('NETWORK_CONNECTION', 'SOCKET_LISTEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
