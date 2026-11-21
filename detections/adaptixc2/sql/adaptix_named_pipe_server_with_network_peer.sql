-- source_yaral: detections/adaptixc2/yaral/adaptix_named_pipe_server_with_network_peer.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_named_pipe_server_with_network_peer
-- severity: high
-- procedure_ids: AX-P03
-- description: Detects an unverified, non-system process creating a named pipe that is then connected to over the network (SMB pipe access from a remote host, or a pipe connection by another host within 30 minutes), the SMB peer-to-peer transport.
-- log_source_prerequisites: Sysmon Event ID 17 (pipe created, NAMED_PIPE_CREATION) and 18 (pipe connected) with pipe name and image, and Windows Security 5145 (IPC$ named-pipe access) with relative target name and source address.
-- false_positives: Line-of-business services and security agents exposing named pipes to remote management.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'adaptix_named_pipe_server_with_network_peer' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('17', '5145') OR event_type IN ('17', '5145')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
