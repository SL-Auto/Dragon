-- source_yaral: detections/sliver/yaral/sliver_remote_admin_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_remote_admin_sequence
-- severity: high
-- procedure_ids: PROC-020
-- description: Remote authentication followed by service or SSH execution on target, joined by logon/session identity
-- log_source_prerequisites: Authentication and service/SSH process events with target host, account, and logon/session identifier
-- false_positives: Deployment, backup, authorized remote administration
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_remote_admin_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4624', 'sshd_auth_success', '4697', '7045', 'sshd_command') OR event_type IN ('4624', 'sshd_auth_success', '4697', '7045', 'sshd_command')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
