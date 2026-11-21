-- source_yaral: detections/sliver/yaral/sliver_remote_admin_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_remote_admin_sequence
-- severity: high
-- procedure_ids: PROC-020
-- description: Remote authentication followed by Windows service installation (4697) or SSH command execution on the target, joined by logon/session identity
-- log_source_prerequisites: Windows Security 4624 and 4697 (TargetLogonId / SubjectLogonId normalized to network.session_id) or SSH authentication and command events with target host, account and session identifier
-- false_positives: Deployment, backup, authorized remote administration
-- references: reports/sliver/source-analysis.md, public-rules/comparisons/sliver/sliver_remote_admin_sequence.md, reviews/sliver/detection-review.md#review-015
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_remote_admin_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4624', '4697', 'sshd_auth_success', 'sshd_command') OR event_type IN ('4624', '4697', 'sshd_auth_success', 'sshd_command')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
