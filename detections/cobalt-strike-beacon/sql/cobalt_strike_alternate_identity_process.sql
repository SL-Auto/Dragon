-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_alternate_identity_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_alternate_identity_process
-- severity: medium
-- procedure_ids: CSB-012
-- description: Correlates explicit-credential or alternate-logon use with a new process under the resulting account.
-- log_source_prerequisites: Normalize Windows 4648 and 4688/EDR process events with host, subject, target account, logon ID and process identity.
-- false_positives: RunAs, scheduled administration, service management, deployment and helpdesk workflows.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_alternate_identity_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4648', 'PROCESS_LAUNCH') OR event_type IN ('4648', 'PROCESS_LAUNCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
