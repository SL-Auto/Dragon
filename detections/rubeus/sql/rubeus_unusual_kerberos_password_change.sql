-- source_yaral: detections/rubeus/yaral/rubeus_unusual_kerberos_password_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_unusual_kerberos_password_change
-- severity: medium
-- procedure_ids: PROC-012
-- description: Detects a Kerberos password change from an unusual source or process context.
-- log_source_prerequisites: Normalize account-management password-change events and process-attributed network connections to Kerberos password-change service where available.
-- false_positives: User password changes, helpdesk resets, machine-account rotation, and identity management.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_unusual_kerberos_password_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4723', '4724') OR event_type IN ('4723', '4724')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
