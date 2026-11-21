-- source_yaral: detections/rubeus/yaral/rubeus_kerberoast_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_kerberoast_sequence
-- severity: high
-- procedure_ids: PROC-004
-- description: Correlates LDAP SPN discovery with service-ticket fan-out by the same host and user.
-- log_source_prerequisites: Normalize directory-side LDAP filters and 4769 with host, user, and service.
-- false_positives: Service inventory, monitoring, identity governance, and authorized assessment.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md, reviews/rubeus/detection-review.md#review-010
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_kerberoast_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4769', 'LDAP_SEARCH') OR event_type IN ('4769', 'LDAP_SEARCH')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
