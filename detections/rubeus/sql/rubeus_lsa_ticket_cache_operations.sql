-- source_yaral: detections/rubeus/yaral/rubeus_lsa_ticket_cache_operations.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_lsa_ticket_cache_operations
-- severity: medium
-- procedure_ids: PROC-006
-- description: Detects Kerberos ticket-cache query/enumeration operations from EDR API telemetry. Split from encoded-ticket retrieval, which is a stronger, separately severity-scored signal covered by rubeus_lsa_encoded_ticket_retrieval.
-- log_source_prerequisites: EDR must expose LsaCallAuthenticationPackage and Kerberos message type with process and target LUID.
-- false_positives: Klist, SSO, EDR, incident response, and authentication components routinely enumerate the ticket cache.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_cache_operations.md; reviews/rubeus/detection-review.md#review-010
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_lsa_ticket_cache_operations' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('EDR_API_CALL') OR event_type IN ('EDR_API_CALL')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
