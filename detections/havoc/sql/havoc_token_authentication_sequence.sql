-- source_yaral: detections/havoc/yaral/havoc_token_authentication_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_token_authentication_sequence
-- severity: high
-- procedure_ids: HV-P12
-- description: Explicit-credential or token-manipulation activity is followed by execution under the same account
-- log_source_prerequisites: Windows Security 4648 or tenant-verified EDR token manipulation and process creation with account logon ID enrichment
-- false_positives: RunAs, service accounts, deployment and approved administrative automation
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_token_authentication_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_LAUNCH', 'TOKEN_CREATE', 'TOKEN_DUPLICATE', 'TOKEN_IMPERSONATION') OR event_type IN ('PROCESS_LAUNCH', 'TOKEN_CREATE', 'TOKEN_DUPLICATE', 'TOKEN_IMPERSONATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
