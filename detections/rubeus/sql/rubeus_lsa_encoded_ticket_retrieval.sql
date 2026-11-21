-- source_yaral: detections/rubeus/yaral/rubeus_lsa_encoded_ticket_retrieval.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_lsa_encoded_ticket_retrieval
-- severity: high
-- procedure_ids: PROC-006
-- description: Detects a successful Kerberos encoded-ticket retrieval call through LsaCallAuthenticationPackage, separated from lower-confidence cache enumeration/query activity.
-- log_source_prerequisites: EDR must expose LsaCallAuthenticationPackage API calls with Kerberos message type and a success/failure result; process, user, host, and target LUID are required for triage.
-- false_positives: Klist, SSO components, credential-isolation and IR tooling that legitimately retrieve encoded tickets.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_cache_operations.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, process_id, process_path, api_name, kerberos_message_type, result, target_luid); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, process_id, process_path, api_name, kerberos_message_type, result, target_luid.
SELECT hostname, process_id, COUNT(*) AS matched_count, 'rubeus_lsa_encoded_ticket_retrieval' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type = 'EDR_API_CALL'
  AND api_name = 'LsaCallAuthenticationPackage'
  AND REGEXP_LIKE(kerberos_message_type, '^Kerb(RetrieveEncodedTicket|RetrieveTicket)(Message)?$', 'i')
  AND result = 'ALLOW'
GROUP BY hostname, process_id
HAVING COUNT(*) >= 1;
