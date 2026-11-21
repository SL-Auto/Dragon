-- source_yaral: detections/rubeus/yaral/rubeus_lsa_ticket_submission.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_lsa_ticket_submission
-- severity: high
-- procedure_ids: PROC-007
-- description: Detects a successful Kerberos ticket submission into an LSA logon session through LsaCallAuthenticationPackage, separated from lower-confidence cache-purge activity.
-- log_source_prerequisites: EDR must expose LsaCallAuthenticationPackage API calls with Kerberos message type, a success/failure result, and the target LUID; caller process, user, and host are required for triage.
-- false_positives: SSO and identity middleware, credential-isolation software, and authorized red-team/IR tooling that submits tickets into a logon session.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_mutation.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, process_id, process_path, api_name, kerberos_message_type, result, target_luid); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, process_id, process_path, api_name, kerberos_message_type, result, target_luid.
SELECT hostname, process_id, COUNT(*) AS matched_count, 'rubeus_lsa_ticket_submission' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type = 'EDR_API_CALL'
  AND api_name = 'LsaCallAuthenticationPackage'
  AND REGEXP_LIKE(kerberos_message_type, '^KerbSubmitTicket(Message)?$', 'i')
  AND result = 'ALLOW'
GROUP BY hostname, process_id
HAVING COUNT(*) >= 1;
