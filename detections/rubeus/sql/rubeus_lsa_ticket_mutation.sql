-- source_yaral: detections/rubeus/yaral/rubeus_lsa_ticket_mutation.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_lsa_ticket_mutation
-- severity: medium
-- procedure_ids: PROC-007
-- description: Detects Kerberos ticket-cache purge operations from EDR API telemetry. Split from ticket submission, which is a stronger, separately severity-scored signal covered by rubeus_lsa_ticket_submission.
-- log_source_prerequisites: EDR must expose LsaCallAuthenticationPackage message type, caller process, user, host, and target LUID.
-- false_positives: Klist purge, SSO, identity middleware, and incident response routinely purge cached tickets.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_lsa_ticket_mutation.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling. Purge was split from ticket submission on 2026-08-16; deploy this rule together with rubeus_lsa_ticket_submission rather than as a substitute for it.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, api_name, kerberos_message_type, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_lsa_ticket_mutation' AS canonical_rule
FROM normalized_events
WHERE (product_event_type = 'EDR_API_CALL' OR event_type = 'EDR_API_CALL')
  AND api_name = 'LsaCallAuthenticationPackage'
  AND kerberos_message_type ILIKE '%KerbPurgeTicketCacheMessage%'
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
