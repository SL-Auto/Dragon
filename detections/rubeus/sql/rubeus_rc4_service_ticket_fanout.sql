-- source_yaral: detections/rubeus/yaral/rubeus_rc4_service_ticket_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_rc4_service_ticket_fanout
-- severity: high
-- procedure_ids: PROC-002,PROC-004
-- description: Detects a single requester obtaining RC4-encrypted service tickets for three or more distinct unapproved-legacy services within a 15-minute window, independent of LDAP SPN-discovery visibility.
-- log_source_prerequisites: Normalize DC Security 4769 with source IP, requesting user, target service, TicketEncryptionType and Status, plus an approved-legacy-RC4-service enrichment keyed by target service (missing enrichment fails open).
-- false_positives: Approved legacy RC4 services and application servers that have not yet been migrated to AES; environments where the legacy-RC4-service enrichment is stale, incomplete, or absent (an unpopulated enrichment field defaults to unapproved and will over-alert until the allowlist is built).
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, source_ip, user_id, service_name, TicketEncryptionType, Status, approved_legacy_rc4_service); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip, user_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 15 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, source_ip, user_id, service_name, TicketEncryptionType, Status, approved_legacy_rc4_service.
SELECT source_ip, user_id, COUNT(DISTINCT service_name) AS matched_count, 'rubeus_rc4_service_ticket_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
  AND product_event_type = '4769'
  AND TicketEncryptionType = '0x17'
  AND Status = '0x0'
  AND COALESCE(approved_legacy_rc4_service, FALSE) = FALSE
  AND NOT REGEXP_LIKE(COALESCE(service_name, ''), '(\$$|^krbtgt$)', 'i')
GROUP BY source_ip, user_id
HAVING COUNT(DISTINCT service_name) >= 3;
