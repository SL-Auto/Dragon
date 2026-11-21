-- source_yaral: detections/rubeus/yaral/rubeus_asrep_single_account_sensitive.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_asrep_single_account_sensitive
-- severity: high
-- procedure_ids: PROC-003
-- description: Detects a successful AS request without pre-authentication data for an account the tenant has classified as high-risk, compensating for targeted single-account AS-REP roasting below the three-account threshold of rubeus_asrep_roast_sequence.
-- log_source_prerequisites: DC Security 4768 with PreAuthType, Status, source IP and target account, plus an account-risk enrichment that sets additional.fields[account_risk_tier] = high for privileged, service and other sensitive accounts. Without that enrichment this rule stays silent; the base three-account rule still applies.
-- false_positives: Sensitive accounts that legitimately have pre-authentication disabled for legacy clients; record them as approved exceptions in the risk enrichment.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_asrep_roast_sequence.md; reviews/rubeus/detection-review.md#review-014
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, source_ip, user_id, PreAuthType, Status, account_risk_tier, TicketEncryptionType); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip, user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, source_ip, user_id, PreAuthType, Status, account_risk_tier, TicketEncryptionType.
SELECT source_ip, user_id, COUNT(*) AS matched_count, 'rubeus_asrep_single_account_sensitive' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type = '4768'
  AND PreAuthType = '0'
  AND Status = '0x0'
  AND account_risk_tier = 'high'
GROUP BY source_ip, user_id
HAVING COUNT(*) >= 1;
