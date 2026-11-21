-- source_yaral: detections/rubeus/yaral/rubeus_ticket_renewal_anomaly.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_ticket_renewal_anomaly
-- severity: low
-- procedure_ids: PROC-002
-- description: Detects a burst of Kerberos ticket renewals (4770) by one source and identity, a scripted or looping renewal anomaly separated from service-ticket (4769) acquisition volume. It does not identify low-rate automatic renewal, which is indistinguishable from native LSA renewal.
-- log_source_prerequisites: Normalize DC Security 4770 with account, source IP, service, and result.
-- false_positives: Long-running services, SSO session-renewal components, and scheduled tasks that legitimately renew tickets repeatedly.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, source_ip, user_id, service_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip, user_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, source_ip, user_id, service_name.
SELECT source_ip, user_id, COUNT(*) AS matched_count, 'rubeus_ticket_renewal_anomaly' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type = '4770'
GROUP BY source_ip, user_id
HAVING COUNT(*) >= 15;
