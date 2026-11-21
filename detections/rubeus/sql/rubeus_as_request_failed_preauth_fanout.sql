-- source_yaral: detections/rubeus/yaral/rubeus_as_request_failed_preauth_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_as_request_failed_preauth_fanout
-- severity: high
-- procedure_ids: PROC-001
-- description: Detects one source generating failed AS requests (4768 unknown/revoked principal, or 4771 pre-authentication failure) against multiple accounts, distinct from the existing multi-principal AS fan-out rule.
-- log_source_prerequisites: DC Security 4768 and 4771 with source IP, target account and the Status/Result Code field normalized to additional.fields[\
-- false_positives: Password audits, account-lockout/health monitoring tooling, and misconfigured legacy clients retrying stale credentials.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_as_request_anomaly.md; reviews/rubeus/detection-review.md#review-012
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, source_ip, user_id, Status, action); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, source_ip, user_id, Status, action.
SELECT source_ip, COUNT(DISTINCT user_id) AS matched_count, 'rubeus_as_request_failed_preauth_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND product_event_type IN ('4768', '4771')
  AND ((action = 'BLOCK') OR (REGEXP_LIKE(Status, '^0x(6|12|18)$', 'i')))
GROUP BY source_ip
HAVING COUNT(DISTINCT user_id) >= 3;
