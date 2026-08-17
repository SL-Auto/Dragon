-- source_yaral: detections/rubeus/yaral/rubeus_as_request_failed_preauth_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_as_request_failed_preauth_fanout
-- severity: high
-- procedure_ids: PROC-001
-- description: Detects one source generating failed or atypical-result AS requests against multiple accounts, distinct from the existing successful multi-principal fan-out rule.
-- log_source_prerequisites: Normalize DC Security 4768 with source IP, target account, and a normalized security_result.action or result-code field distinguishing non-success outcomes.
-- false_positives: Password audits, account-lockout/health monitoring tooling, and misconfigured legacy clients retrying stale credentials.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_as_request_anomaly.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, cardinality, and the non-ALLOW result filter must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, source_ip, target_user_id, result_action, raw_event).
SELECT source_ip, COUNT(DISTINCT target_user_id) AS account_count,
       'rubeus_as_request_failed_preauth_fanout' AS canonical_rule
FROM normalized_events
WHERE (product_event_type = '4768' OR event_type = '4768') AND result_action <> 'ALLOW'
GROUP BY source_ip
HAVING COUNT(DISTINCT target_user_id) >= 3;
