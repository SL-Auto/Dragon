-- source_yaral: detections/rubeus/yaral/rubeus_service_ticket_or_renewal_anomaly.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_service_ticket_or_renewal_anomaly
-- severity: medium
-- procedure_ids: PROC-002
-- description: Detects unusual service-ticket (4769) acquisition volume by one source and identity. Split from ticket renewal, which is a separately scored signal covered by rubeus_ticket_renewal_anomaly, and complemented by the ticket-property-specific rubeus_rc4_service_ticket_fanout.
-- log_source_prerequisites: Normalize DC Security 4769 with account, source IP, service, result, and encryption type.
-- false_positives: SSO, service accounts, application servers, and scanners generating broad service-ticket fan-out.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_service_ticket_or_renewal_anomaly.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend. Renewal (4770) and the RC4-specific branch were split out of this rule's scope on 2026-08-16; deploy alongside rubeus_ticket_renewal_anomaly and rubeus_rc4_service_ticket_fanout.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, source_ip, target_user_id, target_resource_name, raw_event).
SELECT source_ip, target_user_id,
       COUNT(*) AS event_count,
       COUNT(DISTINCT target_resource_name) AS service_count,
       'rubeus_service_ticket_or_renewal_anomaly' AS canonical_rule
FROM normalized_events
WHERE product_event_type = '4769' OR event_type = '4769'
GROUP BY source_ip, target_user_id
HAVING COUNT(*) >= 20 OR COUNT(DISTINCT target_resource_name) >= 10;
