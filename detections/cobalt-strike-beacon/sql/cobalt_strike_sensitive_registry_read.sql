-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_sensitive_registry_read.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_sensitive_registry_read
-- severity: medium
-- procedure_ids: CSB-023
-- description: Surfaces registry read/enumeration of security-sensitive configuration by an uncommon process.
-- log_source_prerequisites: Normalize EDR REGISTRY_READ or scoped 4656/4663 with process, user, hive/key/value, operation and sensitivity classification.
-- false_positives: Inventory, compliance, EDR, backup, forensics and operating-system components.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_sensitive_registry_read' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('REGISTRY_READ') OR event_type IN ('REGISTRY_READ')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
