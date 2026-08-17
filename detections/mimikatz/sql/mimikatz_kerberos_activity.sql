-- source_yaral: detections/mimikatz/yaral/mimikatz_kerberos_activity.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_kerberos_activity
-- severity: low
-- procedure_ids: P10
-- description: Surfaces Kerberos ticket issuance or endpoint LSA ticket-cache operations for contextual analytics.
-- log_source_prerequisites: DC 4768-4771 and vendor LSA ticket-operation telemetry.
-- false_positives: Normal domain authentication and administrative ticket management.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_kerberos_activity' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4768', '4769', '4770', '4771') OR event_type IN ('4768', '4769', '4770', '4771')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
