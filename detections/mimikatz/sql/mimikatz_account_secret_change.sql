-- source_yaral: detections/mimikatz/yaral/mimikatz_account_secret_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_account_secret_change
-- severity: medium
-- procedure_ids: P16
-- description: Detects account or machine-account secret changes for contextual correlation.
-- log_source_prerequisites: DC Security 4723, 4724 and 4742 with caller, target and source context.
-- false_positives: Helpdesk resets, machine password rotation and authorized recovery.
-- references: reports/mimikatz/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'mimikatz_account_secret_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4723', '4724', '4742') OR event_type IN ('4723', '4724', '4742')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
