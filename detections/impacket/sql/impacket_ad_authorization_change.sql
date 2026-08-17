-- source_yaral: detections/impacket/yaral/impacket_ad_authorization_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_ad_authorization_change
-- severity: high
-- procedure_ids: IMP-10
-- description: Detects changes to AD authorization, ownership, delegation or dMSA attributes.
-- log_source_prerequisites: DC 5136/5137 with DN, attribute, actor and old/new values.
-- false_positives: Approved delegation and IAM workflows.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_ad_authorization_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('5136', '5137') OR event_type IN ('5136', '5137')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
