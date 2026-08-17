-- source_yaral: detections/impacket/yaral/impacket_privilege_path_effects.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_privilege_path_effects
-- severity: high
-- procedure_ids: IMP-22
-- description: Detects correlated directory privilege changes and anomalous Kerberos ticket use.
-- log_source_prerequisites: DC directory-change and Kerberos events with actor, target and source.
-- false_positives: Approved domain migrations and delegation changes.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_privilege_path_effects' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4741', '4742', '4768', '4769', '5136', '5137') OR event_type IN ('4741', '4742', '4768', '4769', '5136', '5137')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
