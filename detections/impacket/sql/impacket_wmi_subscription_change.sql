-- source_yaral: detections/impacket/yaral/impacket_wmi_subscription_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_wmi_subscription_change
-- severity: high
-- procedure_ids: IMP-06
-- description: Detects WMI filter, consumer or binding creation.
-- log_source_prerequisites: Sysmon 19-21 or equivalent WMI repository events.
-- false_positives: Approved monitoring and management products.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_wmi_subscription_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('20', '21') OR event_type IN ('20', '21')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
