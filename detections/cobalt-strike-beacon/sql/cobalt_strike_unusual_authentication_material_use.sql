-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_unusual_authentication_material_use.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_unusual_authentication_material_use
-- severity: high
-- procedure_ids: CSB-013
-- description: Surfaces Kerberos or NTLM authentication whose endpoint/process context is rare or inconsistent with the account baseline.
-- log_source_prerequisites: Normalize DC 4768/4769/4776 and endpoint 4624 with account, source, service, authentication package and identity-baseline enrichment.
-- false_positives: New hosts, password rotation, service migration, disaster recovery, legacy NTLM and identity infrastructure.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_unusual_authentication_material_use' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4624', '4768', '4769', '4776') OR event_type IN ('4624', '4768', '4769', '4776')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
