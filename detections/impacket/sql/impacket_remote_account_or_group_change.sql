-- source_yaral: detections/impacket/yaral/impacket_remote_account_or_group_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_remote_account_or_group_change
-- severity: high
-- procedure_ids: IMP-07
-- description: Detects account, computer and group membership changes associated with a network-originating logon.
-- log_source_prerequisites: DC Security identity-change and 4624 events with actor and source.
-- false_positives: Identity lifecycle and delegated administration.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_remote_account_or_group_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4720', '4722', '4723', '4724', '4725', '4726', '4728', '4729', '4732', '4733', '4738', '4741', '4742', '4743', '4756', '4757') OR event_type IN ('4720', '4722', '4723', '4724', '4725', '4726', '4728', '4729', '4732', '4733', '4738', '4741', '4742', '4743', '4756', '4757')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
