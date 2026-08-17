-- source_yaral: detections/impacket/yaral/impacket_cross_source_ntlm_relay.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_cross_source_ntlm_relay
-- severity: high
-- procedure_ids: IMP-21
-- description: Correlates NTLM authentication for one account across different sources and a target effect.
-- log_source_prerequisites: Normalized NTLM authentication with account, source, destination and result.
-- false_positives: NAT, proxies, clustered services and multi-hop authentication.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_cross_source_ntlm_relay' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4624', '4776') OR event_type IN ('4624', '4776')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
