-- source_yaral: detections/impacket/yaral/impacket_suspicious_kerberos_requests.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: impacket_suspicious_kerberos_requests
-- severity: medium
-- procedure_ids: IMP-11
-- description: Detects high-volume or uncommon Kerberos ticket-request patterns requiring investigation.
-- log_source_prerequisites: DC 4768/4769/4771 with client, account, service, encryption and options.
-- false_positives: Service discovery, application startup and authentication troubleshooting.
-- references: reports/impacket/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'impacket_suspicious_kerberos_requests' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4768', '4769', '4771') OR event_type IN ('4768', '4769', '4771')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
