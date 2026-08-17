-- source_yaral: detections/havoc/yaral/havoc_kerberos_ticket_effect.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_kerberos_ticket_effect
-- severity: high
-- procedure_ids: HV-P17
-- description: A process performs LSA Kerberos cache mutation followed by resource authentication
-- log_source_prerequisites: Tenant-verified EDR or ETW LSA Kerberos operation plus 4769 or resource authentication joined by account and host
-- false_positives: Authorized ticket administration, SSO troubleshooting and security tooling
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_kerberos_ticket_effect' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4769', 'KERBEROS_RESOURCE_AUTHENTICATION', 'KERBEROS_TICKET_SUBMIT', 'LSA_KERBEROS_OPERATION') OR event_type IN ('4769', 'KERBEROS_RESOURCE_AUTHENTICATION', 'KERBEROS_TICKET_SUBMIT', 'LSA_KERBEROS_OPERATION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
