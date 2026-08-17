-- source_yaral: detections/bloodhound/yaral/bloodhound_remote_security_configuration_reads.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_remote_security_configuration_reads
-- severity: high
-- procedure_ids: BH-012
-- description: Detects remote reads of CA, Netlogon, LDAP or NTLM security configuration across hosts.
-- log_source_prerequisites: EDR REGISTRY_READ or scoped 4656/4663 with full key path, source identity and target host.
-- false_positives: Security posture assessment, PKI administration and domain-controller compliance tools.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_remote_security_configuration_reads' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4656', '4663', 'REGISTRY_READ') OR event_type IN ('4656', '4663', 'REGISTRY_READ')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
