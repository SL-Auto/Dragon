-- source_yaral: detections/mimikatz/yaral/mimikatz_sensitive_store_multi_family_access.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: mimikatz_sensitive_store_multi_family_access
-- severity: high
-- procedure_ids: P18,P19,P20,P23,P25,P37,P41,P46
-- description: Correlates one process reading two independent sensitive-store families (credential manager/Vault versus crypto/certificate/Hello, IIS, SCCM/Citrix or RDM stores) as a stronger compensating signal for broad single-path store access.
-- log_source_prerequisites: EDR sensitive file or registry read telemetry with process, host and user identity, sufficient to distinguish at least two of: Credential Manager/Vault; DPAPI/crypto/certificate/Hello key stores; IIS configuration; SCCM/VSS/Citrix; Remote Desktop Manager.
-- false_positives: Backup, migration, credential-manager, endpoint-security and IT-provisioning tools that legitimately enumerate more than one store family in a session.
-- references: reports/mimikatz/source-analysis.md; public-rules/comparisons/mimikatz/mimikatz_sensitive_store_access.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality (the family-A vs family-B path split) must be implemented and tested in the target backend. This placeholder groups by process without splitting families.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, process_id, user_id, raw_event).
SELECT hostname, process_id, user_id, COUNT(*) AS event_count,
       'mimikatz_sensitive_store_multi_family_access' AS canonical_rule
FROM normalized_events
WHERE event_type IN ('FILE_READ', 'REGISTRY_READ') OR product_event_type IN ('FILE_READ', 'REGISTRY_READ')
GROUP BY hostname, process_id, user_id
HAVING COUNT(*) > 0;
