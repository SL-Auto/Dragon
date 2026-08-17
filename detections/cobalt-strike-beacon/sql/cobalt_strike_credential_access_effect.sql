-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_credential_access_effect.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_credential_access_effect
-- severity: high
-- procedure_ids: CSB-028
-- description: Detects LSASS access, protected credential-store access, or directory replication control access as credential-access effects.
-- log_source_prerequisites: Normalize Sysmon 10/EDR LSASS access, sensitive store reads, or DC 4662 replication-right events with actor/process/source and target details.
-- false_positives: EDR, antivirus, backup, forensics, identity sync, migration and directory recovery.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_credential_access_effect' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4662', 'CREDENTIAL_STORE_READ', 'LSASS_PROCESS_ACCESS') OR event_type IN ('4662', 'CREDENTIAL_STORE_READ', 'LSASS_PROCESS_ACCESS')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
