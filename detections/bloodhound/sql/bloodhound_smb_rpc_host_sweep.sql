-- source_yaral: detections/bloodhound/yaral/bloodhound_smb_rpc_host_sweep.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_smb_rpc_host_sweep
-- severity: high
-- procedure_ids: BH-006
-- description: Detects one process attempting SMB or RPC connections to many internal hosts.
-- log_source_prerequisites: EDR/firewall network events with source process, destination host/IP and port.
-- false_positives: Vulnerability scanners, deployment systems, backup discovery and approved inventory.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_smb_rpc_host_sweep' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION') OR event_type IN ('NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
