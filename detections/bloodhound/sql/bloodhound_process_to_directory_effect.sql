-- source_yaral: detections/bloodhound/yaral/bloodhound_process_to_directory_effect.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: bloodhound_process_to_directory_effect
-- severity: medium
-- procedure_ids: BH-001
-- description: Detects one endpoint process entity issuing LDAP searches against many distinct directory objects or search bases, independent of process prevalence, signer, executable path or a preceding launch event, compensating for bloodhound_collector_process_network_context's dependence on rarity and connection count.
-- log_source_prerequisites: Endpoint-attributed LDAP_SEARCH telemetry (EDR LDAP query events) with host, stable process entity identifier, process path, account, and search base DN or per-result object identity normalized to target.resource.name. Cloud audit logs are not process-attributed and are out of scope for this rule.
-- false_positives: Identity inventory, endpoint management, directory administration consoles, backup and migration tooling, including signed and prevalent software; domain-joined services resolving many group or SID references.
-- references: reports/bloodhound/source-analysis.md#bh-001, public-rules/comparisons/bloodhound/bloodhound_collector_process_network_context.md, reviews/bloodhound/detection-review.md#bh-dr-16
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: principal.hostname->dest/DeviceName/hostname/host.name; principal.process.product_specific_process_id->process_guid/InitiatingProcessId+InitiatingProcessCreationTime/process_id/process.entity_id; target.resource.name->ldap_search_base/DistinguishedName/object_name; principal.process.file.full_path->process_path/InitiatingProcessFolderPath
-- assumptions_and_gaps: Native per-host, per-stable-process distinct object/search-base threshold over 30 minutes (schedule every 10 minutes). The stable process key must be the vendor entity ID; raw PID alone reintroduces PID-reuse joins.
-- Schema assumption: normalized_events(event_time, product_event_type, hostname, process_entity_id, process_path, user_id, object_name).
SELECT hostname, process_entity_id,
       COUNT(DISTINCT object_name) AS objects,
       MIN(process_path) AS process_path_sample,
       'bloodhound_process_to_directory_effect' AS canonical_rule
FROM normalized_events
WHERE product_event_type = 'LDAP_SEARCH'
  AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND process_entity_id IS NOT NULL
  AND object_name IS NOT NULL
GROUP BY hostname, process_entity_id
HAVING COUNT(DISTINCT object_name) >= 25;
