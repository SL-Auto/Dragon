-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_directory_discovery_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_directory_discovery_compensating_signal
-- severity: medium
-- procedure_ids: CSB-022
-- description: Aggregates multi-class LDAP directory queries by user and host, independent of any single process, to surface discovery distributed across multiple short-lived processes in the same session.
-- log_source_prerequisites: Normalize LDAP_QUERY with client account, hostname, and object-class field, plus an allowlist enrichment identifying approved directory-scanning software.
-- false_positives: Identity governance, endpoint inventory, directory health, administration and vulnerability-assessment tooling that legitimately queries many object classes.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_directory_discovery.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, user_id, hostname, object_class, approved_directory_scanner); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id, hostname and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, user_id, hostname, object_class, approved_directory_scanner.
SELECT user_id, hostname, COUNT(DISTINCT object_class) AS matched_count, 'cobalt_strike_directory_discovery_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND event_type IN ('LDAP_SEARCH', 'LDAP_QUERY')
  AND COALESCE(approved_directory_scanner, FALSE) = FALSE
GROUP BY user_id, hostname
HAVING COUNT(DISTINCT object_class) >= 4;
