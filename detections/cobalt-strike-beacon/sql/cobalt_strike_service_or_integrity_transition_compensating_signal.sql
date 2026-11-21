-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_service_or_integrity_transition_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_service_or_integrity_transition_compensating_signal
-- severity: high
-- procedure_ids: CSB-020
-- description: Detects a process launch reaching SYSTEM integrity whose parent process is unsigned or rare and is not an approved elevation broker, providing the causal parent/child relationship that the base rule's standalone 4697/7045/integrity-transition signal does not require.
-- log_source_prerequisites: Normalize PROCESS_LAUNCH with target integrity level, parent process signer and prevalence, and an approved-elevation-broker enrichment.
-- false_positives: Installers, driver-installation flows, and approved elevation-broker components not reflected in the enrichment allowlist.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_service_or_integrity_transition.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, integrity_level, process_signed, process_prevalence, approved_elevation_broker); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, integrity_level, process_signed, process_prevalence, approved_elevation_broker.
SELECT *, 'cobalt_strike_service_or_integrity_transition_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND event_type = 'PROCESS_LAUNCH'
  AND integrity_level = 'SYSTEM'
  AND ((process_signed = FALSE) OR (process_prevalence = 'RARE'))
  AND COALESCE(approved_elevation_broker, FALSE) = FALSE;
