-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_powershell_or_clr_in_unusual_host.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_powershell_or_clr_in_unusual_host
-- severity: high
-- procedure_ids: CSB-015,CSB-017
-- description: Detects PowerShell/CLR runtime initialization or script telemetry in a process not normally hosting that runtime.
-- log_source_prerequisites: Normalize PowerShell 400/403/4103/4104, CLR load or EDR runtime initialization with host process and parser-provided expected-host enrichment.
-- false_positives: Custom .NET hosts, management agents, IDEs, installers and legitimate PowerShell embedding.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_powershell_or_clr_in_unusual_host' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('CLR_RUNTIME_LOAD', 'POWERSHELL_SCRIPT') OR event_type IN ('CLR_RUNTIME_LOAD', 'POWERSHELL_SCRIPT')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
