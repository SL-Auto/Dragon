-- source_yaral: detections/sliver/yaral/sliver_browser_debugging_from_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_browser_debugging_from_network_process
-- severity: high
-- procedure_ids: PROC-022
-- description: Network process launches a browser child with remote debugging enabled and a debug listener is established
-- log_source_prerequisites: Process command line plus parent network telemetry and child listen-socket telemetry
-- false_positives: Developers, browser automation and testing frameworks that launch browsers with remote debugging
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_browser_debugging_from_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_LAUNCH', 'NETWORK_CONNECTION') OR event_type IN ('PROCESS_LAUNCH', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
