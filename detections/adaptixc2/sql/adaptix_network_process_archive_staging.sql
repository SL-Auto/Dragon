-- source_yaral: detections/adaptixc2/yaral/adaptix_network_process_archive_staging.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_network_process_archive_staging
-- severity: medium
-- procedure_ids: AX-P07
-- description: Detects an unverified process with outbound connections creating a .zip archive within 15 minutes, the Gopher zip-then-download staging pattern.
-- log_source_prerequisites: Process-attributed NETWORK_CONNECTION telemetry (Sysmon Event ID 3 or EDR) with direction, protocol, destination IP and port, host and stable process ID; optional signature verification status. FILE_CREATION (Sysmon Event ID 11) with path and creating process.
-- false_positives: Unsigned archivers, backup tools and updaters.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'adaptix_network_process_archive_staging' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('FILE_CREATION', 'NETWORK_CONNECTION') OR event_type IN ('FILE_CREATION', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
