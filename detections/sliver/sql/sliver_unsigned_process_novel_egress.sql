-- source_yaral: detections/sliver/yaral/sliver_unsigned_process_novel_egress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: sliver_unsigned_process_novel_egress
-- severity: medium
-- procedure_ids: PROC-001
-- description: An unsigned, newly launched process establishes outbound network activity to the same destination more than once
-- log_source_prerequisites: Process launch telemetry with code-signature verification status, plus process-attributed outbound network telemetry with destination
-- false_positives: Unsigned internal tooling, scripts, and freshly built or unpackaged software making outbound connections
-- references: reports/sliver/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'sliver_unsigned_process_novel_egress' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('PROCESS_LAUNCH', 'NETWORK_CONNECTION') OR event_type IN ('PROCESS_LAUNCH', 'NETWORK_CONNECTION')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
