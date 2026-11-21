-- source_yaral: detections/adaptixc2/yaral/adaptix_rwx_memory_in_network_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: adaptix_rwx_memory_in_network_process
-- severity: medium
-- procedure_ids: AX-P06
-- description: Detects an EDR-reported private read-write-execute memory allocation in an unverified process that has made outbound connections within 10 minutes, the effect of in-memory BOF and COFF loading.
-- log_source_prerequisites: EDR memory-protection telemetry normalized as product event type MEMORY_PROTECTION or VIRTUAL_ALLOC with protection in additional.fields['protection'], plus process-attributed NETWORK_CONNECTION; vendor-specific.
-- false_positives: JIT-compiling runtimes and packed legitimate software.
-- references: reports/adaptixc2/source-analysis.md#procedure-analysis; reviews/adaptixc2/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'adaptix_rwx_memory_in_network_process' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('MEMORY_PROTECTION', 'NETWORK_CONNECTION', 'VIRTUAL_ALLOC') OR event_type IN ('MEMORY_PROTECTION', 'NETWORK_CONNECTION', 'VIRTUAL_ALLOC')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
