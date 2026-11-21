-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal
-- severity: high
-- procedure_ids: CSB-004,CSB-014,CSB-016
-- description: Correlates a private executable-memory region without a backing file with a subsequent thread start whose start address falls in that private region, on the same process, providing execution evidence that the base rule's standalone memory-allocation signal cannot express.
-- log_source_prerequisites: Normalize EXECUTABLE_MEMORY with private/backing-file attributes and THREAD_START with start-address-in-region and expected-JIT-host enrichment, joined on host and PID within 5 minutes.
-- false_positives: JIT runtimes (browsers, .NET, JVM), application virtualization, and approved dynamic-code frameworks not reflected in the JIT-host enrichment.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_suspicious_process_lineage_or_memory.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, memory_is_private, memory_has_backing_file, start_address_in_private_rx, approved_jit_host); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on hostname, process_id within 5 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, memory_is_private, memory_has_backing_file, start_address_in_private_rx, approved_jit_host.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type = 'EXECUTABLE_MEMORY'
    AND memory_is_private = 'true'
    AND memory_has_backing_file = FALSE
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND event_type = 'THREAD_START'
    AND start_address_in_private_rx = 'true'
    AND COALESCE(approved_jit_host, FALSE) = FALSE
)
SELECT a.hostname, a.process_id, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_suspicious_process_lineage_or_memory_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.hostname = b.hostname
 AND a.process_id = b.process_id
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '5' MINUTE
GROUP BY a.hostname, a.process_id;
