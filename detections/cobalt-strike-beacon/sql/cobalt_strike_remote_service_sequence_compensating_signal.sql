-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_remote_service_sequence_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_remote_service_sequence_compensating_signal
-- severity: high
-- procedure_ids: CSB-030
-- description: Correlates a file staged to a remote target with a subsequent System 7045 service install on that target whose service image file name equals the staged file name, tightening the base rule's looser source/account/host proximity join; file-name matching tolerates UNC versus local path forms.
-- log_source_prerequisites: Normalize FILE_CREATION/FILE_MODIFICATION written to a remote target host (SMB/admin-share write with source and target host and full path), and System 7045 on that target with the installed service image path, joined on source host, target host and image file name within 10 minutes, write first.
-- false_positives: Software distribution and endpoint-management tools that stage an installer to a share and then register it as a service using the identical path.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_remote_service_sequence.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, product_event_type, hostname, target_host, target_path, target_process_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on service_host, image_name within 10 minutes (first event before second). Joined on service host and image file name; the staging source host exists only on the write leg (as in the canonical rule, where $source is bound by the write event). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, product_event_type, hostname, target_host, target_path, target_process_path.
WITH first_leg AS (
  SELECT *, REGEXP_SUBSTR(target_path, '([^\\/]+\.(?:exe|dll|bat|cmd|ps1))$', 1, 1, 'i', 1) AS image_name, target_host AS service_host FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND event_type IN ('FILE_CREATION', 'FILE_MODIFICATION', 'FILE_WRITE')
 ),
second_leg AS (
  SELECT *, REGEXP_SUBSTR(target_process_path, '([^\\/\"\s]+\.(?:exe|dll|bat|cmd|ps1))', 1, 1, 'i', 1) AS image_name, hostname AS service_host FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '20' MINUTE
    AND product_event_type = '7045'
)
SELECT a.service_host, a.image_name, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'cobalt_strike_remote_service_sequence_compensating_signal' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.service_host = b.service_host
 AND a.image_name = b.image_name
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '10' MINUTE
GROUP BY a.service_host, a.image_name;
