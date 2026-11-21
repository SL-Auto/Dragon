-- source_yaral: detections/ligolo-ng/yaral/ligolo_websocket_default_user_agent.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: ligolo_websocket_default_user_agent
-- severity: low
-- procedure_ids: LG-P01
-- description: Detects HTTP requests carrying Ligolo-ng's hard-coded default WebSocket User-Agent (Chrome 103 on Windows 10 x64) from a source that is not a browser process. Current browsers auto-update far beyond Chrome 103, so this static string is anomalous.
-- log_source_prerequisites: Web proxy, NDR or EDR NETWORK_HTTP events with the User-Agent header and source host or IP; the initiating process image where available.
-- false_positives: Legacy embedded browsers or kiosk devices pinned to Chrome 103, and scripts or tools that copy this User-Agent.
-- references: reports/ligolo-ng/source-analysis.md#evidence; reviews/ligolo-ng/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, source_ip, user_agent, target_host, process_path); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, source_ip, user_agent, target_host, process_path.
SELECT source_ip, COUNT(*) AS matched_count, 'ligolo_websocket_default_user_agent' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'NETWORK_HTTP'
  AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '\\(chrome|msedge|brave|opera|vivaldi|firefox)\.exe$', 'i')
GROUP BY source_ip
HAVING COUNT(*) >= 1;
