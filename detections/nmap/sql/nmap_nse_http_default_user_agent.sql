-- source_yaral: detections/nmap/yaral/nmap_nse_http_default_user_agent.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_nse_http_default_user_agent
-- severity: medium
-- procedure_ids: NM-P08,NM-P10
-- description: Detects HTTP requests carrying the Nmap Scripting Engine's default User-Agent, which names the engine and its documentation URL.
-- log_source_prerequisites: Web server, reverse proxy, WAF, forward proxy or NDR NETWORK_HTTP events with User-Agent and source IP.
-- false_positives: Authorized vulnerability scans using default NSE settings.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, source_ip, user_agent, target_host); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, source_ip, user_agent, target_host.
SELECT source_ip, COUNT(*) AS matched_count, 'nmap_nse_http_default_user_agent' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND event_type = 'NETWORK_HTTP'
  AND REGEXP_LIKE(user_agent, 'Nmap Scripting Engine', 'i')
GROUP BY source_ip
HAVING COUNT(*) >= 1;
