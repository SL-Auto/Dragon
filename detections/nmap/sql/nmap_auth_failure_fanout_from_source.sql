-- source_yaral: detections/nmap/yaral/nmap_auth_failure_fanout_from_source.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: nmap_auth_failure_fanout_from_source
-- severity: medium
-- procedure_ids: NM-P09
-- description: Detects one source IP producing authentication failures for ten or more distinct accounts, or against five or more hosts, within 10 minutes, the target-side effect of NSE brute-force and default-credential scripts.
-- log_source_prerequisites: Windows Security 4625 and 4771 (and service authentication failures normalized as USER_LOGIN with security_result.action BLOCK) with source IP, target account and target host.
-- false_positives: Misconfigured services retrying stale credentials, password-audit tools and shared NAT sources.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, product_event_type, source_ip, target_user, target_host, action); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by source_ip and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, product_event_type, source_ip, target_user, target_host, action.
SELECT source_ip, COUNT(DISTINCT target_user) AS matched_count, 'nmap_auth_failure_fanout_from_source' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND ((product_event_type IN ('4625', '4771')) OR (event_type = 'USER_LOGIN' AND action = 'BLOCK'))
GROUP BY source_ip
HAVING COUNT(DISTINCT target_user) >= 10;
