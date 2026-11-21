-- source_yaral: detections/nmap/yaral/nmap_reverse_dns_ptr_burst.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_reverse_dns_ptr_burst
-- severity: medium
-- procedure_ids: NM-P07
-- description: Detects one process issuing reverse DNS (PTR) queries for one hundred or more distinct in-addr.arpa or ip6.arpa names within 5 minutes, the default mass reverse resolution after host discovery.
-- log_source_prerequisites: Process-attributed DNS query telemetry (Sysmon Event ID 22 or EDR NETWORK_DNS) with query name, host and process ID.
-- false_positives: Network monitoring and logging tools that reverse-resolve many addresses; approve their images.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, process_path, dns_query); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 5 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, process_path, dns_query.
SELECT hostname, process_id, COUNT(DISTINCT dns_query) AS matched_count, 'nmap_reverse_dns_ptr_burst' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '5' MINUTE
  AND event_type = 'NETWORK_DNS'
  AND REGEXP_LIKE(dns_query, '\.(in-addr|ip6)\.arpa\.?$', 'i')
GROUP BY hostname, process_id
HAVING COUNT(DISTINCT dns_query) >= 100;
