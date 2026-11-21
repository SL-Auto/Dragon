-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_dns_process_context_compensating_signal.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cobalt_strike_dns_process_context_compensating_signal
-- severity: medium
-- procedure_ids: CSB-006
-- description: Detects repeated process-attributed TXT/NULL-type DNS queries to domains flagged as rare by baseline enrichment, covering low-volume record-type-specific tunneling exchanges that the length/entropy-based base rule does not filter by record type.
-- log_source_prerequisites: Normalize process-attributed NETWORK_DNS (for example Sysmon 22 or EDR DNS events; DNS Client service-attributed resolver logs cannot attribute the requesting process) with host, process ID, query name/type, and a domain-rarity baseline enrichment field.
-- false_positives: Mail-security appliances and anti-abuse services performing bulk legitimate TXT lookups against rare or newly observed domains; the rarity enrichment must be tenant-tuned before enabling.
-- references: reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_dns_process_context.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_id, dns_query, dns_type, domain_baseline_rarity); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_id and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_id, dns_query, dns_type, domain_baseline_rarity.
SELECT hostname, process_id, COUNT(DISTINCT dns_query) AS matched_count, 'cobalt_strike_dns_process_context_compensating_signal' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND event_type IN ('NETWORK_DNS', 'DNS_QUERY')
  AND ((dns_type = 16) OR (dns_type = 10))
  AND domain_baseline_rarity = 'RARE'
GROUP BY hostname, process_id
HAVING COUNT(DISTINCT dns_query) >= 8;
