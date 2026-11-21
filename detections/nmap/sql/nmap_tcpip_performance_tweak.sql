-- source_yaral: detections/nmap/yaral/nmap_tcpip_performance_tweak.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_tcpip_performance_tweak
-- severity: medium
-- procedure_ids: NM-P14
-- description: Detects the Nmap installer's optional TCP/IP performance change: regedt32 /S importing nmap_performance.reg, or writes of MaxUserPort or TcpTimedWaitDelay under the Tcpip Parameters key.
-- log_source_prerequisites: REGISTRY_MODIFICATION telemetry (Sysmon Event ID 13 or EDR) with key and value name, and PROCESS_LAUNCH with command line.
-- false_positives: Server tuning by administrators for high-connection workloads.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, registry_key, registry_value, command_line); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, registry_key, registry_value, command_line.
SELECT hostname, COUNT(*) AS matched_count, 'nmap_tcpip_performance_tweak' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND ((event_type = 'REGISTRY_MODIFICATION' AND REGEXP_LIKE(registry_key, '\\Services\\Tcpip\\Parameters$', 'i') AND REGEXP_LIKE(registry_value, '^(MaxUserPort|TcpTimedWaitDelay)$', 'i')) OR (event_type = 'PROCESS_LAUNCH' AND REGEXP_LIKE(command_line, 'regedt32(\.exe)?\"?\s+/S\s+.*nmap_performance\.reg', 'i')))
GROUP BY hostname
HAVING COUNT(*) >= 1;
