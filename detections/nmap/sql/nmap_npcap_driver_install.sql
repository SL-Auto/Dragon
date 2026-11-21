-- source_yaral: detections/nmap/yaral/nmap_npcap_driver_install.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: nmap_npcap_driver_install
-- severity: medium
-- procedure_ids: NM-P14
-- description: Detects installation or first load of the Npcap packet-capture driver (service or driver named npcap, or a driver signed by Insecure.Com LLC), which the Nmap Windows installer bundles for raw scanning.
-- log_source_prerequisites: Windows System 7045 (service installed) and Sysmon Event ID 6 (driver loaded, DRIVER_LOAD) with service or image name and signer.
-- false_positives: Wireshark and network-troubleshooting installations by administrators.
-- references: reports/nmap/source-analysis.md#procedure-analysis; reviews/nmap/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, service_name, target_path, signer); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, service_name, target_path, signer.
SELECT hostname, COUNT(*) AS matched_count, 'nmap_npcap_driver_install' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND ((product_event_type = '7045' AND REGEXP_LIKE(service_name, '^npcap', 'i')) OR (product_event_type = '6' AND REGEXP_LIKE(target_path, '\\npcap\.sys$', 'i')) OR (product_event_type = '6' AND REGEXP_LIKE(signer, 'Insecure\.Com', 'i')))
GROUP BY hostname
HAVING COUNT(*) >= 1;
