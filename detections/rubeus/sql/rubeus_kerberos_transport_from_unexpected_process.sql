-- source_yaral: detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: rubeus_kerberos_transport_from_unexpected_process
-- severity: high
-- procedure_ids: PROC-001,PROC-002,PROC-003,PROC-004,PROC-005,PROC-012
-- description: Detects a Windows process other than lsass.exe connecting to a Kerberos KDC (port 88) or the Kerberos password-change service (port 464). This is the client-side network effect of ticket requests, roasting, delegation abuse or password change performed by a tool that implements its own Kerberos transport instead of using the LSA.
-- log_source_prerequisites: Process-attributed network-connection telemetry (Sysmon Event ID 3 or EDR equivalent, NETWORK_CONNECTION) with destination port, host and initiating process image path. Windows hosts are identified by a drive-letter image path.
-- false_positives: Java and other cross-platform applications with their own Kerberos stack, MIT Kerberos for Windows, identity-synchronization and password-management agents, and authorized security assessment tools; approve them by image path and signer after validation. Domain controllers should be scoped separately if their KDC-to-KDC traffic is attributed to processes other than lsass.exe.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_unusual_kerberos_password_change.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; reviews/rubeus/detection-review.md#review-015
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (event_type, hostname, process_path, target_ip, target_port, user_id); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname, process_path and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, event_type, hostname, process_path, target_ip, target_port, user_id.
SELECT hostname, process_path, COUNT(*) AS matched_count, 'rubeus_kerberos_transport_from_unexpected_process' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND event_type = 'NETWORK_CONNECTION'
  AND ((target_port = 88) OR (target_port = 464))
  AND REGEXP_LIKE(process_path, '^[a-z]:\\', 'i')
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '^[a-z]:\\windows\\system32\\lsass\.exe$', 'i')
GROUP BY hostname, process_path
HAVING COUNT(*) >= 1;
