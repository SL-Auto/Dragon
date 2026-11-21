-- source_yaral: detections/impacket/yaral/impacket_terminal_services_session_control_by_other_actor.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: impacket_terminal_services_session_control_by_other_actor
-- severity: high
-- procedure_ids: IMP-18
-- description: Detects a Terminal Services session connect, disconnect, reconnect or logoff control action performed by a principal different from the session's own target user, consistent with remote session hijack or tscon-style session takeover.
-- log_source_prerequisites: Terminal Services Operational and Security session events (4778/4779/23/24/25) with both a populated principal (acting) and target (session-owning) user identity.
-- false_positives: Helpdesk-initiated session shadowing/takeover, session broker or load-balancer service accounts, and RDS farm reconnection performed under a management service identity.
-- references: reports/impacket/source-analysis.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, user_id, target_user); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. The canonical field-to-field inequality (acting user differs from session owner) is expressed natively in SPL/KQL/SQL below; Sigma cannot compare two fields and EQL cannot aggregate. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, user_id, target_user.
SELECT hostname, COUNT(*) AS matched_count, 'impacket_terminal_services_session_control_by_other_actor' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND user_id IS NOT NULL AND target_user IS NOT NULL AND user_id <> target_user
  AND product_event_type IN ('4778', '4779', '23', '24', '25')
GROUP BY hostname
HAVING COUNT(*) >= 1;
