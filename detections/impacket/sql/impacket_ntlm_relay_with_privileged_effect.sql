-- source_yaral: detections/impacket/yaral/impacket_ntlm_relay_with_privileged_effect.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: impacket_ntlm_relay_with_privileged_effect
-- severity: critical
-- procedure_ids: IMP-21
-- description: Correlates NTLM authentication (4624/4776) with a privileged target-side effect (service install, account/group change, or AD authorization change) by the same account on the same host, requiring the target-side effect that the base cross-source relay rule does not.
-- log_source_prerequisites: Normalized Windows Security 4624 network logons (LogonType 3) with AuthenticationPackageName, target host, target account and source IP, correlated on the same host and acting account with service (4697/7045), account/group (4720-4757 family) or AD-authorization change (5136/5137) events. 4776 is DC-side credential validation and is not used because its host is the validating DC, not the relay target.
-- false_positives: Administrators who authenticate and then immediately perform routine privileged administration on the same host within the correlation window.
-- references: reports/impacket/source-analysis.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, target_host, user_id, target_user, LogonType, AuthenticationPackageName, source_ip); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on target_host, acting_user within 5 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, target_host, user_id, target_user, LogonType, AuthenticationPackageName, source_ip.
WITH first_leg AS (
  SELECT *, target_user AS acting_user FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND product_event_type = '4624'
    AND LogonType = '3'
    AND REGEXP_LIKE(AuthenticationPackageName, '^NTLM$', 'i')
 ),
second_leg AS (
  SELECT *, user_id AS acting_user FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
    AND product_event_type IN ('4697', '7045', '4720', '4722', '4723', '4724', '4725', '4726', '4738', '4741', '4742', '4743', '4728', '4729', '4732', '4733', '4756', '4757', '5136', '5137')
)
SELECT a.target_host, a.acting_user, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'impacket_ntlm_relay_with_privileged_effect' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.target_host = b.target_host
 AND a.acting_user = b.acting_user
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '5' MINUTE
GROUP BY a.target_host, a.acting_user;
