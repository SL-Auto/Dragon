-- source_yaral: detections/impacket/yaral/impacket_new_machine_account_s4u.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: impacket_new_machine_account_s4u
-- severity: high
-- procedure_ids: IMP-07,IMP-11,IMP-22
-- description: Detects a newly created computer account requesting S4U (protocol-transition or constrained-delegation) service tickets within one hour of its creation, proving that the object created in the directory participates in the later ticket path. This is the resource-based constrained delegation chain: account creation, delegation configuration, then S4U ticket requests as the new account.
-- log_source_prerequisites: Domain-controller Security 4741 (computer account created; new account in target.user.userid) and 4769 (requesting account in target.user.userid) with S4U context in the description, a structured delegation_flow field, or TransmittedServices, from every DC.
-- false_positives: Provisioning or middleware that creates a computer account and immediately configures it for constrained delegation; approve those service accounts after validation.
-- references: reports/impacket/source-analysis.md#imp-22; public-rules/comparisons/impacket/impacket_privilege_path_effects.md; reviews/impacket/detection-review.md#review-014
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, target_user, service_name, source_ip, description, delegation_flow, TransmittedServices); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on target_user within 60 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, target_user, service_name, source_ip, description, delegation_flow, TransmittedServices.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '120' MINUTE
    AND product_event_type = '4741'
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '120' MINUTE
    AND product_event_type = '4769'
    AND ((REGEXP_LIKE(description, '(S4U2Self|S4U2Proxy|protocol transition|transited services)', 'i')) OR (REGEXP_LIKE(delegation_flow, '^(S4U2Self|S4U2Proxy)$', 'i')) OR (REGEXP_LIKE(TransmittedServices, '[A-Za-z0-9]', 'i')))
)
SELECT a.target_user, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'impacket_new_machine_account_s4u' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.target_user = b.target_user
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '60' MINUTE
GROUP BY a.target_user;
