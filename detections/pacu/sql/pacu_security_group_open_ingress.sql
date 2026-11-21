-- source_yaral: detections/pacu/yaral/pacu_security_group_open_ingress.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_security_group_open_ingress
-- severity: medium
-- procedure_ids: PA-P06
-- description: Detects one principal authorizing security-group ingress from any address (0.0.0.0/0 or ::/0) on three or more security groups within 30 minutes.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; requestParameters serialized in additional.fields['ipPermissions'] and groupId in target.resource.name.
-- false_positives: Development environments and load-balancer onboarding scripts.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, ip_permissions); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, ip_permissions.
SELECT principal_arn, COUNT(DISTINCT resource_name) AS matched_count, 'pacu_security_group_open_ingress' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'AuthorizeSecurityGroupIngress'
  AND REGEXP_LIKE(ip_permissions, '(0\.0\.0\.0/0|::/0)', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT resource_name) >= 3;
