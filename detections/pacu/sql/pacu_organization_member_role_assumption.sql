-- source_yaral: detections/pacu/yaral/pacu_organization_member_role_assumption.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_organization_member_role_assumption
-- severity: high
-- procedure_ids: PA-P09
-- description: Detects one principal assuming the OrganizationAccountAccessRole in two or more member accounts within 1 hour.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; the assumed role ARN in target.resource.name and the member account in target.cloud.project.name.
-- false_positives: Organization administrators and landing-zone automation.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, account_id); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, account_id.
SELECT principal_arn, COUNT(DISTINCT account_id) AS matched_count, 'pacu_organization_member_role_assumption' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'AssumeRole'
  AND REGEXP_LIKE(resource_name, ':role/OrganizationAccountAccessRole$', 'i')
GROUP BY principal_arn
HAVING COUNT(DISTINCT account_id) >= 2;
