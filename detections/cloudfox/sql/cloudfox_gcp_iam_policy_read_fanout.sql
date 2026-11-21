-- source_yaral: detections/cloudfox/yaral/cloudfox_gcp_iam_policy_read_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_gcp_iam_policy_read_fanout
-- severity: medium
-- procedure_ids: CF-G01
-- description: Detects one GCP principal reading IAM policies (getIamPolicy) on ten or more distinct resources within 30 minutes.
-- log_source_prerequisites: GCP Cloud Audit Logs normalized with methodName in metadata.product_event_type, serviceName in target.application, resourceName in target.resource.name and principalEmail in principal.user.email_addresses; ADMIN_READ Data Access logs enabled for Resource Manager, IAM and the relevant services.
-- false_positives: Policy Analyzer, CSPM and IAM governance service accounts.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, principal_email, resource_name, service_name); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_email and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, principal_email, resource_name, service_name.
SELECT principal_email, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_gcp_iam_policy_read_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, 'GetIamPolicy$', 'i')
GROUP BY principal_email
HAVING COUNT(DISTINCT resource_name) >= 10;
