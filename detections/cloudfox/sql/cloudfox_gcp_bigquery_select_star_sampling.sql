-- source_yaral: detections/cloudfox/yaral/cloudfox_gcp_bigquery_select_star_sampling.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_gcp_bigquery_select_star_sampling
-- severity: high
-- procedure_ids: CF-G03
-- description: Detects one GCP principal running BigQuery query jobs of the form SELECT * FROM project.dataset.table LIMIT n against two or more tables within 30 minutes, the shape of automated sensitive-data sampling.
-- log_source_prerequisites: GCP Cloud Audit Logs normalized with methodName in metadata.product_event_type, serviceName in target.application, resourceName in target.resource.name and principalEmail in principal.user.email_addresses; BigQuery job query text in additional.fields['query'].
-- false_positives: Data-catalog profilers, DLP scanners and analysts previewing tables; approve their service accounts.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, principal_email, query); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_email and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, principal_email, query.
SELECT principal_email, COUNT(DISTINCT query) AS matched_count, 'cloudfox_gcp_bigquery_select_star_sampling' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '(jobservice\.insert|JobService\.InsertJob|jobs\.insert)', 'i')
  AND REGEXP_LIKE(query, '^\s*SELECT\s+\*\s+FROM\s+`[^`]+\.[^`]+\.[^`]+`\s+LIMIT\s+\d+\s*$', 'i')
GROUP BY principal_email
HAVING COUNT(DISTINCT query) >= 2;
