-- source_yaral: detections/cloudfox/yaral/cloudfox_azure_app_settings_secret_list.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_azure_app_settings_secret_list
-- severity: high
-- procedure_ids: CF-Z04
-- description: Detects one caller listing App Service or Function App application settings or connection strings (Microsoft.Web/sites/config/list/action) on two or more sites within 30 minutes.
-- log_source_prerequisites: Azure Activity Log (administrative category) with operationName in metadata.product_event_type, caller in principal.user.userid and resourceId in target.resource.name.
-- false_positives: Deployment pipelines, App Service backup or migration tooling, and administrators using the portal configuration blade.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, caller, resource_name, source_ip); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by caller and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, caller, resource_name, source_ip.
SELECT caller, COUNT(DISTINCT resource_name) AS matched_count, 'cloudfox_azure_app_settings_secret_list' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '^MICROSOFT\.WEB/SITES/(SLOTS/)?CONFIG/LIST/ACTION$', 'i')
GROUP BY caller
HAVING COUNT(DISTINCT resource_name) >= 2;
