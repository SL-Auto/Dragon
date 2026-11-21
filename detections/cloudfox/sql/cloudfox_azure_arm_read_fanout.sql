-- source_yaral: detections/cloudfox/yaral/cloudfox_azure_arm_read_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_azure_arm_read_fanout
-- severity: medium
-- procedure_ids: CF-Z01,CF-Z02,CF-Z03,CF-Z04
-- description: Detects one Azure caller reading resources from five or more distinct resource providers within 30 minutes, the breadth of automated tenant enumeration including runbook content and VM user data.
-- log_source_prerequisites: ARM read-plane telemetry (product event type AZURE_RESOURCE_READ, the same normalized label used by the BloodHound rules) with caller and resource provider in additional.fields['resource_provider']; the default Activity Log does not record reads.
-- false_positives: Defender for Cloud, CSPM, inventory and governance tooling.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, caller, resource_provider); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by caller and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, caller, resource_provider.
SELECT caller, COUNT(DISTINCT resource_provider) AS matched_count, 'cloudfox_azure_arm_read_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_event_type = 'AZURE_RESOURCE_READ'
GROUP BY caller
HAVING COUNT(DISTINCT resource_provider) >= 5;
