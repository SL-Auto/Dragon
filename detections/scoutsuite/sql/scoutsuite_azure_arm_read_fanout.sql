-- source_yaral: detections/scoutsuite/yaral/scoutsuite_azure_arm_read_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: scoutsuite_azure_arm_read_fanout
-- severity: medium
-- procedure_ids: SS-P02
-- description: Detects one Azure caller reading resources from eight or more resource providers within 30 minutes, the breadth of a ScoutSuite Azure audit.
-- log_source_prerequisites: ARM read-plane telemetry normalized as AZURE_RESOURCE_READ with caller in principal.user.userid and resource provider in additional.fields['resource_provider'].
-- false_positives: Defender for Cloud, CSPM and governance identities.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, caller, resource_provider); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by caller and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, caller, resource_provider.
SELECT caller, COUNT(DISTINCT resource_provider) AS matched_count, 'scoutsuite_azure_arm_read_fanout' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_event_type = 'AZURE_RESOURCE_READ'
GROUP BY caller
HAVING COUNT(DISTINCT resource_provider) >= 8;
