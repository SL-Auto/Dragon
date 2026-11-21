-- source_yaral: detections/pacu/yaral/pacu_snapshot_and_database_takeover.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: pacu_snapshot_and_database_takeover
-- severity: high
-- procedure_ids: PA-P10
-- description: Detects one principal resetting an RDS master password (ModifyDBInstance with MasterUserPassword), or performing two or more snapshot-access steps (RDS snapshot creation or restore, EBS volume creation from snapshot, volume attachment, EBS direct snapshot reads) within 30 minutes.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; requestParameters keys in additional.fields; EBS direct API data events enabled for ListSnapshotBlocks and GetSnapshotBlock.
-- false_positives: Database administrators and backup or disaster-recovery automation.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_parameter_keys); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_parameter_keys.
SELECT principal_arn, COUNT(DISTINCT product_event_type) AS matched_count, 'pacu_snapshot_and_database_takeover' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND ((product_event_type = 'ModifyDBInstance' AND REGEXP_LIKE(request_parameter_keys, 'masterUserPassword', 'i')) OR (product_event_type IN ('CreateDBSnapshot', 'RestoreDBInstanceFromDBSnapshot', 'CreateVolume', 'AttachVolume', 'ListSnapshotBlocks', 'GetSnapshotBlock')))
GROUP BY principal_arn
HAVING COUNT(DISTINCT product_event_type) >= 2;
