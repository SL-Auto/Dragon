-- source_yaral: detections/scoutsuite/yaral/scoutsuite_kubernetes_cluster_wide_secret_and_resource_list.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: scoutsuite_kubernetes_cluster_wide_secret_and_resource_list
-- severity: high
-- procedure_ids: SS-P04
-- description: Detects one Kubernetes identity listing Secrets cluster-wide together with ten or more other resource kinds within 10 minutes, the dynamic full-cluster listing that ScoutSuite performs.
-- log_source_prerequisites: Kubernetes API audit logs (EKS, AKS or GKE control-plane logging) normalized with verb and resource in metadata.product_event_type (for example list secrets), user in principal.user.userid and resource kind in additional.fields['resource'].
-- false_positives: Backup operators (Velero), GitOps controllers and cluster-wide security scanners.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, resource); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 5 minutes over the trailing 10 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, resource.
SELECT user_id, COUNT(DISTINCT resource) AS matched_count, 'scoutsuite_kubernetes_cluster_wide_secret_and_resource_list' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  AND REGEXP_LIKE(product_event_type, '^list', 'i')
GROUP BY user_id
HAVING COUNT(DISTINCT resource) >= 11;
