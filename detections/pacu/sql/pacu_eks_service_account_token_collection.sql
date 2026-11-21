-- source_yaral: detections/pacu/yaral/pacu_eks_service_account_token_collection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_eks_service_account_token_collection
-- severity: high
-- procedure_ids: PA-P15
-- description: Detects one identity reading Kubernetes service-account tokens or secrets across three or more namespaces within 30 minutes in EKS audit logs.
-- log_source_prerequisites: EKS control-plane audit logs normalized with verb and resource in metadata.product_event_type (for example get secrets, create serviceaccounts/token), user in principal.user.userid and namespace in target.namespace.
-- false_positives: Cluster administrators and secret-sync controllers.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, namespace); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 10 minutes over the trailing 30 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, namespace.
SELECT user_id, COUNT(DISTINCT namespace) AS matched_count, 'pacu_eks_service_account_token_collection' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND REGEXP_LIKE(product_event_type, '(get|list|watch|create).*(secrets|serviceaccounts/token)', 'i')
GROUP BY user_id
HAVING COUNT(DISTINCT namespace) >= 3;
