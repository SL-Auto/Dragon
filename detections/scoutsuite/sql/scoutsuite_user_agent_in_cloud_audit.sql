-- source_yaral: detections/scoutsuite/yaral/scoutsuite_user_agent_in_cloud_audit.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: scoutsuite_user_agent_in_cloud_audit
-- severity: high
-- procedure_ids: SS-P01,SS-P02,SS-P03,SS-P05
-- description: Detects cloud API activity whose user agent contains ScoutSuite's self-identifying string (Scout Suite/<version> with the project URL), recorded by AWS CloudTrail, GCP Cloud Audit Logs (callerSuppliedUserAgent), OCI Audit or Alibaba ActionTrail.
-- log_source_prerequisites: Cloud audit events (AWS CloudTrail, GCP Cloud Audit Logs, OCI Audit, Alibaba ActionTrail) normalized with the request user agent in network.http.user_agent and the caller in principal.user.userid.
-- false_positives: Authorized security-posture assessments run with ScoutSuite.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (principal_id, user_agent, event_source, source_ip); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, principal_id, user_agent, event_source, source_ip.
SELECT principal_id, COUNT(*) AS matched_count, 'scoutsuite_user_agent_in_cloud_audit' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND REGEXP_LIKE(user_agent, 'Scout ?Suite/[0-9]', 'i')
GROUP BY principal_id
HAVING COUNT(*) >= 1;
