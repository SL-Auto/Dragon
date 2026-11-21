-- source_yaral: detections/pacu/yaral/pacu_iam_credential_backdoor_other_user.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: pacu_iam_credential_backdoor_other_user
-- severity: high
-- procedure_ids: PA-P03,PA-P04
-- description: Detects an IAM principal creating an access key or console login profile for a different IAM user (CreateAccessKey, CreateLoginProfile or UpdateLoginProfile where the target user differs from the caller).
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; requestParameters.userName in target.user.userid and userIdentity.userName in principal.user.user_display_name.
-- false_positives: Identity administrators and automation that provision user credentials; approve their ARNs.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'pacu_iam_credential_backdoor_other_user' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile') OR event_type IN ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
