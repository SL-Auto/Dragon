-- source_yaral: detections/scoutsuite/yaral/scoutsuite_aws_userdata_and_credential_report_sweep.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: scoutsuite_aws_userdata_and_credential_report_sweep
-- severity: high
-- procedure_ids: SS-P01
-- description: Detects one AWS principal reading EC2 user data for three or more instances and generating or retrieving the IAM credential report within 30 minutes, the secret-bearing reads of a ScoutSuite AWS audit.
-- log_source_prerequisites: AWS CloudTrail management events with eventName in metadata.product_event_type, requestParameters.attribute in additional.fields['attribute'], instanceId in target.resource.name and userIdentity ARN in principal.user.userid.
-- false_positives: Posture tooling and auditors.
-- references: reports/scoutsuite/source-analysis.md#procedure-analysis; reviews/scoutsuite/detection-review.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'scoutsuite_aws_userdata_and_credential_report_sweep' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('DescribeInstanceAttribute', 'GenerateCredentialReport', 'GetCredentialReport') OR event_type IN ('DescribeInstanceAttribute', 'GenerateCredentialReport', 'GetCredentialReport')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
