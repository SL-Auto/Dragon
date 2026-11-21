-- source_yaral: detections/pacu/yaral/pacu_instance_userdata_modify_restart.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: pacu_instance_userdata_modify_restart
-- severity: high
-- procedure_ids: PA-P09
-- description: Detects one principal modifying an EC2 instance's user data and starting that instance within 30 minutes, which executes the new user data at boot.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, userIdentity ARN in principal.user.userid, userAgent in network.http.user_agent and requestParameters in additional.fields; requestParameters attribute in additional.fields['attribute'] and instanceId in target.resource.name; userIdentity.invokedBy in additional.fields (service-invoked changes excluded, PA-DR-10).
-- false_positives: Configuration changes during maintenance by instance owners.
-- references: reports/pacu/source-analysis.md#procedure-analysis; reviews/pacu/detection-review.md; public-rules/comparisons/pacu/pacu_instance_userdata_modify_restart.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_attribute, invoked_by); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native ordered two-event correlation on principal_arn, resource_name within 30 minutes (first event before second). Exact per-pair self-join; regex, REGEXP_SUBSTR and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, resource_name, request_attribute, invoked_by.
WITH first_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND product_name = 'AWS CloudTrail'
    AND product_event_type = 'ModifyInstanceAttribute'
    AND REGEXP_LIKE(request_attribute, 'userData', 'i')
    AND NOT REGEXP_LIKE(COALESCE(invoked_by, ''), '(AWS Internal|\.amazonaws\.com)$', 'i')
 ),
second_leg AS (
  SELECT * FROM normalized_events
  WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
    AND product_name = 'AWS CloudTrail'
    AND product_event_type = 'StartInstances'
)
SELECT a.principal_arn, a.resource_name, MIN(a.event_time) AS first_time, MAX(b.event_time) AS last_time, 'pacu_instance_userdata_modify_restart' AS canonical_rule
FROM first_leg a
JOIN second_leg b
  ON a.principal_arn = b.principal_arn
 AND a.resource_name = b.resource_name
 AND b.event_time BETWEEN a.event_time AND a.event_time + INTERVAL '30' MINUTE
GROUP BY a.principal_arn, a.resource_name;
