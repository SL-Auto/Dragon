-- source_yaral: detections/cloudfox/yaral/cloudfox_aws_programmatic_assumerole_history_lookup.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: cloudfox_aws_programmatic_assumerole_history_lookup
-- severity: low
-- procedure_ids: CF-A07
-- description: Detects programmatic (non-console) cloudtrail:LookupEvents filtered to AssumeRole, used to learn which roles have been assumed from the account.
-- log_source_prerequisites: AWS CloudTrail management events normalized with metadata.product_name = 'AWS CloudTrail', eventName in metadata.product_event_type, eventSource in target.application, userIdentity ARN in principal.user.userid; requestParameters.lookupAttributes serialized in additional.fields['lookupAttributes'] and userAgent in network.http.user_agent.
-- false_positives: Security analysts and SOAR playbooks querying CloudTrail history via SDK.
-- references: reports/cloudfox/source-analysis.md#procedure-analysis; reviews/cloudfox/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, lookup_attributes); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by principal_arn and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_name, product_event_type, principal_arn, event_source, source_ip, user_agent, lookup_attributes.
SELECT principal_arn, COUNT(*) AS matched_count, 'cloudfox_aws_programmatic_assumerole_history_lookup' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_name = 'AWS CloudTrail'
  AND product_event_type = 'LookupEvents'
  AND REGEXP_LIKE(lookup_attributes, 'AssumeRole', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_agent, ''), '(console\.amazonaws\.com|signin\.amazonaws\.com|AWS Internal)', 'i')
GROUP BY principal_arn
HAVING COUNT(*) >= 1;
