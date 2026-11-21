-- source_yaral: detections/roadtools/yaral/roadtools_scripting_user_agent_signin.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_scripting_user_agent_signin
-- severity: medium
-- procedure_ids: RT-P01,RT-P04,RT-P06,RT-P07,RT-P10,RT-P11
-- description: Detects user or service-principal sign-ins, or Graph requests, whose user agent is a Python HTTP library default (python-requests or aiohttp), as used by ROADtools when no user agent is chosen.
-- log_source_prerequisites: Entra ID sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) normalized with the log name in metadata.product_event_type, UPN or service principal in principal.user.userid, IP in principal.ip, userAgent in network.http.user_agent, and appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, sessionId and resultType in additional.fields; MicrosoftGraphActivityLogs with UserAgent.
-- false_positives: Approved Python automation and service principals; security tooling.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_scripting_user_agent_signin' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type IN ('SigninLogs', 'AADNonInteractiveUserSignInLogs', 'AADServicePrincipalSignInLogs', 'MicrosoftGraphActivityLogs')
  AND REGEXP_LIKE(user_agent, '(python-requests/|aiohttp/|Python/[0-9.]+ aiohttp)', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 1;
