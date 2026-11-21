-- source_yaral: detections/roadtools/yaral/roadtools_federated_credential_sp_signin.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_federated_credential_sp_signin
-- severity: medium
-- procedure_ids: RT-P07
-- description: Detects service-principal sign-ins that authenticate with a federated identity credential (client assertion from an external issuer) from an IP outside Azure and GitHub-style workload ranges, consistent with an attacker-run OIDC issuer.
-- log_source_prerequisites: Entra ID sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) normalized with the log name in metadata.product_event_type, UPN or service principal in principal.user.userid, IP in principal.ip, userAgent in network.http.user_agent, and appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, sessionId and resultType in additional.fields; clientCredentialType in additional.fields['clientCredentialType'] and the issuer in additional.fields['federatedCredentialIssuer'].
-- false_positives: New CI/CD integrations with external OIDC issuers.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, client_credential_type, federated_issuer); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by user_id and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, user_id, source_ip, user_agent, app_id, resource_id, auth_protocol, incoming_token_type, result_type, client_credential_type, federated_issuer.
SELECT user_id, COUNT(*) AS matched_count, 'roadtools_federated_credential_sp_signin' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type = 'AADServicePrincipalSignInLogs'
  AND REGEXP_LIKE(client_credential_type, 'federatedIdentityCredential', 'i')
  AND NOT REGEXP_LIKE(COALESCE(federated_issuer, ''), '(token\.actions\.githubusercontent\.com|sts\.windows\.net|login\.microsoftonline\.com|accounts\.google\.com|oidc\.eks\.|gitlab\.com)', 'i')
GROUP BY user_id
HAVING COUNT(*) >= 1;
