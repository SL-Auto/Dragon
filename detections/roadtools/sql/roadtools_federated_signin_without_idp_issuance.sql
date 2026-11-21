-- source_yaral: detections/roadtools/yaral/roadtools_federated_signin_without_idp_issuance.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: unsupported
-- rule_name: roadtools_federated_signin_without_idp_issuance
-- severity: medium
-- procedure_ids: RT-P09
-- description: Detects a federated (SAML or WS-Federation) Entra sign-in for a user with no corresponding token-issuance event on the organization's AD FS within 10 minutes, consistent with a forged SAML token.
-- log_source_prerequisites: Entra ID sign-in logs (SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) normalized with the log name in metadata.product_event_type, UPN or service principal in principal.user.userid, IP in principal.ip, userAgent in network.http.user_agent, and appId, resourceId, authenticationProtocol, incomingTokenType, deviceId, sessionId and resultType in additional.fields; AD FS Security auditing events 1200 or 1202 (token issued) normalized with the user in principal.user.userid.
-- false_positives: AD FS audit gaps, multiple identity providers and clock skew.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- assumptions_and_gaps: Target draft does not safely reproduce canonical absence logic; implement only after confirming complete source coverage and time semantics.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'roadtools_federated_signin_without_idp_issuance' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('1200', '1202', 'SigninLogs') OR event_type IN ('1200', '1202', 'SigninLogs')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
