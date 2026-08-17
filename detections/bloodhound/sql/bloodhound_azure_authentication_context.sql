-- source_yaral: detections/bloodhound/yaral/bloodhound_azure_authentication_context.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: bloodhound_azure_authentication_context
-- severity: medium
-- procedure_ids: BH-016
-- description: Detects a sign-in followed by broad Graph or ARM read activity from the same principal and source.
-- log_source_prerequisites: Entra interactive/service-principal sign-ins and Graph/ARM audit with principal/app, source IP and correlation identifiers.
-- false_positives: Cloud inventory, governance, CSPM and authorized assessment.
-- references: reports/bloodhound/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'bloodhound_azure_authentication_context' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('AADServicePrincipalSignInLogs', 'AZURE_RESOURCE_READ', 'MicrosoftGraphActivityLogs', 'SigninLogs') OR event_type IN ('AADServicePrincipalSignInLogs', 'AZURE_RESOURCE_READ', 'MicrosoftGraphActivityLogs', 'SigninLogs')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
