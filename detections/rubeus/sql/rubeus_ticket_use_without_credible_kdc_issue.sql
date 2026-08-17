-- source_yaral: detections/rubeus/yaral/rubeus_ticket_use_without_credible_kdc_issue.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_ticket_use_without_credible_kdc_issue
-- severity: high
-- procedure_ids: PROC-008,PROC-009
-- description: Detects anomalous Kerberos-authenticated service use without a corresponding observed service-ticket issue, gated on an explicit domain-controller collection-health signal.
-- log_source_prerequisites: Centralize complete 4769 telemetry and resource-side Kerberos service-use/PAC anomaly data with normalized user, source, and service, plus a collection-health event proving all authoritative domain controllers reported for the window.
-- false_positives: Missing DC logs, cached tickets, referrals, cross-realm activity, and parser mismatches; the collection-health gate mitigates but does not eliminate these.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_ticket_use_without_credible_kdc_issue.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend. The absence check (zero matching 4769 rows) and the required collection-health gate need a LEFT JOIN ... IS NULL anti-join plus an EXISTS check against the health event, not a plain WHERE filter.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_ticket_use_without_credible_kdc_issue' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4769', 'USER_LOGIN') OR event_type IN ('4769', 'USER_LOGIN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
