-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_privileged_context_change.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_privileged_context_change
-- severity: medium
-- procedure_ids: CSB-011
-- description: Surfaces special-privilege assignment or endpoint token-privilege modification by an uncommon process.
-- log_source_prerequisites: Normalize Windows 4672 or EDR TOKEN_PRIVILEGE_CHANGE with process, user, logon ID, privilege list and signer/prevalence.
-- false_positives: Services, installers, EDR, backup, forensic and administrative tools.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_privileged_context_change' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4672', 'TOKEN_PRIVILEGE_CHANGE') OR event_type IN ('4672', 'TOKEN_PRIVILEGE_CHANGE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
