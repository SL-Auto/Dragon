-- source_yaral: detections/cobalt-strike-beacon/yaral/cobalt_strike_user_data_collection.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: cobalt_strike_user_data_collection
-- severity: high
-- procedure_ids: CSB-027
-- description: Surfaces vendor collection telemetry for screen, clipboard, input or browser-secret access by an uncommon process.
-- log_source_prerequisites: Normalize EDR SCREEN_CAPTURE, CLIPBOARD_READ, INPUT_CAPTURE or BROWSER_SECRET_READ with process, user/session, collection type and signer/prevalence.
-- false_positives: Accessibility, conferencing, remote support, password managers, browsers and approved monitoring.
-- references: reports/cobalt-strike-beacon/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; map canonical UDM fields to the target schema and verify every predicate before enabling.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'cobalt_strike_user_data_collection' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('BROWSER_SECRET_READ', 'CLIPBOARD_READ', 'INPUT_CAPTURE', 'SCREEN_CAPTURE') OR event_type IN ('BROWSER_SECRET_READ', 'CLIPBOARD_READ', 'INPUT_CAPTURE', 'SCREEN_CAPTURE')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
