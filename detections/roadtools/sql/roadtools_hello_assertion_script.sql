-- source_yaral: detections/roadtools/yaral/roadtools_hello_assertion_script.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: roadtools_hello_assertion_script
-- severity: medium
-- procedure_ids: RT-P13
-- description: Detects PowerShell script blocks that request Windows Hello or WebAuthn assertions through native APIs, as in the ROADtools Windows Hello assertion scripts.
-- log_source_prerequisites: PowerShell script-block logging (Event 4104) normalized with ScriptBlockText in additional.fields['ScriptBlockText'] and host.
-- false_positives: Security research and authorized testing.
-- references: reports/roadtools/source-analysis.md#procedure-analysis; reviews/roadtools/detection-review.md
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: normalized columns (product_event_type, hostname, user_id, script_block_text); EQL uses ECS equivalents; enrichment columns map from UDM additional.fields / labels of the same name
-- assumptions_and_gaps: Native filter, grouping by hostname and threshold. Hop window approximated by scheduling every 20 minutes over the trailing 60 minutes. Regex and interval syntax are dialect-specific.
-- Schema assumption: normalized_events with columns event_time, product_event_type, hostname, user_id, script_block_text.
SELECT hostname, COUNT(*) AS matched_count, 'roadtools_hello_assertion_script' AS canonical_rule
FROM normalized_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '60' MINUTE
  AND product_event_type = '4104'
  AND REGEXP_LIKE(script_block_text, '(WebAuthNAuthenticatorGetAssertion|webauthn\.dll|Microsoft Passport Key Storage Provider|NCryptSignHash)', 'i')
GROUP BY hostname
HAVING COUNT(*) >= 1;
