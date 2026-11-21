-- source_yaral: detections/bloodhound/yaral/bloodhound_ldap_deep_single_category_enumeration.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: bloodhound_ldap_deep_single_category_enumeration
-- severity: high
-- procedure_ids: BH-002,BH-004
-- description: Detects a single identity on one client host retrieving a high volume of distinct directory objects within one naming context over a four-hour window, compensating for single-category or throttled collection that stays under the multi-category fanout threshold of bloodhound_ldap_directory_discovery_fanout.
-- log_source_prerequisites: Directory-side or EDR LDAP_SEARCH/1644 events expanded to per-result object identity (result_object_id label), with client host, account and naming context; summary-only query events cannot satisfy this rule (see reviews/bloodhound/detection-review.md#bh-dr-10).
-- false_positives: Identity governance, directory synchronization, migration tooling and authorized security assessment performing bulk single-category export.
-- references: reports/bloodhound/source-analysis.md, public-rules/comparisons/bloodhound/bloodhound_ldap_directory_discovery_fanout.md, reviews/bloodhound/detection-review.md#bh-dr-10
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: principal.hostname->src_host/SrcHostname/hostname/source.address; principal.user.userid->user/ActorUsername/user_id/user.id; labels.naming_context->naming_context/NamingContext; labels.result_object_id->result_object_id/ResultObjectId; target.hostname->dest/DvcHostname
-- assumptions_and_gaps: Native distinct-count aggregation per host/user/naming context. Canonical 4h hop window is approximated by a schedule of every 60 minutes over the trailing 4 hours. Requires the per-result object expansion described in BH-DR-10. Interval syntax is dialect-specific.
-- Schema assumption: normalized_events(event_time, product_event_type, hostname, user_id, target_hostname, naming_context, result_object_id).
SELECT hostname, user_id, naming_context,
       COUNT(DISTINCT result_object_id) AS objects,
       MIN(event_time) AS first_seen, MAX(event_time) AS last_seen,
       'bloodhound_ldap_deep_single_category_enumeration' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('LDAP_SEARCH', '1644')
  AND event_time >= CURRENT_TIMESTAMP - INTERVAL '4' HOUR
  AND naming_context IS NOT NULL
  AND result_object_id IS NOT NULL
GROUP BY hostname, user_id, naming_context
HAVING COUNT(DISTINCT result_object_id) >= 500;
