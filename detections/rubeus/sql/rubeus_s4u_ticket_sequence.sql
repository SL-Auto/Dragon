-- source_yaral: detections/rubeus/yaral/rubeus_s4u_ticket_sequence.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: rubeus_s4u_ticket_sequence
-- severity: high
-- procedure_ids: PROC-005
-- description: Detects a service identity making S4U requests against an authoritatively unapproved delegation edge, or requesting S4U tickets across multiple distinct target services when edge-approval enrichment is unavailable.
-- log_source_prerequisites: Normalize 4769 with requesting account, client/source, target service, transited services, ticket options, and delegation context, plus an authoritative delegation-edge-approval enrichment keyed by service account and target service.
-- false_positives: Approved constrained delegation, protocol transition, web front ends, and identity middleware; stale or incomplete delegation-edge enrichment.
-- references: RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_s4u_ticket_sequence.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend. This is now a two-branch OR: (a) two-or-more distinct target services in the window, or (b) any single S4U request against an edge explicitly marked unapproved; the second branch requires the delegation-edge enrichment join and must not be silently dropped. Both branches must identify S4U activity through EITHER a free-text description match OR a structured delegation-flow field match (whichever the parser actually populates); do not implement only one.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'rubeus_s4u_ticket_sequence' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('4769') OR event_type IN ('4769')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
