-- source_yaral: detections/havoc/yaral/havoc_listener_and_forwarding.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: partial
-- rule_name: havoc_listener_and_forwarding
-- severity: high
-- procedure_ids: HV-P16
-- description: A process listens locally and also establishes outbound connections consistent with forwarding
-- log_source_prerequisites: EDR socket listen and connect telemetry with stable process identity and direction
-- false_positives: Approved proxies, VPNs, developer tunnels and network services
-- references: reports/havoc/source-analysis.md
-- assumptions_and_gaps: Candidate retrieval is translated; canonical entity joins, ordering, windows, and cardinality must be implemented and tested in the target backend.
-- schema_profile: schemas/normalized-sql.yml
-- Schema assumption: normalized_events(event_time, product_event_type, event_type, hostname, user_id, raw_event).
SELECT hostname, user_id, COUNT(*) AS event_count,
       'havoc_listener_and_forwarding' AS canonical_rule
FROM normalized_events
WHERE product_event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN') OR event_type IN ('NETWORK_CONNECTION', 'NETWORK_LISTEN')
GROUP BY hostname, user_id
HAVING COUNT(*) > 0;
