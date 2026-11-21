-- source_yaral: detections/bloodhound/yaral/bloodhound_samr_alias_membership_fanout.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: bloodhound_samr_alias_membership_fanout
-- severity: high
-- procedure_ids: BH-009
-- description: Detects SAMR alias enumeration or alias-membership reads, resolved either by SAMR operation name or by SAMR interface UUID plus opnum, against multiple remote hosts from one source, compensating for parser/vendor differences that separate SAMR from LSA policy telemetry inside the combined bloodhound_samr_local_group_enumeration regex.
-- log_source_prerequisites: NDR or EDR RPC telemetry that resolves the SAMR interface (name or UUID 12345778-1234-abcd-ef00-0123456789ac) and the operation (name such as SamrEnumerateAliasesInDomain/SamrGetMembersInAlias, or opnum 15/33), plus source and target host identity.
-- false_positives: Asset inventory, compliance scanners, privileged-access management and endpoint-management systems that enumerate local group membership across hosts.
-- references: reports/bloodhound/source-analysis.md#bh-009, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/, public-rules/comparisons/bloodhound/bloodhound_samr_local_group_enumeration.md, reviews/bloodhound/detection-review.md#bh-dr-22
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: principal.hostname->src/id.orig_h/source_host/source.ip; target.hostname->dest/id.resp_h/target_host/destination.ip; labels.rpc_interface->endpoint/zeek.dce_rpc.endpoint; labels.rpc_operation->operation/zeek.dce_rpc.operation; labels.rpc_opnum->opnum (vendor NDR only)
-- assumptions_and_gaps: Native interface/operation filter and >=3 distinct targets per source over 30 minutes (schedule every 10 minutes). Written for Zeek dce_rpc (endpoint/operation names); the UUID+opnum branch applies to NDR/EDR sources that expose opnums.
-- Schema assumption: rpc_events(event_time, source_host, target_host, rpc_interface, rpc_interface_uuid, rpc_operation, rpc_opnum).
SELECT source_host,
       COUNT(DISTINCT target_host) AS targets,
       'bloodhound_samr_alias_membership_fanout' AS canonical_rule
FROM rpc_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND (   (REGEXP_LIKE(rpc_interface, 'samr', 'i') AND REGEXP_LIKE(rpc_operation, '(GetMembersInAlias|EnumerateAliases)', 'i'))
       OR (LOWER(rpc_interface_uuid) = '12345778-1234-abcd-ef00-0123456789ac' AND rpc_opnum IN (15, 33)))
GROUP BY source_host
HAVING COUNT(DISTINCT target_host) >= 3;
