-- source_yaral: detections/bloodhound/yaral/bloodhound_remote_security_configuration_value_reads.yaral
-- translation_status: experimental_needs_backend_mapping_and_validation
-- fidelity: high
-- rule_name: bloodhound_remote_security_configuration_value_reads
-- severity: high
-- procedure_ids: BH-012
-- description: Detects one account reading two or more collector-relevant security-configuration registry values (KDC certificate binding, Schannel certificate mapping, LSA/MSV1_0 NTLM restriction and compatibility values, or CA security/enrollment-agent/edit-flag values) on a single target, compensating for single-target reads below bloodhound_remote_security_configuration_reads's multi-host threshold.
-- log_source_prerequisites: EDR REGISTRY_READ telemetry exposing full registry key path, value name, subject account, reading process path and target host. Windows Security 4656/4663 record the key and access mask but not the value name, so they cannot satisfy this rule (reviews/bloodhound/detection-review.md#bh-dr-25).
-- false_positives: Security posture assessment, PKI administration, vulnerability management and domain-controller compliance tooling reading several of these values on one host; administrators inspecting values with regedit or reg.exe.
-- references: reports/bloodhound/source-analysis.md#bh-012, sources/bloodhound-ce-src packages/go/ein/ad.go#L121-L146 (5e8e78e), public-rules/comparisons/bloodhound/bloodhound_remote_security_configuration_reads.md, reviews/bloodhound/detection-review.md#bh-dr-20
-- schema_profile: schemas/normalized-sql.yml
-- field_mapping: target.hostname->dest/DeviceName/hostname/host.name; principal.user.userid->user/InitiatingProcessAccountName/user_id/user.name; target.registry.registry_key->registry_path/RegistryKey/registry_key/registry.path; target.registry.registry_value_name->registry_value_name/RegistryValueName/registry_value/registry.value; principal.process.file.full_path->process_path/InitiatingProcessFolderPath/process.executable
-- assumptions_and_gaps: Native key/value pairing, owning-service and local-service exclusions, and >=2 distinct values per actor and target over 30 minutes (schedule every 10 minutes). Requires EDR value-level registry read telemetry; Windows 4656/4663 cannot supply value names (BH-DR-25). Case-insensitive regex uses REGEXP_LIKE(...,'i'); backslashes are literal in standard SQL strings.
-- Schema assumption: normalized_events(event_time, product_event_type, hostname, target_hostname, user_id, process_path, registry_key, registry_value).
SELECT user_id, target_hostname,
       COUNT(DISTINCT registry_value) AS value_count,
       'bloodhound_remote_security_configuration_value_reads' AS canonical_rule
FROM normalized_events
WHERE product_event_type = 'REGISTRY_READ'
  AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND (   (REGEXP_LIKE(registry_key, '\\Services\\Kdc$', 'i') AND REGEXP_LIKE(registry_value, '^StrongCertificateBindingEnforcement$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\SecurityProviders\\Schannel$', 'i') AND REGEXP_LIKE(registry_value, '^CertificateMappingMethods$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\Control\\Lsa(\\MSV1_0)?$', 'i') AND REGEXP_LIKE(registry_value, '^(RestrictSendingNtlmTraffic|RestrictReceivingNTLMTraffic|NtlmMinClientSec|NtlmMinServerSec|LmCompatibilityLevel|UseMachineId|ClientAllowedNTLMServers)$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\CertSvc\\Configuration\\', 'i') AND REGEXP_LIKE(registry_value, '^(Security|EnrollmentAgentRights|EditFlags)$', 'i')))
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '\\(lsass|certsrv|services|wininit|csrss)\.exe$', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_id, ''), '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$', 'i')
GROUP BY user_id, target_hostname
HAVING COUNT(DISTINCT registry_value) >= 2;
