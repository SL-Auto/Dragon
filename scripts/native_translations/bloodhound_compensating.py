"""Write hand-authored secondary translations for five BloodHound canonical rules.

Run once from any directory; writes into detections/bloodhound/{spl,kql,sql,eql,sigma}/.
"""
import pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]
DET = ROOT / "detections" / "bloodhound"
STATUS = "experimental_needs_backend_mapping_and_validation"


def meta(text, name):
    m = re.search(r'(?m)^\s*' + re.escape(name) + r'\s*=\s*"([^"]*)"', text)
    return m.group(1) if m else ""


def header(rule, prefix, fidelity, schema, field_map, gaps):
    text = (DET / "yaral" / f"{rule}.yaral").read_text(encoding="utf-8")
    lines = [
        f"source_yaral: detections/bloodhound/yaral/{rule}.yaral",
        f"translation_status: {STATUS}",
        f"fidelity: {fidelity}",
        f"rule_name: {rule}",
        f"severity: {meta(text, 'severity').lower()}",
        f"procedure_ids: {meta(text, 'procedure_ids')}",
        f"description: {meta(text, 'description')}",
        f"log_source_prerequisites: {meta(text, 'log_source_prerequisites')}",
        f"false_positives: {meta(text, 'false_positives')}",
        f"references: {meta(text, 'references')}",
        f"schema_profile: {schema}",
        f"field_mapping: {field_map}",
        f"assumptions_and_gaps: {gaps}",
    ]
    return "\n".join(prefix + l for l in lines) + "\n", text


def sigma_doc(rule, fidelity, field_map, gaps, logsource, detection, correlation=None):
    text = (DET / "yaral" / f"{rule}.yaral").read_text(encoding="utf-8")
    q = lambda v: '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
    base_name = f"{rule}_base" if correlation else rule
    out = [
        f"title: {q(meta(text, 'description'))}",
        f"name: {base_name}",
        "status: experimental",
        f"description: {q(meta(text, 'description'))}",
        f"source_yaral: {q(f'detections/bloodhound/yaral/{rule}.yaral')}",
        f"translation_status: {STATUS}",
        f"fidelity: {fidelity}",
        "schema_profile: schemas/sigma.yml",
        f"field_mapping: {q(field_map)}",
        f"assumptions_and_gaps: {q(gaps)}",
        "references:",
        f"  - {q(meta(text, 'references'))}",
        f"procedure_ids: {q(meta(text, 'procedure_ids'))}",
        f"log_source_prerequisites: {q(meta(text, 'log_source_prerequisites'))}",
        "logsource:",
    ] + ["  " + l for l in logsource] + ["detection:"] + ["  " + l for l in detection] + [
        "falsepositives:",
        f"  - {q(meta(text, 'false_positives'))}",
        f"level: {meta(text, 'severity').lower()}",
    ]
    if correlation:
        out += ["---", f"title: {q(meta(text, 'description'))}", f"name: {rule}", "status: experimental",
                "correlation:"] + ["  " + l for l in correlation] + [f"level: {meta(text, 'severity').lower()}"]
    return "\n".join(out) + "\n"


def write(rule, fmt, ext, body):
    path = DET / fmt / f"{rule}{ext}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8", newline="\n")


GRAPH_REL = r"(?i)/(users|groups|servicePrincipals|applications|devices)/[^/?]+/(members|transitiveMembers|memberOf|transitiveMemberOf|owners|registeredOwners|registeredUsers|appRoleAssignedTo|appRoleAssignments)([/?]|$)"
GRAPH_OBJ = r"(?i)/(?:users|groups|servicePrincipals|applications|devices)/([^/?]+)/"
NTLM_VALUES = "RestrictSendingNtlmTraffic|RestrictReceivingNTLMTraffic|NtlmMinClientSec|NtlmMinServerSec|LmCompatibilityLevel|UseMachineId|ClientAllowedNTLMServers"
SAMR_OPS = "GetMembersInAlias|EnumerateAliases"
SAMR_UUID = "12345778-1234-abcd-ef00-0123456789ac"

# ---------------------------------------------------------------- ldap deep single category
r = "bloodhound_ldap_deep_single_category_enumeration"
fm = "principal.hostname->src_host/SrcHostname/hostname/source.address; principal.user.userid->user/ActorUsername/user_id/user.id; labels.naming_context->naming_context/NamingContext; labels.result_object_id->result_object_id/ResultObjectId; target.hostname->dest/DvcHostname"
g_native = "Native distinct-count aggregation per host/user/naming context. Canonical 4h hop window is approximated by a schedule of every 60 minutes over the trailing 4 hours. Requires the per-result object expansion described in BH-DR-10."
h, _ = header(r, "# ", "high", "schemas/splunk-cim.yml", fm, g_native)
write(r, "spl", ".spl", h + """| search index=<directory_index> (EventCode=1644 OR event_type="LDAP_SEARCH") earliest=-4h@m latest=now
| where isnotnull(naming_context) AND isnotnull(result_object_id)
| stats dc(result_object_id) as objects values(dest) as domain_controllers min(_time) as first_seen max(_time) as last_seen by src_host user naming_context
| where objects >= 500
| eval canonical_rule="bloodhound_ldap_deep_single_category_enumeration"
""")
h, _ = header(r, "// ", "high", "schemas/sentinel-asim.yml", fm, g_native + " LdapQueryEvents is a placeholder for the tenant table or ASIM-style parser that exposes per-result objects.")
write(r, "kql", ".kql", h + """LdapQueryEvents
| where TimeGenerated > ago(4h)
| where EventID == 1644 or EventType == "LDAP_SEARCH"
| where isnotempty(NamingContext) and isnotempty(ResultObjectId)
| summarize Objects = count_distinct(ResultObjectId), DomainControllers = make_set(DvcHostname, 50), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by SrcHostname, ActorUsername, NamingContext
| where Objects >= 500
| extend CanonicalRule = "bloodhound_ldap_deep_single_category_enumeration"
""")
h, _ = header(r, "-- ", "high", "schemas/normalized-sql.yml", fm, g_native + " Interval syntax is dialect-specific.")
write(r, "sql", ".sql", h + """-- Schema assumption: normalized_events(event_time, product_event_type, hostname, user_id, target_hostname, naming_context, result_object_id).
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
""")
h, _ = header(r, "// ", "partial", "schemas/elastic-ecs.yml", fm, "EQL cannot compute distinct counts; this selects candidate events only. Implement the >=500 distinct result-object threshold per source.address/user.id/naming context over 4h in an ES|QL or threshold rule.")
write(r, "eql", ".eql", h + """any where (event.code == "1644" or event.action == "LDAP_SEARCH") and
  ldap.naming_context != null and ldap.result_object_id != null
""")
write(r, "sigma", ".yml", sigma_doc(r, "high", fm, "Base rule selects LDAP result events; the Sigma value_count correlation expresses the distinct-object threshold. Requires a backend that supports Sigma correlations and per-result expansion (BH-DR-10).",
    ["category: ldap_query", "product: windows"],
    ["selection:", "  EventID|contains:", "    - '1644'", "    - 'LDAP_SEARCH'", "filter_missing:", "  ResultObjectId: null", "condition: selection and not filter_missing"],
    ["type: value_count", f"rules:", f"  - {r}_base", "group-by:", "  - SourceHostname", "  - User", "  - NamingContext", "timespan: 4h", "condition:", "  field: ResultObjectId", "  gte: 500"]))

# ---------------------------------------------------------------- graph deep relationship
r = "bloodhound_graph_deep_relationship_enumeration"
fm = "metadata.product_event_type->MicrosoftGraphActivityLogs table/sourcetype; network.http.method->RequestMethod/http.request.method; target.url->RequestUri/url.original; principal.user.userid->UserId; principal.user.product_object_id->ServicePrincipalId; principal.application->AppId; principal.ip->IPAddress"
g = "Native regex filter, URI object capture, delegated/app-only principal coalesce and distinct-object threshold per principal and app. The 30m hop window is approximated by a schedule of every 10 minutes over the trailing 30 minutes."
h, _ = header(r, "# ", "high", "schemas/splunk-cim.yml", fm, g)
write(r, "spl", ".spl", h + f"""| search index=<entra_index> sourcetype=<graph_activity_sourcetype> requestMethod="GET" earliest=-30m@m latest=now
| eval principal=coalesce(nullif(userId,""), nullif(servicePrincipalId,""))
| where isnotnull(principal)
| regex requestUri="{GRAPH_REL}"
| rex field=requestUri "{GRAPH_OBJ.replace('([^/?]+)', '(?<object_id>[^/?]+)')}"
| stats dc(object_id) as objects values(ipAddress) as source_ips min(_time) as first_seen max(_time) as last_seen by principal appId
| where objects >= 100
| eval canonical_rule="bloodhound_graph_deep_relationship_enumeration"
""")
h, _ = header(r, "// ", "high", "schemas/sentinel-asim.yml", fm, g + " Uses the native Sentinel MicrosoftGraphActivityLogs table.")
write(r, "kql", ".kql", h + f"""MicrosoftGraphActivityLogs
| where TimeGenerated > ago(30m)
| where RequestMethod == "GET"
| where RequestUri matches regex @"{GRAPH_REL}"
| extend Principal = coalesce(UserId, ServicePrincipalId)
| where isnotempty(Principal)
| extend ObjectId = extract(@"{GRAPH_OBJ}", 1, RequestUri)
| summarize Objects = count_distinct(ObjectId), SourceIPs = make_set(IPAddress, 50), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Principal, AppId
| where Objects >= 100
| extend CanonicalRule = "bloodhound_graph_deep_relationship_enumeration"
""")
h, _ = header(r, "-- ", "high", "schemas/normalized-sql.yml", fm, g + " REGEXP_LIKE/REGEXP_SUBSTR and NULLIF are dialect-specific (shown in Oracle/Snowflake-style syntax).")
write(r, "sql", ".sql", h + f"""-- Schema assumption: graph_activity(event_time, request_method, request_uri, user_id, service_principal_id, app_id, ip_address).
WITH rel AS (
  SELECT COALESCE(NULLIF(user_id, ''), NULLIF(service_principal_id, '')) AS principal,
         app_id, ip_address,
         REGEXP_SUBSTR(request_uri, '/(users|groups|servicePrincipals|applications|devices)/([^/?]+)/', 1, 1, 'i', 2) AS object_id
  FROM graph_activity
  WHERE request_method = 'GET'
    AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
    AND REGEXP_LIKE(request_uri, '/(users|groups|servicePrincipals|applications|devices)/[^/?]+/(members|transitiveMembers|memberOf|transitiveMemberOf|owners|registeredOwners|registeredUsers|appRoleAssignedTo|appRoleAssignments)([/?]|$)', 'i')
)
SELECT principal, app_id, COUNT(DISTINCT object_id) AS objects,
       'bloodhound_graph_deep_relationship_enumeration' AS canonical_rule
FROM rel
WHERE principal IS NOT NULL
GROUP BY principal, app_id
HAVING COUNT(DISTINCT object_id) >= 100;
""")
h, _ = header(r, "// ", "partial", "schemas/elastic-ecs.yml", fm, "EQL selects relationship GETs but cannot capture the object segment or count distinct objects; implement the per-principal/app threshold in ES|QL (DISSECT/GROK plus COUNT_DISTINCT).")
write(r, "eql", ".eql", h + f"""any where event.dataset == "azure.graphactivitylogs" and http.request.method == "GET" and
  url.original regex~ "{GRAPH_REL.replace('(?i)', '')}"
""")
write(r, "sigma", ".yml", sigma_doc(r, "partial", fm, "Sigma cannot capture the object ID from the URI or coalesce principal fields; the correlation counts distinct RequestUri per UserId/ServicePrincipalId and AppId, which over-counts paged requests for the same object. Backend must split delegated and app-only identities.",
    ["product: azure", "service: graphactivitylogs"],
    ["selection:", "  RequestMethod: GET", f"  RequestUri|re: '{GRAPH_REL}'", "condition: selection"],
    ["type: value_count", "rules:", f"  - {r}_base", "group-by:", "  - UserId", "  - ServicePrincipalId", "  - AppId", "timespan: 30m", "condition:", "  field: RequestUri", "  gte: 100"]))

# ---------------------------------------------------------------- process to directory effect
r = "bloodhound_process_to_directory_effect"
fm = "principal.hostname->dest/DeviceName/hostname/host.name; principal.process.product_specific_process_id->process_guid/InitiatingProcessId+InitiatingProcessCreationTime/process_id/process.entity_id; target.resource.name->ldap_search_base/DistinguishedName/object_name; principal.process.file.full_path->process_path/InitiatingProcessFolderPath"
g = "Native per-host, per-stable-process distinct object/search-base threshold over 30 minutes (schedule every 10 minutes). The stable process key must be the vendor entity ID; raw PID alone reintroduces PID-reuse joins."
h, _ = header(r, "# ", "high", "schemas/splunk-cim.yml", fm, g)
write(r, "spl", ".spl", h + """| search index=<edr_index> event_type="LDAP_SEARCH" earliest=-30m@m latest=now
| where isnotnull(process_guid) AND isnotnull(ldap_search_base)
| stats dc(ldap_search_base) as objects values(process_path) as process_paths values(user) as accounts by dest process_guid
| where objects >= 25
| eval canonical_rule="bloodhound_process_to_directory_effect"
""")
h, _ = header(r, "// ", "high", "schemas/sentinel-asim.yml", fm, g + " Written against Defender for Endpoint DeviceEvents ActionType LdapSearch; process identity is InitiatingProcessId plus InitiatingProcessCreationTime.")
write(r, "kql", ".kql", h + """DeviceEvents
| where Timestamp > ago(30m)
| where ActionType == "LdapSearch"
| extend SearchBase = tostring(parse_json(AdditionalFields).DistinguishedName)
| where isnotempty(SearchBase)
| summarize Objects = count_distinct(SearchBase), ProcessPaths = make_set(InitiatingProcessFolderPath, 10), Accounts = make_set(InitiatingProcessAccountName, 10)
    by DeviceName, InitiatingProcessId, InitiatingProcessCreationTime
| where Objects >= 25
| extend CanonicalRule = "bloodhound_process_to_directory_effect"
""")
h, _ = header(r, "-- ", "high", "schemas/normalized-sql.yml", fm, g)
write(r, "sql", ".sql", h + """-- Schema assumption: normalized_events(event_time, product_event_type, hostname, process_entity_id, process_path, user_id, object_name).
SELECT hostname, process_entity_id,
       COUNT(DISTINCT object_name) AS objects,
       MIN(process_path) AS process_path_sample,
       'bloodhound_process_to_directory_effect' AS canonical_rule
FROM normalized_events
WHERE product_event_type = 'LDAP_SEARCH'
  AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND process_entity_id IS NOT NULL
  AND object_name IS NOT NULL
GROUP BY hostname, process_entity_id
HAVING COUNT(DISTINCT object_name) >= 25;
""")
h, _ = header(r, "// ", "partial", "schemas/elastic-ecs.yml", fm, "EQL cannot count distinct search bases per process; this selects process-attributed LDAP search events only. Elastic Defend does not natively emit LDAP query events; a third-party EDR integration mapped to ECS is assumed.")
write(r, "eql", ".eql", h + """any where event.action == "LDAP_SEARCH" and process.entity_id != null and ldap.search_base != null
""")
write(r, "sigma", ".yml", sigma_doc(r, "high", fm, "Base rule selects process-attributed LDAP searches; value_count correlation expresses the distinct search-base threshold per host and process GUID. Requires Sigma correlation support and a stable process GUID field.",
    ["category: ldap_query", "product: windows"],
    ["selection:", "  EventType: LDAP_SEARCH", "filter_missing:", "  - ProcessGuid: null", "  - SearchBase: null", "condition: selection and not filter_missing"],
    ["type: value_count", "rules:", f"  - {r}_base", "group-by:", "  - Computer", "  - ProcessGuid", "timespan: 30m", "condition:", "  field: SearchBase", "  gte: 25"]))

# ---------------------------------------------------------------- remote security configuration value reads
r = "bloodhound_remote_security_configuration_value_reads"
fm = "target.hostname->dest/DeviceName/hostname/host.name; principal.user.userid->user/InitiatingProcessAccountName/user_id/user.name; target.registry.registry_key->registry_path/RegistryKey/registry_key/registry.path; target.registry.registry_value_name->registry_value_name/RegistryValueName/registry_value/registry.value; principal.process.file.full_path->process_path/InitiatingProcessFolderPath/process.executable"
g = "Native key/value pairing, owning-service and local-service exclusions, and >=2 distinct values per actor and target over 30 minutes (schedule every 10 minutes). Requires EDR value-level registry read telemetry; Windows 4656/4663 cannot supply value names (BH-DR-25)."
pairs_spl = (
    '(match(registry_path,"(?i)\\\\\\\\Services\\\\\\\\Kdc$") AND match(registry_value_name,"(?i)^StrongCertificateBindingEnforcement$")) OR '
    '(match(registry_path,"(?i)\\\\\\\\SecurityProviders\\\\\\\\Schannel$") AND match(registry_value_name,"(?i)^CertificateMappingMethods$")) OR '
    f'(match(registry_path,"(?i)\\\\\\\\Control\\\\\\\\Lsa(\\\\\\\\MSV1_0)?$") AND match(registry_value_name,"(?i)^({NTLM_VALUES})$")) OR '
    '(match(registry_path,"(?i)\\\\\\\\CertSvc\\\\\\\\Configuration\\\\\\\\") AND match(registry_value_name,"(?i)^(Security|EnrollmentAgentRights|EditFlags)$"))'
)
h, _ = header(r, "# ", "high", "schemas/splunk-cim.yml", fm, g)
write(r, "spl", ".spl", h + f"""| search index=<edr_index> event_type="REGISTRY_READ" earliest=-30m@m latest=now
| where {pairs_spl}
| where NOT match(process_path,"(?i)\\\\\\\\(lsass|certsrv|services|wininit|csrss)\\\\.exe$")
| where NOT match(user,"(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$")
| stats dc(registry_value_name) as values values(registry_value_name) as value_names values(src) as source_hosts values(process_path) as processes by user dest
| where values >= 2
| eval canonical_rule="bloodhound_remote_security_configuration_value_reads"
""")
h, _ = header(r, "// ", "high", "schemas/sentinel-asim.yml", fm, g + " Written against a value-level registry read table (RegistryReadEvents placeholder); Defender DeviceRegistryEvents records changes only.")
write(r, "kql", ".kql", h + f"""RegistryReadEvents
| where TimeGenerated > ago(30m)
| where (RegistryKey matches regex @"(?i)\\\\Services\\\\Kdc$" and RegistryValueName matches regex @"(?i)^StrongCertificateBindingEnforcement$")
     or (RegistryKey matches regex @"(?i)\\\\SecurityProviders\\\\Schannel$" and RegistryValueName matches regex @"(?i)^CertificateMappingMethods$")
     or (RegistryKey matches regex @"(?i)\\\\Control\\\\Lsa(\\\\MSV1_0)?$" and RegistryValueName matches regex @"(?i)^({NTLM_VALUES})$")
     or (RegistryKey matches regex @"(?i)\\\\CertSvc\\\\Configuration\\\\" and RegistryValueName matches regex @"(?i)^(Security|EnrollmentAgentRights|EditFlags)$")
| where not(InitiatingProcessFolderPath matches regex @"(?i)\\\\(lsass|certsrv|services|wininit|csrss)\\.exe$")
| where not(ActorUsername matches regex @"(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$")
| summarize Values = count_distinct(RegistryValueName), ValueNames = make_set(RegistryValueName, 20), SourceHosts = make_set(SrcHostname, 20), Processes = make_set(InitiatingProcessFolderPath, 10)
    by ActorUsername, DvcHostname
| where Values >= 2
| extend CanonicalRule = "bloodhound_remote_security_configuration_value_reads"
""")
h, _ = header(r, "-- ", "high", "schemas/normalized-sql.yml", fm, g + " Case-insensitive regex uses REGEXP_LIKE(...,'i'); backslashes are literal in standard SQL strings.")
write(r, "sql", ".sql", h + f"""-- Schema assumption: normalized_events(event_time, product_event_type, hostname, target_hostname, user_id, process_path, registry_key, registry_value).
SELECT user_id, target_hostname,
       COUNT(DISTINCT registry_value) AS value_count,
       'bloodhound_remote_security_configuration_value_reads' AS canonical_rule
FROM normalized_events
WHERE product_event_type = 'REGISTRY_READ'
  AND event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND (   (REGEXP_LIKE(registry_key, '\\\\Services\\\\Kdc$', 'i') AND REGEXP_LIKE(registry_value, '^StrongCertificateBindingEnforcement$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\\\SecurityProviders\\\\Schannel$', 'i') AND REGEXP_LIKE(registry_value, '^CertificateMappingMethods$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\\\Control\\\\Lsa(\\\\MSV1_0)?$', 'i') AND REGEXP_LIKE(registry_value, '^({NTLM_VALUES})$', 'i'))
       OR (REGEXP_LIKE(registry_key, '\\\\CertSvc\\\\Configuration\\\\', 'i') AND REGEXP_LIKE(registry_value, '^(Security|EnrollmentAgentRights|EditFlags)$', 'i')))
  AND NOT REGEXP_LIKE(COALESCE(process_path, ''), '\\\\(lsass|certsrv|services|wininit|csrss)\\.exe$', 'i')
  AND NOT REGEXP_LIKE(COALESCE(user_id, ''), '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$', 'i')
GROUP BY user_id, target_hostname
HAVING COUNT(DISTINCT registry_value) >= 2;
""")
h, _ = header(r, "// ", "partial", "schemas/elastic-ecs.yml", fm, "EQL expresses the key/value pairing and exclusions but cannot count distinct values; implement the >=2 distinct values per user/host over 30m in ES|QL or a threshold rule. Elastic Defend registry events cover modifications, so a value-level read source mapped to ECS is assumed.")
write(r, "eql", ".eql", h + f"""registry where event.action == "REGISTRY_READ" and
  (
    (registry.path : "*\\\\Services\\\\Kdc\\\\StrongCertificateBindingEnforcement") or
    (registry.path : "*\\\\SecurityProviders\\\\Schannel\\\\CertificateMappingMethods") or
    (registry.key : ("*\\\\Control\\\\Lsa", "*\\\\Control\\\\Lsa\\\\MSV1_0") and registry.value : ("RestrictSendingNtlmTraffic", "RestrictReceivingNTLMTraffic", "NtlmMinClientSec", "NtlmMinServerSec", "LmCompatibilityLevel", "UseMachineId", "ClientAllowedNTLMServers")) or
    (registry.path : "*\\\\CertSvc\\\\Configuration\\\\*" and registry.value : ("Security", "EnrollmentAgentRights", "EditFlags"))
  ) and
  not process.name : ("lsass.exe", "certsrv.exe", "services.exe", "wininit.exe", "csrss.exe") and
  not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")
""")
write(r, "sigma", ".yml", sigma_doc(r, "high", fm, "Base rule expresses key/value pairs and exclusions; value_count correlation expresses >=2 distinct values per user and host. Requires a value-level registry read source and Sigma correlation support.",
    ["category: registry_event", "product: windows"],
    ["value_kdc:", "  TargetObject|endswith: '\\Services\\Kdc\\StrongCertificateBindingEnforcement'",
     "value_schannel:", "  TargetObject|endswith: '\\SecurityProviders\\Schannel\\CertificateMappingMethods'",
     "value_lsa:", "  TargetObject|re: '(?i)\\\\Control\\\\Lsa(\\\\MSV1_0)?\\\\(" + NTLM_VALUES + ")$'",
     "value_ca:", "  TargetObject|re: '(?i)\\\\CertSvc\\\\Configuration\\\\.*\\\\(Security|EnrollmentAgentRights|EditFlags)$'",
     "selection_read:", "  EventType: REGISTRY_READ",
     "filter_owner:", "  Image|endswith:", "    - '\\lsass.exe'", "    - '\\certsrv.exe'", "    - '\\services.exe'", "    - '\\wininit.exe'", "    - '\\csrss.exe'",
     "filter_local_service:", "  User:", "    - 'SYSTEM'", "    - 'LOCAL SERVICE'", "    - 'NETWORK SERVICE'", "    - 'S-1-5-18'", "    - 'S-1-5-19'", "    - 'S-1-5-20'",
     "condition: selection_read and 1 of value_* and not 1 of filter_*"],
    ["type: value_count", "rules:", f"  - {r}_base", "group-by:", "  - User", "  - Computer", "timespan: 30m", "condition:", "  field: TargetObject", "  gte: 2"]))

# ---------------------------------------------------------------- samr alias membership fanout
r = "bloodhound_samr_alias_membership_fanout"
fm = "principal.hostname->src/id.orig_h/source_host/source.ip; target.hostname->dest/id.resp_h/target_host/destination.ip; labels.rpc_interface->endpoint/zeek.dce_rpc.endpoint; labels.rpc_operation->operation/zeek.dce_rpc.operation; labels.rpc_opnum->opnum (vendor NDR only)"
g = "Native interface/operation filter and >=3 distinct targets per source over 30 minutes (schedule every 10 minutes). Written for Zeek dce_rpc (endpoint/operation names); the UUID+opnum branch applies to NDR/EDR sources that expose opnums."
h, _ = header(r, "# ", "high", "schemas/splunk-cim.yml", fm, g)
write(r, "spl", ".spl", h + f"""| search index=<ndr_index> (sourcetype="bro:dce_rpc:json" OR event_type="RPC_CALL") earliest=-30m@m latest=now
| where (match(endpoint,"(?i)samr") AND match(operation,"(?i)({SAMR_OPS})")) OR (lower(rpc_interface_uuid)="{SAMR_UUID}" AND (opnum="15" OR opnum="33"))
| stats dc(dest) as targets values(user) as accounts min(_time) as first_seen max(_time) as last_seen by src
| where targets >= 3
| eval canonical_rule="bloodhound_samr_alias_membership_fanout"
""")
h, _ = header(r, "// ", "high", "schemas/sentinel-asim.yml", fm, g + " Zeek dce_rpc ingested to a custom table (ZeekDceRpc_CL placeholder) or a vendor NDR table with equivalent columns.")
write(r, "kql", ".kql", h + f"""ZeekDceRpc_CL
| where TimeGenerated > ago(30m)
| where (endpoint_s matches regex @"(?i)samr" and operation_s matches regex @"(?i)({SAMR_OPS})")
     or (tolower(rpc_interface_uuid_s) == "{SAMR_UUID}" and opnum_d in (15, 33))
| summarize Targets = count_distinct(id_resp_h_s), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Source = id_orig_h_s
| where Targets >= 3
| extend CanonicalRule = "bloodhound_samr_alias_membership_fanout"
""")
h, _ = header(r, "-- ", "high", "schemas/normalized-sql.yml", fm, g)
write(r, "sql", ".sql", h + f"""-- Schema assumption: rpc_events(event_time, source_host, target_host, rpc_interface, rpc_interface_uuid, rpc_operation, rpc_opnum).
SELECT source_host,
       COUNT(DISTINCT target_host) AS targets,
       'bloodhound_samr_alias_membership_fanout' AS canonical_rule
FROM rpc_events
WHERE event_time >= CURRENT_TIMESTAMP - INTERVAL '30' MINUTE
  AND (   (REGEXP_LIKE(rpc_interface, 'samr', 'i') AND REGEXP_LIKE(rpc_operation, '({SAMR_OPS})', 'i'))
       OR (LOWER(rpc_interface_uuid) = '{SAMR_UUID}' AND rpc_opnum IN (15, 33)))
GROUP BY source_host
HAVING COUNT(DISTINCT target_host) >= 3;
""")
h, _ = header(r, "// ", "partial", "schemas/elastic-ecs.yml", fm, "EQL selects SAMR alias operations from the Zeek integration but cannot count distinct destinations per source; implement the >=3 target threshold in ES|QL or a threshold rule. The opnum branch requires a vendor NDR mapping not present in the Zeek integration.")
write(r, "eql", ".eql", h + """network where event.dataset == "zeek.dce_rpc" and
  zeek.dce_rpc.endpoint : "samr" and
  zeek.dce_rpc.operation : ("SamrGetMembersInAlias", "SamrEnumerateAliasesInDomain")
""")
write(r, "sigma", ".yml", sigma_doc(r, "high", fm, "Base rule uses the Sigma Zeek dce_rpc logsource; value_count correlation expresses >=3 distinct responders per originator. The opnum-only branch is not representable in the Zeek logsource and needs a vendor NDR rule.",
    ["product: zeek", "service: dce_rpc"],
    ["selection:", "  endpoint: samr", "  operation:", "    - SamrGetMembersInAlias", "    - SamrEnumerateAliasesInDomain", "condition: selection"],
    ["type: value_count", "rules:", f"  - {r}_base", "group-by:", "  - id.orig_h", "timespan: 30m", "condition:", "  field: id.resp_h", "  gte: 3"]))

print("wrote 25 translations")
