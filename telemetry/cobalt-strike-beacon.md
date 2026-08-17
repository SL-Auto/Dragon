# cobalt-strike-beacon telemetry requirements

## Scope

- Tool revision: `4.13-docs-202606220941`
- Detection files: 21 one-rule-per-file detections under `detections/cobalt-strike-beacon/yaral/`
- Generated/reviewed: 2026-08-15
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CS-TEL-01 | EDR/Sysmon and Windows process audit | PROCESS_LAUNCH/STOP, PROCESS_OPEN, REMOTE_THREAD, EXECUTABLE_MEMORY, PARENT_MISMATCH, CLR_RUNTIME_LOAD; Sysmon 1/7/8/10; Security 4688 | stable source/target process entity, creator/effective parent, image/hash/signer/prevalence, user/integrity, access, memory/start address, runtime | Enable process, injection, memory, module/runtime and parent attribution; include command line but do not rely on it | Retain 14 days; injection 2m, identity 5m, file/egress 15m, C2 30m | self-injection, Interpreter RW bytecode and unsupported memory sensors may be invisible | CSB-001,004,011-020,024-028,030-034 |
| CS-TEL-02 | EDR/firewall/netflow/proxy/TLS | NETWORK_CONNECTION, SOCKET_LISTEN, HTTP, TLS | process entity/path, host, direction, local/remote IP/port, destination/SNI/certificate, method/URI, bytes, timing | Enable process-attributed connect/listen and central proxy/TLS/firewall metadata | Retain 14 days; preserve distinct destination and timing | encrypted/custom transports, proxies and missing process attribution reduce specificity | CSB-002,005,008-009,021,024-025 |
| CS-TEL-03 | DNS client/resolver | DNS_QUERY and response | process, host, qname/qtype/answer/rcode, label length/entropy, timing | Centralize endpoint/resolver DNS; add tested entropy/length enrichment | Retain 14 days; group 20m | DoH and intermediate resolvers may hide process/name | CSB-006 |
| CS-TEL-04 | Sysmon/EDR IPC | Sysmon 17/18, PIPE_CREATE, PIPE_CONNECT | process, signer/prevalence, host, pipe, peer/direction, user | Enable pipe create/connect on Windows and preserve raw pipe value | Retain 7 days | local pipes lack SMB context; high volume | CSB-007 |
| CS-TEL-05 | Windows Security / domain controllers | 4624, 4648, 4662, 4672, 4688, 4697, 4768, 4769, 4776, 5140, 5145 | account/logon ID, source IP/host, target host, object/right, auth package, service/share/path, process/service image | Enable Logon, Special Logon, Process Creation, Security System Extension, Detailed File Share, Kerberos and Directory Service Access with scoped SACLs on every DC | Retain 30 days for identity baseline; remote joins 10m | missing DCs/SACLs/source fields invalidate joins; legitimate admin overlaps | CSB-011-013,020,022,028,030 |
| CS-TEL-06 | Service Control Manager | System 7035, 7036, 7045 | service, image, account, state, host, timestamp | Forward System log from all Windows hosts | Retain 30 days; join with 5140/5145 within 10m | 7045 lacks remote creator; deployment is common | CSB-020,030,034 |
| CS-TEL-07 | PowerShell and CLR/AMSI/EDR | PowerShell 400/403/4103/4104, POWERSHELL_SCRIPT, CLR_RUNTIME_LOAD | host process/entity, script metadata, engine/runtime version, user, expected-host enrichment | Enable Script Block/Module logging and EDR runtime telemetry; test privacy controls | Retain 14 days | unmanaged hosting may bypass PowerShell logs; expected-host is enrichment | CSB-015,017 |
| CS-TEL-08 | EDR/file/registry/object audit | FILE_READ/WRITE/RENAME/DELETE/TIMESTAMP_CHANGE, REGISTRY_READ, CREDENTIAL_STORE_READ; Sysmon 2/11/23/26; Security 4656/4663 | process entity, user, path/key/value, operation, old/new time, hash, signer/prevalence, sensitivity | Enable file lifecycle and sensitive-read telemetry; scoped SACLs; classify sensitive paths | Retain 14 days; file-to-egress join 15m | standard audit omits most reads; sensitivity is tenant enrichment | CSB-023-026,028,034 |
| CS-TEL-09 | EDR user-data sensors | SCREEN_CAPTURE, CLIPBOARD_READ, INPUT_CAPTURE, BROWSER_SECRET_READ | process, user/session, collection type, target, signer/prevalence, bytes | Enable vendor collection/browser telemetry where lawful; privacy review required | Retain 7 days | not available in standard logs; disable rule without verified mapping | CSB-027 |
| CS-TEL-10 | LDAP/RPC/NDR/directory diagnostics | LDAP_QUERY, RPC_CALL and directory diagnostic events | client process/host/account, server, interface/operation, object type/filter, result | Collect process-attributed LDAP/RPC or directory diagnostics with capacity testing | Retain 14 days; group 10m | encryption, dynamic RPC and absent process identity | CSB-022,028,032 |
| CS-TEL-11 | WinRM/WMI operational and EDR | WINRM_SESSION, WMI_REMOTE_OPERATION; WinRM Operational; WMI-Activity 5857-5861 | source, target, account/session, namespace/operation, client process, child process | Enable and forward WinRM and WMI-Activity operational logs; normalize per OS | Retain 14 days; child join 10m | event IDs/fields vary; causal source may be absent | CSB-031,032 |
| CS-TEL-12 | OpenSSH / Windows OpenSSH | SSH_AUTH, SSH session and child process | account, source IP, target, method/key ID where lawful, session ID, result, child | Enable authentication/session and process audit on SSH servers | Retain 30 days; child join 10m | encrypted command content; platform schemas differ | CSB-033 |
| CS-TEL-13 | Authorized Team Server/client | task/config/listener/REST audit | actor, Beacon ID, task ID/type/state, config/listener, timestamp, result | Enable protected audit/transcripts for sanctioned infrastructure | Retain per engagement governance | unavailable for adversary infrastructure; client-only actions otherwise invisible | CSB-003,010,016,029 and compensation for all |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `cobalt_strike_process_network_context` | CSB-001,002,005 | CS-TEL-01,02 | process-attributed outbound connections, stable process, signer or prevalence | asset role, destination prevalence, certificate/HTTP | cannot match without process attribution/enrichment |
| `cobalt_strike_dns_process_context` | CSB-006 | CS-TEL-03 | DNS query, process, qname, length or entropy | qtype baseline, domain age | disable when entropy/length mapping is absent |
| `cobalt_strike_named_pipe_peer_activity` | CSB-007 | CS-TEL-04 | pipe event, process, signer/prevalence | peer host, SMB session | local/network distinction is lost |
| `cobalt_strike_socket_listen_or_rare_egress` | CSB-008 | CS-TEL-01,02 | listen/connect event and process rarity/signing | service inventory | broad/noisy without prevalence |
| `cobalt_strike_socket_fanout_or_forwarding` | CSB-009 | CS-TEL-02 | stable process and distinct destinations | approved proxy/scanner role | cardinality cannot be calculated |
| `cobalt_strike_suspicious_process_lineage_or_memory` | CSB-004,014,016 | CS-TEL-01 | parent mismatch or executable-memory event | call stack, memory backing | in-process behavior missed without advanced EDR |
| `cobalt_strike_privileged_context_change` | CSB-011 | CS-TEL-01,05 | 4672/token change plus process rarity/signing | service/account role | standard 4672 may lack process |
| `cobalt_strike_alternate_identity_process` | CSB-012 | CS-TEL-01,05 | 4648 and process under target account on host | logon ID/session | concurrent admin can false-join |
| `cobalt_strike_unusual_authentication_material_use` | CSB-013 | CS-TEL-05 | successful auth and first-seen source enrichment | service/account baseline | disable without reliable baseline enrichment |
| `cobalt_strike_powershell_or_clr_in_unusual_host` | CSB-015,017 | CS-TEL-01,07 | runtime/script event and expected-host enrichment | AMSI, call stack | unmanaged runtime invisible without EDR |
| `cobalt_strike_cross_process_injection` | CSB-018,019 | CS-TEL-01 | process open and remote thread/executable memory with stable entities | access mask, start module | self-injection and missing effect events escape |
| `cobalt_strike_service_or_integrity_transition` | CSB-020 | CS-TEL-01,05,06 | service/install or integrity transition | maintenance window, installer identity | contextual only without causality |
| `cobalt_strike_discovery_fanout` | CSB-021 | CS-TEL-02 | process-attributed attempted connections and distinct targets | scanner inventory | local API discovery remains invisible |
| `cobalt_strike_directory_discovery` | CSB-022 | CS-TEL-05,10 | process-attributed LDAP/RPC and object types | approved identity product | cannot match opaque/unattributed queries |
| `cobalt_strike_sensitive_registry_read` | CSB-023 | CS-TEL-08 | registry-read event and sensitivity/process enrichment | key criticality | most standard Windows logs omit reads |
| `cobalt_strike_sensitive_file_activity` | CSB-024,025 | CS-TEL-02,08 | sensitive file event and egress from same process | DLP classification | no match when reads or stable entity absent |
| `cobalt_strike_file_cleanup_or_timestomp` | CSB-026,034 | CS-TEL-08 | deletion/timestamp event and process rarity/signing | USN/MFT history | cleanup may be memory-only |
| `cobalt_strike_user_data_collection` | CSB-027 | CS-TEL-09 | vendor collection event and process context | subsequent egress | disable without vendor sensor mapping |
| `cobalt_strike_credential_access_effect` | CSB-028 | CS-TEL-01,05,08,10 | LSASS/store/replication effect | approved identity/security source | legitimate tools overlap; no attribution |
| `cobalt_strike_remote_service_sequence` | CSB-030 | CS-TEL-05,06,08 | share access plus service installation target/account | source process, deployment inventory | service event lacks remote creator when share audit absent |
| `cobalt_strike_remote_management_execution` | CSB-031,032,033 | CS-TEL-01,11,12 | normalized remote session and child process on target/account | session/logon ID | parser/causal mismatch can false-join |

## Deployment order

1. Validate process, authentication, service, network and stable entity mappings.
2. Add and test prevalence, entropy, sensitivity, expected-host and first-seen enrichments.
3. Enable high-value injection, credential-access and remote-service effects.
4. Baseline contextual C2, DNS, pipe, fan-out and discovery rules.
5. Enable vendor-specific collection/runtime rules only when the required event mapping is verified.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] Every product event and enrichment field compiles and is populated in the target tenant.
- [ ] Stable process/account/session joins were verified with representative events.
- [ ] Benign deployment, EDR, identity, backup, scanning, remote-admin and runtime hosts were baselined.
- [ ] Missing-source behavior was tested; dependent rules are disabled rather than weakened.

## Unresolved telemetry gaps

- Proprietary internals and arbitrary third-party modules/transports prevent implementation-specific completeness; resulting behaviors are the compensation.
- CSB-003, CSB-010 and CSB-029 are not directly observable without authorized Team Server/client audit.
- Local enumeration, in-memory tasking, self-injection, Interpreter bytecode and user-data capture may have no standard Windows event.
- All rules remain experimental until tenant compilation, parser verification and safe fixture validation.
