# Havoc telemetry requirements

## Scope

- Tool revision: `c84f7755a8b1c0f737576bdd3a0e982a296012f1`
- Canonical rules: 12 under `detections/havoc/yaral/`
- Status: `complete_for_experimental_rules`

## Consolidated collection plan

| ID | Provider / product | Atomic event IDs or types | Required fields | Enablement / configuration and retention | Known gaps | Rules/procedures |
| --- | --- | --- | --- | --- | --- | --- |
| HV-T01 | EDR normalized process/network | `PROCESS_LAUNCH`, `PROCESS_TERMINATION`, `NETWORK_CONNECTION`, `NETWORK_LISTEN` | host, process GUID/PID, parent GUID/PID, image, command line, account, direction, addresses, ports, timestamp | Enable process-attributed connect/listen; retain 14 days for baselines and at least 30 minutes online correlation | PID reuse and missing process attribution | recurrent, spawn, file, memory, capture, forwarding, cleanup; HV-P01,03,05–11,14,16,20 |
| HV-T02 | Microsoft Sysmon | Event IDs `1`, `10`, `17`, `18`, `23`, `26` | ProcessGuid, Source/TargetProcessGuid, GrantedAccess, PipeName, TargetFilename, user, hashes | Deploy a reviewed Sysmon configuration; retain 14 days | Event 10 volume and pipe/file parser variance | named pipe, spawn, file, memory, cleanup; HV-P02,05,08,11,15,20 |
| HV-T03 | Windows Security | Event IDs `4648`, `4769` | subject/target account, logon ID, source host/IP, service name, ticket fields, result | Enable advanced audit policy on endpoints/DCs; retain 30 days | Token API operations and cache mutation may not appear | token and Kerberos rules; HV-P12,17 |
| HV-T04 | EDR sensitive semantic events | `PROCESS_ACCESS`, `PROCESS_INJECTION`, `REMOTE_THREAD`, `MEMORY_EXECUTION`, `CLR_ASSEMBLY_LOAD`, `SCREEN_CAPTURE`, `TOKEN_DUPLICATE`, `TOKEN_IMPERSONATION`, `TOKEN_CREATE`, `KERBEROS_TICKET_PURGE`, `KERBEROS_TICKET_SUBMIT`, `LSA_KERBEROS_OPERATION` | stable source/target process, account/LUID, operation, access mask, runtime, result | Enable only after tenant parser verification; retain 14 days | Product availability and semantics vary; disable unbound rules | memory, token, capture, Kerberos; HV-P09–12,14,17 |
| HV-T05 | EDR file telemetry | `FILE_READ`, `FILE_CREATION`, `FILE_MODIFICATION`, `FILE_DELETION` | process GUID/PID, operation, path, hash, bytes, account | Enable sensitive read and lifecycle telemetry; retain 14 days | Reads/listings often absent and high-volume | file and cleanup; HV-P06–08,20 |
| HV-T06 | Directory/network sensors | `LDAP_SEARCH`, `SMB_SESSION`, `RPC_CALL`, `PROCESS_DISCOVERY`; AD DS `1644`; Security `5140`, `5145` | process/source, account, target, attributes/interfaces/share, result | Enable selective 1644 diagnostics, share auditing and EDR discovery; retain 30 days | Local native discovery and low-volume queries may miss | discovery; HV-P04,13 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capabilities | Minimum viable telemetry | Failure mode if absent |
| --- | --- | --- | --- | --- |
| `havoc_recurrent_process_egress` | HV-P01,HV-P03 | HV-T01 | Repeated outbound `NETWORK_CONNECTION` with stable process identity | No recurrence or process attribution |
| `havoc_stable_destination_beaconing` | HV-P01,HV-P03 | HV-T01 | Repeated outbound `NETWORK_CONNECTION` with stable process and destination identity | Destination/process absent or channels rotate destinations |
| `havoc_named_pipe_network_context` | HV-P02,HV-P15 | HV-T01,HV-T02 | Sysmon 17/18 or EDR pipe event plus same-process network | Pipe events or stable entity absent |
| `havoc_spawned_command_execution` | HV-P05 | HV-T01,HV-T02 | Process launch with parent identity and parent network | Parent spoofing or parser mismatch |
| `havoc_file_activity_from_network_process` | HV-P06–HV-P08 | HV-T01,HV-T05 | File lifecycle plus same-process egress | Reads/listing or process field absent |
| `havoc_memory_execution_from_network_process` | HV-P09–HV-P11 | HV-T01,HV-T02,HV-T04 | Verified memory/process semantic plus egress | Vendor event unavailable or unbound |
| `havoc_token_authentication_sequence` | HV-P12 | HV-T01,HV-T03,HV-T04 | 4648 or verified token event plus same-account process | Token API telemetry and session join absent |
| `havoc_discovery_fanout` | HV-P04,HV-P13 | HV-T06 | Process-attributed discovery targets | Low-volume/native discovery unlogged |
| `havoc_screen_capture_then_egress` | HV-P14 | HV-T01,HV-T04 | Verified capture event plus same-process egress | No screen-capture semantic |
| `havoc_listener_and_forwarding` | HV-P16 | HV-T01 | Same process listen and outbound connect | Listen or process direction absent |
| `havoc_kerberos_ticket_effect` | HV-P17 | HV-T03,HV-T04 | Verified ticket mutation plus 4769/resource use | LSA event or account join absent |
| `havoc_cleanup_after_network_activity` | HV-P20 | HV-T01,HV-T02,HV-T05 | Deletion/termination plus prior same-process egress | Helper/delayed cleanup loses identity |

## Non-observable compensation

- HV-P18 memory-file state: monitor subsequent memory execution, file, process and network effects.
- HV-P19 job/transfer bookkeeping: monitor resulting thread, process, file and flow state.

## Validation checklist

- [x] Every canonical rule appears once in the matrix.
- [x] Every coverage procedure resolves to detected or not-observable.
- [ ] Chronicle UDM fields compile in the target tenant.
- [ ] Parser semantics and stable entities are verified with sanitized fixtures.
- [ ] Thresholds and benign administrative populations are baselined.
