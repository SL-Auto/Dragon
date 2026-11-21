# AdaptixC2 telemetry requirements

Scope: the victim-side beacon and gopher agents at revision `e99535c9ef4642190f7ea125c2983d1611f1a3f3`.

## Consolidated collection plan

| Capability ID | Provider / product | Event types or IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Rules / procedures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AX-TEL-01 | Process-attributed network | Sysmon Event ID 3 / `NETWORK_CONNECTION` (OUTBOUND, INBOUND, LISTEN; TCP and UDP) | host, process ID, image, signer status, protocol, destination IP and port | Log UDP and all destinations without port filtering | 10 minutes to 1 hour per process | UDP or port filtering (AX-DR-02) | transport, tunnel, child, archive, RWX and screenshot rules; AX-P01 to AX-P05, AX-P07, AX-P09, AX-P10 |
| AX-TEL-02 | Named pipes and SMB | Sysmon Event ID 17 and 18; Security 5145 | pipe name (normalized), image, source address, share | Enable PipeEvent and Detailed File Share auditing | 30 minutes per host and pipe | Name normalization (AX-DR-03) | `adaptix_named_pipe_server_with_network_peer`; AX-P03 |
| AX-TEL-03 | Process creation | Sysmon Event ID 1 / `PROCESS_LAUNCH`; Security 4688 | parent process ID and command line, child image and command line, user | Command-line capture | 15 to 30 minutes | none | child and seclogon rules; AX-P05 |
| AX-TEL-04 | File creation | Sysmon Event ID 11 / `FILE_CREATION` | path, process ID | Enable for user and temp paths | 15 minutes | none | archive rule; AX-P07 |
| AX-TEL-05 | EDR memory and screen capture | Vendor `MEMORY_PROTECTION` / `VIRTUAL_ALLOC`, `SCREEN_CAPTURE` | process ID, protection, host | Vendor-specific | 10 minutes | Not in Sysmon (AX-DR-05) | RWX and screenshot rules; AX-P06, AX-P10 |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `adaptix_raw_socket_dns_from_user_process` | AX-P02 | AX-TEL-01 | UDP/53 connections per process | signer | UDP not logged |
| `adaptix_recurrent_process_egress` | AX-P01, P04 | AX-TEL-01 | Outbound connections per process and destination | signer | none |
| `adaptix_named_pipe_server_with_network_peer` | AX-P03 | AX-TEL-02 | Pipe creation and 5145 with normalized names | none | Name normalization (AX-DR-03) |
| `adaptix_tcp_bind_listener_with_internal_peer` | AX-P03, P09 | AX-TEL-01 | LISTEN and INBOUND events | signer | LISTEN not logged |
| `adaptix_tunnel_internal_fanout` | AX-P09 | AX-TEL-01 | Outbound to external and internal destinations | signer | Internal destinations filtered |
| `adaptix_network_process_spawns_child` | AX-P05 | AX-TEL-01, 03 | Egress and child launch by process ID | signer | none |
| `adaptix_secondary_logon_hidden_interpreter` | AX-P05 | AX-TEL-03 | Parent command line | none | No parent command line |
| `adaptix_rwx_memory_in_network_process` | AX-P06 | AX-TEL-01, 05 | EDR RWX events | signer | No vendor event (AX-DR-05) |
| `adaptix_network_process_archive_staging` | AX-P07 | AX-TEL-01, 04 | .zip creation and egress | signer | none |
| `adaptix_screen_capture_then_egress` | AX-P10 | AX-TEL-01, 05 | EDR screen-capture events | signer | No vendor event |

## Deployment order

1. Unfiltered process-attributed network logging, including UDP (AX-TEL-01).
2. Pipe and share auditing with name normalization (AX-TEL-02).
3. Process creation and EDR memory events.

## Validation checklist

- [x] Every current YARA-L rule appears in the rule matrix.
- [ ] UDP logging and pipe-name normalization were verified.

## Unresolved telemetry gaps

- API-only discovery (AX-P08) and runtime behavior (AX-P11) are not observable; compensating signals are named in the review.
