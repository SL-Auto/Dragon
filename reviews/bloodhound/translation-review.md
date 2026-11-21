# BloodHound collectors translation review

- Canonical rules: 21 YARA-L rules under `detections/bloodhound/yaral/`.
- Expected secondary drafts: 105 files; 21 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: LDAP requested-attribute enrichment, RPC interface visibility, cloud resource-family enrichment and absence/recurrence semantics require backend-specific implementation.
- Required follow-up: verify basename/source parity, map each backend schema, implement canonical correlations natively, compile and test. No translation may claim equivalence while marked `partial`.

## 2026-11-21 exceptions — five compensating rules

The five compensating rules have hand-authored translations. The other 16 rules still have generator candidate-retrieval drafts. Where the backend can express the canonical intent, these translations implement the aggregation natively instead of selecting candidate events by event type alone.

| Rule | SPL / KQL / SQL | EQL | Sigma | Exceptions |
| --- | --- | --- | --- | --- |
| `bloodhound_ldap_deep_single_category_enumeration` | `high`: native distinct count per host/user/naming context | `partial`: no distinct count | `high`: `value_count` correlation | 4h hop window approximated by hourly schedule over trailing 4h; per-result expansion required (BH-DR-10). |
| `bloodhound_graph_deep_relationship_enumeration` | `high`: regex, URI object capture, principal coalesce | `partial`: no capture or distinct count | `partial`: counts distinct `RequestUri`, over-counts paged reads of one object | KQL targets native `MicrosoftGraphActivityLogs`; SQL regex functions are dialect-specific. |
| `bloodhound_process_to_directory_effect` | `high`: per stable process entity | `partial`: Elastic Defend lacks LDAP query events | `high` | KQL is written for Defender `DeviceEvents` `LdapSearch` with process identity `InitiatingProcessId` + `InitiatingProcessCreationTime`; raw PID alone is not a valid key. |
| `bloodhound_remote_security_configuration_value_reads` | `high`: exact key/value pairs and exclusions | `partial`: no distinct count | `high` | Requires value-level registry read telemetry; Defender `DeviceRegistryEvents` and Windows 4656/4663 cannot supply it (BH-DR-25), so KQL uses a `RegistryReadEvents` placeholder. |
| `bloodhound_samr_alias_membership_fanout` | `high`: Zeek `dce_rpc` endpoint/operation plus UUID/opnum branch | `partial`: no distinct count; Zeek integration lacks opnum | `high`, Zeek `dce_rpc` logsource only | Opnum-only branch needs a vendor NDR rule in Sigma/EQL. |

`high` means the canonical correlation, aggregation and exclusions are expressed natively in the target. It does not mean equivalent or validated. Field mappings remain tenant assumptions, and every file stays `experimental_needs_backend_mapping_and_validation`.
