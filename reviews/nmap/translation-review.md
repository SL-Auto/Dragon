# Nmap translation review

- Canonical rules: 13 YARA-L rules under `detections/nmap/yaral/`.
- Secondary drafts reviewed: 65 files; 13 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders:** all 13 rules are single-event aggregations, rendered by `scripts/native_translations/specs_nmap.py`. SPL, KQL, SQL and Sigma are `high` and EQL is `partial`, except for the three rules below.
- **Rules downgraded to `partial` in every backend:**
  - `nmap_process_connect_scan_fanout`
  - `nmap_network_scan_flow_pattern`
  - `nmap_auth_failure_fanout_from_source`
  - Their canonical conditions are a disjunction of two distinct counts (hosts or ports; accounts or hosts). The renderer expresses only the first count (distinct destination IPs, or distinct accounts). The second branch must be added per backend, for example `dc(target_port) >= N` in SPL or a second `count_distinct` in KQL.
- **Field map:** `original_file_name`, `parent_command_line` and `signer` were added to the shared ECS map in `translate_lib.py`.
- **IP regex:** the internal-range regex approximates the canonical `net.ip_in_range_cidr`. Tenants with typed IP columns should use native CIDR predicates.
