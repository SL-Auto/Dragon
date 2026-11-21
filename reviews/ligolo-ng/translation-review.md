# Ligolo-ng translation review

- Canonical rules: 7 YARA-L rules under `detections/ligolo-ng/yaral/`.
- Secondary drafts reviewed: 35 files; 7 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders (`scripts/native_translations/specs_ligolo.py`):** `ligolo_agent_ping_probe_children`, `ligolo_websocket_default_user_agent`, `ligolo_process_internal_admin_port_sweep` and `ligolo_agent_command_line_trust_flags`.
  - SPL, KQL, SQL and Sigma are `high`; EQL is `partial`, because it cannot aggregate.
  - The ping rule's distinct-command threshold is per host and parent process ID.
  - Field names `command_line`, `parent_process_path`, `parent_process_id` and `user_agent` were added to the shared ECS map in `translate_lib.py`.
  - The admin-port sweep approximates the canonical `net.ip_in_range_cidr` checks with a text regex over the destination IP, and lists ports as strings; tenants with typed IP or port columns should use native CIDR and integer predicates.
  - Signature status maps to `process_signed` / `process.code_signature.trusted`, which is close to but not identical with UDM `verification_status = VERIFIED`.
- **Generator candidate retrieval (`scripts/translate-yaral.ps1`), `partial`:**
  - `ligolo_tunnel_process_internal_fanout`
  - `ligolo_bind_listener_internal_fanout`
  - `ligolo_agent_listener_with_tunnel_egress`
  - These drafts select `NETWORK_CONNECTION` events only. They do not express the per-process join, the internal versus non-internal CIDR split, the direction legs, the signature exclusion or the distinct-destination and distinct-port thresholds. A native per-backend implementation is required before use.
