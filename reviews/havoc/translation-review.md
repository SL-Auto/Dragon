# Havoc translation review

- Canonical rules: 13 YARA-L rules under `detections/havoc/yaral/`.
- Expected secondary drafts: 65 files; 13 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Shared limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Havoc-specific exceptions: recurrent active-minute aggregation, same-process pipe/network and file/network joins, parent/child lineage, memory/token/screen/LSA semantic events, discovery cardinality and sanctioned server audit require backend-native implementation.
- Every translation remains `partial` and `experimental_needs_backend_mapping_and_validation`; none reproduces canonical correlation or aggregation until mapped and tested in its target backend.
- Re-review confirmed basename/source parity and preserved procedure, severity, prerequisites, false-positive and reference metadata. Compile and validate only with authorized sanitized fixtures.
