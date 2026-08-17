# BloodHound collectors translation review

- Canonical rules: 16 YARA-L rules under `detections/bloodhound/yaral/`.
- Expected secondary drafts: 80 files; 16 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: LDAP requested-attribute enrichment, RPC interface visibility, cloud resource-family enrichment and absence/recurrence semantics require backend-specific implementation.
- Required follow-up: verify basename/source parity, map each backend schema, implement canonical correlations natively, compile and test. No translation may claim equivalence while marked `partial`.
