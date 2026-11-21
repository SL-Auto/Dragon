# ROADtools translation review

- Canonical rules: 17 YARA-L rules under `detections/roadtools/yaral/`.
- Secondary drafts reviewed: 85 files; 17 each in SPL, KQL, SQL, Elastic EQL and Sigma.
- Parity: complete by basename and `source_yaral` linkage.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml` and `schemas/sigma.yml`.
- None of the drafts claims equivalence or validation.

## Exceptions

- **Native renders:** 13 single-event rules (`scripts/native_translations/specs_roadtools.py`) are `high` in SPL, KQL, SQL and Sigma, and `partial` in EQL.
- **Generator candidate retrieval (`partial`):**
  - `roadtools_device_registration_then_prt_signin` and `roadtools_device_registration_then_hello_key`: cross-log ordered joins between audit and sign-in data.
  - `roadtools_seamless_sso_ticket_from_unusual_process`: a Kerberos-to-sign-in join on an enrichment field.
  - `roadtools_federated_signin_without_idp_issuance`: absence logic.
  - The drafts select the participating events only. Each backend needs a native join or absence implementation.
- **Column names:** normalized columns (`auth_protocol`, `incoming_token_type`, `app_id`, `resource_id`, `client_credential_type`, `federated_issuer`, `modified_properties`, `request_uri`) need mapping to the tenant's Entra and Graph fields.
