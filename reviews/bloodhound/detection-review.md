# BloodHound collectors adversarial detection-logic review

## Overall assessment

The 16 canonical YARA-L rules cover all 20 procedure families through shared observability. They detect directory/cloud enumeration effects, RPC/SMB fanout, sensitive reads and collection artifacts; they do not identify BloodHound by themselves. All rules remain experimental and require tenant field mapping, enrichment and authorized fixtures.

## Findings

### BH-DR-01 — tool attribution

- Severity: `high`
- Assumption challenged: broad LDAP, Graph, ARM or RPC enumeration identifies BloodHound.
- Gap or failure mode: governance, CSPM, identity inventory and assessment products can produce the same effects; renamed or embedded collectors defeat process-name indicators.
- Resolution: `fixed`. Rules use behavior/effect predicates, never collector names or default filenames. Metadata and report explicitly prohibit tool attribution from a single match.

### BH-DR-02 — cloud RBAC field collision

- Severity: `blocker`
- Assumption challenged: a product event-type field contains the RBAC operation name.
- Gap or failure mode: the initial rule tested operation keywords against `metadata.product_event_type`, which normally contains the log type and could never match the intended operation.
- Resolution: `fixed`. `bloodhound_azure_rbac_enumeration` now requires the normalized operation field and uses product event type only to select the cloud audit source.

### BH-DR-03 — cloud output false join

- Severity: `high`
- Assumption challenged: any cloud audit and any file/service event on a host within 30 minutes are causally related.
- Gap or failure mode: unrelated users and routine file creation could join, especially on shared collectors or servers.
- Resolution: `fixed`. The rule now joins host and user and constrains the local effect to JSON creation or a service lifecycle event. Stable process/network correlation remains preferred enrichment.

### BH-DR-04 — recurrence threshold and jitter

- Severity: `medium`
- Assumption challenged: a fixed event-count threshold captures looped collection without noise.
- Gap or failure mode: throttling/jitter may lower counts while monitoring products may exceed them.
- Resolution: `fixed`. The recurrence rule also requires rare-process enrichment and distinct-target breadth; metadata calls for irregular and missing-interval fixtures. The absolute threshold remains a tenant-tuned hypothesis.

### BH-DR-05 — provider/parser collisions

- Severity: `high`
- Assumption challenged: numeric IDs such as 11, 1644, 4662 and 5145 are globally unique.
- Gap or failure mode: event IDs collide across providers and normalized schemas; 4662 is not a general LDAP-read event.
- Resolution: `compensating_signal`. Prerequisites bind each ID to its provider/product mapping and prefer normalized named types. The report limits 4662 to applicable SACL/access semantics and uses LDAP_SEARCH/1644 as primary directory-query evidence.

### BH-DR-06 — enrichment dependencies

- Severity: `high`
- Assumption challenged: `resource_family`, `provider_family`, requested LDAP attributes, process prevalence and RPC operation fields exist by default.
- Gap or failure mode: rules silently fail when enrichment is absent.
- Resolution: `compensating_signal`. These fields are explicit telemetry prerequisites; dependent rules must stay disabled until mappings are verified. Network fanout, SYSVOL reads and artifact lifecycle provide compensation where rich query telemetry is unavailable.

### BH-DR-07 — remote enumeration visibility

- Severity: `medium`
- Assumption challenged: native Windows logs expose NetSessionEnum, SAMR and LSA read operations.
- Gap or failure mode: authentication/share events may exist without the actual RPC operation.
- Resolution: `accepted_gap`. Rules require verified EDR/NDR RPC interface telemetry. Without it, retain only process-attributed SMB/RPC fanout as lower-specificity compensation.

### BH-DR-08 — entity joins and PID reuse

- Severity: `medium`
- Assumption challenged: PID or host/user joins always represent one collector execution.
- Gap or failure mode: PID reuse and concurrent administration can false-join events.
- Resolution: `compensating_signal`. Prefer stable process entity IDs and cloud correlation IDs; rules using weaker joins explicitly remain experimental and use bounded windows.

### BH-DR-09 — mutable archive behavior

- Severity: `low`
- Assumption challenged: a fixed BloodHound ZIP name is reliable.
- Gap or failure mode: filenames can be randomized or output can remain uncompressed.
- Resolution: `fixed`. The archive rule uses same-process multi-JSON lifecycle and generic archive extensions, with directory/network rules compensating for no-archive execution.

## Required follow-up

- Compile every rule against the tenant YARA-L version and verify each UDM field/provider mapping.
- Test approved inventory/CSPM/identity-governance products as negatives.
- Test threshold boundaries, reordered events, missing events, PID reuse, concurrent users and incomplete DC/cloud audit coverage.
- Do not enable enrichment-dependent rules until collection-health monitoring proves the required fields are populated.
- No unresolved blocker remains; all accepted gaps are telemetry limitations with compensating signals.
