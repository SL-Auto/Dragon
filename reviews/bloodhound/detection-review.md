# BloodHound collectors adversarial detection-logic review

## Overall assessment

The 21 canonical YARA-L rules cover all 20 procedure families through shared observability (16 original rules plus five compensating rules adopted from public-rule comparisons and adversarially reviewed on 2026-11-21, findings BH-DR-10 to BH-DR-24). They detect directory/cloud enumeration effects, RPC/SMB fanout, sensitive reads and collection artifacts; they do not identify BloodHound by themselves. All rules remain experimental and require tenant field mapping, enrichment and authorized fixtures.

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

## 2026-11-21 delta review — five comparison-adopted compensating rules

Scope: `bloodhound_ldap_deep_single_category_enumeration`, `bloodhound_graph_deep_relationship_enumeration`, `bloodhound_process_to_directory_effect`, `bloodhound_remote_security_configuration_value_reads`, `bloodhound_samr_alias_membership_fanout`. These were written into `yaral/` on 2026-08-16 from comparison proposals and carried `review_status = "reviewed_with_gaps"` with no matching findings. That metadata was not backed by a review.

Evidence:

- AzureHound `23735c8` client sources.
- BloodHound CE `5e8e78e` ingest model `packages/go/ein/ad.go#L121-L146`, read only to see which registry values the collector reports.
- MS-SAMR opnum assignments.
- Microsoft KB5014754 registry locations (analyst inference, labelled).

### BH-DR-10 — per-result LDAP object identity

- Severity: `high`
- Rule: `bloodhound_ldap_deep_single_category_enumeration`
- Assumption challenged: LDAP_SEARCH/1644 events carry one identity per returned object.
- Gap or failure mode: Directory Service 1644 and most EDR LDAP events summarise a query (base, filter, entries visited/returned). They do not list each result object. The rule cannot reach 500 distinct objects unless the parser expands results.
- Resolution: `accepted_gap`. The limitation comes from the summary telemetry itself. YARA-L also cannot safely sum the string-typed entries-returned label across vendors. Prerequisites now state the expansion requirement explicitly. Compensating signals: `bloodhound_ldap_directory_discovery_fanout` (category breadth) and DC-side 1644 expensive-search thresholds.

### BH-DR-11 — throttled collection outside 30-minute window

- Severity: `medium`
- Rule: `bloodhound_ldap_deep_single_category_enumeration`
- Gap or failure mode: the comparison claimed coverage of slow collection, but a 30-minute window misses throttled or looped collection (BH-014).
- Resolution: `fixed`. Window widened to 4h, consistent with BH-TEL-01 retention and the recurrence rule. The 500-object threshold is unchanged; a `$domain_controllers` outcome now shows multi-DC distribution.

### BH-DR-12 — naming-context partitioning

- Severity: `low`
- Rule: `bloodhound_ldap_deep_single_category_enumeration`
- Gap or failure mode: grouping by naming context splits one collection across domain/configuration/schema NCs; domains smaller than 500 objects never match.
- Resolution: `accepted_gap`. The domain NC alone exceeds the threshold in realistic estates. Small domains are covered by category fanout.

### BH-DR-13 — Graph relationship endpoints missing

- Severity: `high`
- Rule: `bloodhound_graph_deep_relationship_enumeration`
- Assumption challenged: the URI regex covers AzureHound relationship reads.
- Gap or failure mode: AzureHound reads `/groups/{id}/members`, `/groups|applications|servicePrincipals/{id}/owners`, `/servicePrincipals/{id}/appRoleAssignedTo` and `/devices/{id}/registeredOwners` (`client/groups.go#L50-L66`, `apps.go#L51`, `service_principals.go#L50`, `app_role_assignments.go#L33`, `devices.go#L50`). The canonical regex matched only `owners`: it omitted `members`, `appRoleAssignedTo`, `registeredOwners` and the `devices` family.
- Resolution: `fixed`. Regex now covers members/transitiveMembers/memberOf/transitiveMemberOf/owners/registeredOwners/registeredUsers/appRoleAssignedTo/appRoleAssignments across users/groups/servicePrincipals/applications/devices, with an anchored path segment.

### BH-DR-14 — app-only principals dropped by zero-value filtering

- Severity: `high`
- Rule: `bloodhound_graph_deep_relationship_enumeration`
- Gap or failure mode: AzureHound supports app/secret/certificate authentication (`config/config.go#L144-L158`). App-only Graph activity has an empty UserId, and YARA-L drops zero-valued match variables by default, so app-only collection never matched.
- Resolution: `fixed`. The principal is now `strings.coalesce(userid, product_object_id)`, where ServicePrincipalId maps to `principal.user.product_object_id`. The public candidate set at `elastic-security@9d792a8` independently groups app-only Graph reconnaissance by service principal ID; this corroborates the fix but was not its source.

### BH-DR-15 — target object identity not populated

- Severity: `high`
- Rule: `bloodhound_graph_deep_relationship_enumeration`
- Gap or failure mode: Graph activity logs carry the target object only inside the request URI. `target.resource.name` is normally empty, so `count_distinct` would be zero or one.
- Resolution: `fixed`. The object is captured from the URI path segment with `re.capture`.

### BH-DR-16 — unreferenced event variable

- Severity: `blocker`
- Rule: `bloodhound_process_to_directory_effect`
- Gap or failure mode: `$q` was defined in `events` but absent from `condition`. YARA-L requires every event variable to be referenced in the condition, so the rule would not compile.
- Resolution: `fixed`. The rule was restructured (see BH-DR-18) and the condition is now `$q and $objects >= 25`.

### BH-DR-17 — cloud audit branches cannot join on endpoint PID

- Severity: `high`
- Rule: `bloodhound_process_to_directory_effect`
- Gap or failure mode: MicrosoftGraphActivityLogs and Azure read-plane audits carry no endpoint host/PID. Their branches could never satisfy the host+PID join, which gave false assurance of cloud coverage.
- Resolution: `fixed` (scope narrowed). The rule now uses only endpoint-attributed LDAP_SEARCH. The cloud branch is `accepted_gap` because cloud audit lacks process identity by design. It is compensated by `bloodhound_collector_process_network_context` (process-attributed Graph/ARM connections) and `bloodhound_cloud_collection_output` (host/user join).

### BH-DR-18 — launch-event dependency excluded the targeted branch

- Severity: `high`
- Rule: `bloodhound_process_to_directory_effect`
- Gap or failure mode: requiring a PROCESS_LAUNCH within 20 minutes excluded collectors started earlier or loaded into a long-lived host process. That was exactly the "common host processes loading collector code" branch the comparison said it would close.
- Resolution: `fixed`. The launch requirement was removed. The rule aggregates distinct objects/search bases per host and stable process entity over 30m, and carries process path and account as outcomes.

### BH-DR-19 — LDAP object/search-base proxy

- Severity: `medium`
- Rule: `bloodhound_process_to_directory_effect`
- Gap or failure mode: EDR LDAP events are one per query. Collectors that issue a few large paged queries yield few distinct search bases, while per-object resolution lookups yield many.
- Resolution: `compensating_signal`. `target.resource.name` is defined in prerequisites as the search base DN or per-result object. Large paged-query collection is covered by `bloodhound_ldap_directory_discovery_fanout` and `bloodhound_ldap_deep_single_category_enumeration`.

### BH-DR-20 — registry key/value pairing never matched collected values

- Severity: `blocker`
- Rule: `bloodhound_remote_security_configuration_value_reads`
- Assumption challenged: the key and value regexes describe what SharpHound reads.
- Gap or failure mode:
  - `StrongCertificateBindingEnforcement` lives under `Services\Kdc` and `CertificateMappingMethods` under `Control\SecurityProviders\Schannel`; neither key was in the key regex.
  - `RestrictNTLM` is not a substring of any collected NTLM value. The collected values are `RestrictSendingNtlmTraffic`, `RestrictReceivingNTLMTraffic`, `NtlmMinClientSec`, `NtlmMinServerSec`, `LmCompatibilityLevel`, `UseMachineId` and `ClientAllowedNTLMServers` (`ein/ad.go#L121-L146`).
  - `LDAPServerIntegrity`/`LdapEnforceChannelBinding` are not evidenced as collector registry reads; LDAP signing and channel binding are probed over the network under BH-013.
  - The rule could therefore match essentially none of BH-012.
- Resolution: `fixed` (rewrite). Explicit key/value pairs now cover the Kdc, Schannel, Lsa/MSV1_0 and CertSvc configuration families (`Security`, `EnrollmentAgentRights`, `EditFlags`; CA value names are labelled inference from Microsoft CA configuration documentation).

### BH-DR-21 — owning-service local reads

- Severity: `high`
- Rule: `bloodhound_remote_security_configuration_value_reads`
- Gap or failure mode: lsass (KDC, MSV1_0, Schannel), certsrv and services.exe read these values continuously. Under a SACL or EDR read telemetry, they would dominate matches.
- Resolution: `fixed`. Owning-service images and local well-known service identities (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) are excluded, but machine accounts are not. A remote collector running as SYSTEM elsewhere authenticates as `HOST$` and therefore still matches. The match key is now actor + target, because 4663 logs on the target and has no remote source host. Residual false negative: a collector running locally as SYSTEM on the DC/CA itself. That case is compensated by `bloodhound_remote_security_configuration_reads` and the process/network rules.

### BH-DR-22 — opnum-only RPC sensors

- Severity: `medium`
- Rule: `bloodhound_samr_alias_membership_fanout`
- Gap or failure mode: sensors that expose interface UUID and opnum but not operation names bypassed the name regex.
- Resolution: `fixed`. Added an alternative branch: SAMR UUID `12345778-1234-abcd-ef00-0123456789ac` with opnum 15 (SamrEnumerateAliasesInDomain) or 33 (SamrGetMembersInAlias), per MS-SAMR.

### BH-DR-23 — procedure scope divergence from proposal

- Severity: `low`
- Rule: `bloodhound_samr_alias_membership_fanout`
- Gap or failure mode: the comparison proposal tagged BH-009 and BH-010, but the rule observes only SAMR; LSA user-rights reads (BH-010) use a different interface.
- Resolution: `fixed`. The rule is tagged BH-009 only. BH-010 remains linked to `bloodhound_samr_local_group_enumeration`.

### BH-DR-24 — single sensitive host

- Severity: `medium`
- Rule: `bloodhound_samr_alias_membership_fanout`
- Gap or failure mode: a three-target threshold misses enumeration of one tier-0 host.
- Resolution: `accepted_gap`. Single-host alias reads are routine (administration consoles, LAPS, PAM). A single-target branch is safe only with asset-criticality enrichment, which is absent from the declared telemetry. Compensating signals: remote session/registry rules and SMB/RPC host sweep.

### BH-DR-25 — native registry audit lacks value name

- Severity: `high`
- Rule: `bloodhound_remote_security_configuration_value_reads`
- Found during: secondary translation mapping (second review pass).
- Assumption challenged: Windows Security 4656/4663 carry the registry value name.
- Gap or failure mode: 4656/4663 for registry objects record the key path (`ObjectName`), process, subject and access mask (for example "Query key value"). They do not record the value name, and 4657 (which does) covers modifications only. The native branch would leave `registry_value_name` empty, so it could never match while implying native-log coverage.
- Resolution: `fixed` (scope narrowed). The rule now requires EDR `REGISTRY_READ` with value-name visibility. Native key-level reads remain covered by `bloodhound_remote_security_configuration_reads`. Native value-level visibility is an `accepted_gap` inherent to the Windows audit schema.

### BH-DR-26 — unanchored short event-ID alternations

- Severity: `high`
- Rules: `bloodhound_cloud_collection_output`, `bloodhound_collection_archive_creation`.
- Gap or failure mode: `/(11|FILE_CREATION)/` and `/(11|FILE_CREATION|4697|7045)/` matched any ID containing `11`, including 1102 (audit log cleared), 4611 and 5011.
- Resolution: `fixed`. The alternations are anchored `^(...)$`. The same defect was fixed in Impacket (REVIEW-009).

### Re-review of revised rules

All five revised rules were re-traced branch by branch after the changes above:

- No `blocker` remains.
- Every event variable is referenced in its condition.
- Every regex is tied to source-evidenced endpoints or values.
- All match variables are populated for both delegated and app-only identities.
- Exclusions remove only owning-service or local-service identities and do not exclude machine accounts.
- Remaining `accepted_gap` items (BH-DR-10, BH-DR-12, BH-DR-17 cloud branch, BH-DR-24, BH-DR-25 native value names) each name a compensating rule.

## Required follow-up

- Compile every rule against the tenant YARA-L version and verify each UDM field/provider mapping.
- Test approved inventory/CSPM/identity-governance products as negatives.
- Test threshold boundaries, reordered events, missing events, PID reuse, concurrent users and incomplete DC/cloud audit coverage.
- Do not enable enrichment-dependent rules until collection-health monitoring proves the required fields are populated.
- No unresolved blocker remains; all accepted gaps are telemetry limitations with compensating signals.
