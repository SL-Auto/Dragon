# Public-rule comparison: rubeus_s4u_ticket_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_s4u_ticket_sequence.yaral`
- Internal SHA-256: `93dd3e851377f28d89ce8616010950af73c639ea794eeaeaa8b303c5ed0286d2`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-005`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/BloodHound Enterprise/Analytic Rules/KerberosDelegationOnTierZeroObjects.yaml`](../../snapshots/microsoft-sentinel/c3361d9ff34320e7fe3314d5f9063e15470ca53e/Solutions/BloodHound Enterprise/Analytic Rules/KerberosDelegationOnTierZeroObjects.yaml) - SHA-256 `5ab7a58d4f562869d1c32f6563178399fcef1284b28b5c87b4281807dbc3ed8b`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Risky delegation relationship exists | Assumed external inventory but not tested | Public BloodHound rule covers delegation on Tier Zero objects | Delegation configuration edge - strong | Authoritative allowed-delegation inventory | public_stronger | Public covers the enabling condition. |
| S4U2Self/protocol transition | 4769 description text plus two targets | Not covered | S4U-specific 4769 fields - strong if parsed | Service-account baseline | ours_stronger | Ours observes runtime impersonation activity. |
| S4U2Proxy reaches target services | Distinct target-service fan-out | Not covered | Unexpected delegation edge plus service target - strong | Resource-side impersonated access | ours_stronger | Public configuration rule cannot show use. |

## Missing detection branches

- Missing from ours: Single-target abuse, authoritative allowed edges, impersonated user, forwardable flags, resource-side effect and parser-safe S4U fields.
- Missing from public rule: Runtime S4U use.
- Missing from both: Legitimate-looking use along an already authorized edge without identity-aware resource telemetry.

## Detection edge cases and blind spots

4769 descriptions rarely expose literal S4U labels consistently; TransitedServices semantics vary. Legitimate web front ends create frequent multi-target S4U activity.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Unexpected S4U edge | strong | ours plus inventory | Close to misuse and specific when the baseline is authoritative. | Requires tenant-specific validation and collection-health monitoring. |
| Delegation on Tier Zero object | strong | public | High-risk precondition, not proof of use. | Requires tenant-specific validation and collection-health monitoring. |
| Two target services | weak | ours | Fan-out alone is common in middleware. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Configuration exposure does not detect exploitation and depends on BloodHound Enterprise data freshness.

## Internal-rule weaknesses

Claims an inventory comparison but implements only textual S4U matching and a two-target threshold; this is a major gap between description and logic.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The 2026-08-16 adoption kept the base two-target branch and added the proposal's unapproved-edge branch.
  - Re-review found the edge branch fired on every S4U ticket when the inventory was absent (unset boolean reads false); it now also requires `delegation_inventory_evaluated = true` (REVIEW-011).
  - Invalid `re.regex ... nocase` replaced with `(?i)` (REVIEW-010).
- Canonical result: `detections/rubeus/yaral/rubeus_s4u_ticket_sequence.yaral`, SHA-256 `9d69d376aacbc278b1ff04ea7cf12471220791ef1a841f1abaa54103b70cf534`.
- Canonical result: `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral`, SHA-256 `3135be137086b6cba19c72bf21974e8aa19f01a4ef42afd3f58e5c79da5a465c`.
- Regeneration: canonical change on 2026-11-21; detection review, coverage, `telemetry/rubeus.md`, `telemetry/MASTER.md` counts, five translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

Public candidates do not cover the full `PROC-005` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Runtime S4U activity across an unauthorized delegation edge, including one sensitive target.
- Required telemetry: 4769 with normalized S4U/delegation context plus authoritative allowed-edge and target-sensitivity enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_s4u_unauthorized_delegation_edge {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-005"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["delegation_flow"].value.string_value = /(S4U2Self|S4U2Proxy)/
    $e.additional.fields["delegation_edge_approved"].value.bool_value = false
    $e.target.user.userid = $service_account
    $e.target.resource.name = $target_service
  condition:
    $e
}
```

Implements the delegation-edge comparison that the current rule only describes and catches a single unauthorized target. The enrichment must be authoritative and freshness-monitored; raw description-text matching should remain compensation only.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| S4U across an unapproved delegation edge | covered when the delegation inventory is present | `KerberosDelegationOnTierZeroObjects.yaml`: BloodHound Enterprise attack-path finding (configuration, not runtime) | 4769 S4U + unapproved edge - strong | two-target S4U fan-out - moderate | different_scope |
| S4U to multiple target services without inventory | covered (>= 2 targets) | not covered | 4769 S4U fan-out - moderate | transport rule - strong | ours_stronger |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_s4u_ticket_sequence.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_s4u_ticket_sequence {
  meta:
    author = "Detection Research Agent"
    description = "Detects a service identity making S4U requests against an authoritatively unapproved delegation edge, or requesting S4U tickets across multiple distinct target services when edge-approval enrichment is unavailable."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Unexpected delegation edges can represent impersonation, but legitimate constrained delegation must be modeled."
    procedure_ids = "PROC-005"
    log_source_prerequisites = "Normalize 4769 with requesting account, client/source, target service, transited services, ticket options, and delegation context, plus an authoritative delegation-edge-approval enrichment keyed by service account and target service. The single-event unapproved-edge branch additionally requires a delegation-inventory enrichment that sets delegation_inventory_evaluated = true; unset UDM booleans read as false, so without that marker the branch would fire on every S4U ticket."
    false_positives = "Approved constrained delegation, protocol transition, web front ends, and identity middleware; stale or incomplete delegation-edge enrichment."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_s4u_ticket_sequence.md; reviews/rubeus/detection-review.md#review-011"
    validation_status = "needs_validation"
    validation_method = "Compare fixtures to an authoritative delegation-edge inventory to validate the unapproved-edge branch; independently confirm the multi-target textual fan-out branch still requires two or more distinct services so it remains a compensating signal rather than the primary detection once edge enrichment is available. Verify which of security_result.description (free text) or additional.fields[delegation_flow] (structured) the parser actually populates for S4U2Self/S4U2Proxy on 4769 events, and confirm both the $e and $u branches keep firing under whichever field is present; do not remove either disjunct without re-testing against real fixtures."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.product_event_type = "4769"
    $e.target.user.userid = $service_account
    $e.target.resource.name = $target_service
    (re.regex($e.security_result.description, `(?i)(S4U2Self|S4U2Proxy|protocol transition|transited services)`) or
     re.regex($e.additional.fields["delegation_flow"].value.string_value, `(?i)(S4U2Self|S4U2Proxy)`))

    $u.metadata.product_event_type = "4769"
    $u.target.user.userid = $service_account
    $u.additional.fields["delegation_edge_approved"].value.bool_value = false
    $u.additional.fields["delegation_inventory_evaluated"].value.bool_value = true
    (re.regex($u.security_result.description, `(?i)(S4U2Self|S4U2Proxy|protocol transition|transited services)`) or
     re.regex($u.additional.fields["delegation_flow"].value.string_value, `(?i)(S4U2Self|S4U2Proxy)`))
  match:
    $service_account over 10m
  outcome:
    $targets = count_distinct($target_service)
  condition:
    ($e and $targets >= 2) or $u
}
```

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_kerberos_transport_from_unexpected_process.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_kerberos_transport_from_unexpected_process {
  meta:
    author = "Detection Research Agent"
    description = "Detects a Windows process other than lsass.exe connecting to a Kerberos KDC (port 88) or the Kerberos password-change service (port 464). This is the client-side network effect of ticket requests, roasting, delegation abuse or password change performed by a tool that implements its own Kerberos transport instead of using the LSA."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "On domain-joined Windows hosts, Kerberos AS/TGS and kpasswd exchanges are normally sent by the LSA (lsass.exe). A user-mode process speaking Kerberos directly is uncommon, independent of tool names, and sits on the path of every Rubeus ticket operation (raw TcpClient transport, Networking.cs L116-160)."
    procedure_ids = "PROC-001,PROC-002,PROC-003,PROC-004,PROC-005,PROC-012"
    log_source_prerequisites = "Process-attributed network-connection telemetry (Sysmon Event ID 3 or EDR equivalent, NETWORK_CONNECTION) with destination port, host and initiating process image path. Windows hosts are identified by a drive-letter image path."
    false_positives = "Java and other cross-platform applications with their own Kerberos stack, MIT Kerberos for Windows, identity-synchronization and password-management agents, and authorized security assessment tools; approve them by image path and signer after validation. Domain controllers should be scoped separately if their KDC-to-KDC traffic is attributed to processes other than lsass.exe."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_unusual_kerberos_password_change.md; public-rules/comparisons/rubeus/rubeus_kerberoast_sequence.md; reviews/rubeus/detection-review.md#review-015"
    validation_status = "needs_validation"
    validation_method = "Confirm on sanitized endpoint telemetry that ordinary logon, ticket renewal and interactive or scripted password changes appear only from lsass.exe, inventory approved non-LSA Kerberos clients, and replay a fixture of a non-LSA process connecting to ports 88 and 464."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    ($e.target.port = 88 or $e.target.port = 464)
    $e.principal.hostname = $host
    $e.principal.process.file.full_path = $process
    re.regex($e.principal.process.file.full_path, `(?i)^[a-z]:\\`)
    not re.regex($e.principal.process.file.full_path, `(?i)^[a-z]:\\windows\\system32\\lsass\.exe$`)
  match:
    $host, $process over 10m
  outcome:
    $ports = array_distinct($e.target.port)
    $destinations = array_distinct($e.target.ip)
    $connections = count($e.metadata.id)
    $accounts = array_distinct($e.principal.user.userid)
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
