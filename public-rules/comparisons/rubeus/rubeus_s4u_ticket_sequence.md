# Public-rule comparison: rubeus_s4u_ticket_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_s4u_ticket_sequence.yaral`
- Internal SHA-256: `93dd3e851377f28d89ce8616010950af73c639ea794eeaeaa8b303c5ed0286d2`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-005`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/BloodHound Enterprise/Analytic Rules/KerberosDelegationOnTierZeroObjects.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/BloodHound Enterprise/Analytic Rules/KerberosDelegationOnTierZeroObjects.yaml) - SHA-256 `5ab7a58d4f562869d1c32f6563178399fcef1284b28b5c87b4281807dbc3ed8b`

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

- Candidate improvement: Make the allowed-delegation-edge comparison explicit, add single-target Tier Zero/sensitive-user branches, and retain public configuration exposure as preventive context.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

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
