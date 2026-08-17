# <Tool> telemetry requirements

## Scope

- Tool revision:
- Detection files:
- Generated/reviewed:
- Status: `draft | complete_for_experimental_rules`

## Consolidated collection plan

| Capability ID | Provider / product | Events / IDs | Required fields | Enablement / configuration | Retention / correlation | Known gaps | Supports |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TEL-001 | | | | | | | Rules and procedure IDs |

## Rule-by-rule requirements

| YARA-L rule | Procedures | Capability IDs | Minimum viable telemetry | Optional enrichment | Failure mode if absent |
| --- | --- | --- | --- | --- | --- |
| `<rule_name>` | | | | | |

## Deployment order

## Validation checklist

- [ ] Every YARA-L rule appears exactly once in the rule matrix.
- [ ] Provider/parser mappings were verified in the target tenant.
- [ ] Required fields are populated in representative events.
- [ ] Retention supports every correlation window and absence check.
- [ ] Missing-source behavior and compensating signals were tested.
- [ ] Collection volume, privacy, and access controls were reviewed.

## Unresolved telemetry gaps
