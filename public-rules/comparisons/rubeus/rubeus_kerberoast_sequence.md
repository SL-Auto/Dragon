# Public-rule comparison: rubeus_kerberoast_sequence

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_kerberoast_sequence.yaral`
- Internal SHA-256: `f70f549433ef69b82d59788dab687605fb3903ada30efd3490751bfea5d593b7`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-004`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/SecurityEvent/PotentialKerberoast.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/SecurityEvent/PotentialKerberoast.yaml) - SHA-256 `747d8097f4af3b53bd1d3093223a149055eac51ac600d1e272b42d9567028f51`
- [`public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/Microsoft Defender XDR/Analytic Rules/Execution/PotentialKerberoastActivities.yaml`](../../snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Solutions/Microsoft Defender XDR/Analytic Rules/Execution/PotentialKerberoastActivities.yaml) - SHA-256 `1c2463290723bcc6a52ee4cff785a594ed83ff0c831238062dce9a53b74cea5a`
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberoasting_unusual_process.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberoasting_unusual_process.toml) - SHA-256 `cbabbfa8cacdc7c5a023087dfd6c81a87cf485f66edb56da36bb45ae56b591dc`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| SPN-bearing accounts discovered | LDAP filter for servicePrincipalName | Not required by public rules | LDAP SPN search - moderate | Directory query fan-out and caller context | ours_stronger | Ours captures reconnaissance immediately preceding requests. |
| Roastable service tickets requested | Five services after LDAP search | Sentinel detects RC4/options burst; MDE uses Kerberoast-tagged identity events; Elastic uses unusual process Kerberos traffic | 4769 RC4/options plus service fan-out - strong | Unusual process-to-KDC flow | complementary | Public rules cover ticket properties and single-stage activity; ours adds ordered reconnaissance. |
| Single high-value SPN requested | Below five-service threshold | RC4/options or MDE enriched event may detect | Rare RC4 request for sensitive SPN - strong | First-seen requester-to-SPN relationship | public_stronger | Public ticket-property branches cover targeted low volume better. |

## Missing detection branches

- Missing from ours: Targeted single-SPN requests; roasting without visible LDAP; distributed or slow fan-out; encryption/ticket-option risk.
- Missing from public rule: LDAP-to-TGS ordered sequence and non-RC4 roastable tickets.
- Missing from both: Offline cracking and credential use without later correlated authentication.

## Detection edge cases and blind spots

Legitimate service discovery produces the same LDAP filter. Modern AES-capable service accounts reduce RC4 usefulness. Host/user joins can fail when DC events lack hostname or use different identity forms.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| 4769 RC4 with roast-associated options | strong | public | Close to a roastable ticket request and more specific than volume alone. | Requires tenant-specific validation and collection-health monitoring. |
| LDAP SPN search followed by TGS fan-out | strong | ours | Ordered procedure coverage, dependent on rare LDAP telemetry. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process using Kerberos | moderate | public | Broad but useful when DC fields are incomplete. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

RC4-only logic misses AES requests and may rely on fragile option constants; MDE technique tags are opaque upstream enrichment.

## Internal-rule weaknesses

Requires LDAP visibility and five services, omits ticket encryption/options, and can miss targeted or tool-separated activity.

## Decision trail

- Candidate improvement: Improve ours with an independent 4769 RC4/rare-SPN branch and allow the LDAP sequence to remain a high-confidence branch; do not copy fixed public thresholds without tenant evidence.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-004` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: Kerberoasting without visible LDAP reconnaissance, including low-volume RC4 service-ticket acquisition.
- Required telemetry: DC Security 4769 with encryption type, ticket options, requester, service/SPN, source and an approved legacy-service enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_kerberoast_rc4_service_fanout {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-004"
  events:
    $e.metadata.product_event_type = "4769"
    $e.additional.fields["TicketEncryptionType"].value.string_value = "0x17"
    $e.additional.fields["approved_legacy_rc4_service"].value.bool_value = false
    $e.principal.ip = $source
    $e.target.user.userid = $user
    $e.target.resource.name = $service
  match:
    $source, $user over 15m
  outcome:
    $services = count_distinct($service)
  condition:
    $e and $services >= 3
}
```

Adds ticket-property specificity and works when LDAP telemetry is missing. The threshold and legacy-service enrichment require local testing; AES and single-SPN branches remain separate gaps.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
