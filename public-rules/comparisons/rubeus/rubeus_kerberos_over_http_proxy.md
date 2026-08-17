# Public-rule comparison: rubeus_kerberos_over_http_proxy

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_kerberos_over_http_proxy.yaral`
- Internal SHA-256: `7e730f13ea28ca40c9480cf7f04b8dddfe56aaff105c409349e9e1c97b63aa6a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-013`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberoasting_unusual_process.toml`](../../snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/credential_access_kerberoasting_unusual_process.toml) - SHA-256 `cbabbfa8cacdc7c5a023087dfd6c81a87cf485f66edb56da36bb45ae56b591dc`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Kerberos payload sent through HTTP proxy | HTTP event with application/kerberos | Public rule observes direct Kerberos traffic from unusual processes, not HTTP transport | Kerberos HTTP content type - strong | Proxy destination plus initiating process | ours_stronger | Ours covers the alternate transport directly. |
| Unapproved process initiates request | Description claims unusual process but condition does not test process | Public rule has extensive process allow/deny context for direct KDC traffic | Process attribution and signer - moderate | Approved KDC-proxy client inventory | public_stronger | Our implementation omits its stated unapproved-process branch. |
| Approved KDC proxy use | Alerts on every matching content type | Public direct-Kerberos rule is out of scope | Approved-client/destination baseline - moderate | TLS proxy and endpoint process correlation | insufficient_evidence | Neither rule provides a safe KDC-proxy-specific allow model. |

## Missing detection branches

- Missing from ours: Process identity, proxy destination, approved-client baseline, URI/method consistency, and TLS visibility limitations.
- Missing from public rule: Kerberos-over-HTTP itself.
- Missing from both: Encrypted HTTP where content type is unavailable and endpoint network telemetry lacks process attribution.

## Detection edge cases and blind spots

Content-Type casing/parameters and proxy normalization vary. Approved remote-access clients may generate identical traffic. Network-only records may not identify the initiating process.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| application/kerberos content type | strong | ours | Protocol-specific, but only when visible. | Requires tenant-specific validation and collection-health monitoring. |
| Unusual process context | moderate | public | Useful attribution; mutable and environment-dependent. | Requires tenant-specific validation and collection-health monitoring. |
| HTTP destination alone | weak | neither | Proxy endpoints can be shared and legitimate. | Requires tenant-specific validation and collection-health monitoring. |

## Public-rule weaknesses

Direct port-88/process logic does not cover HTTP KDC proxy transport.

## Internal-rule weaknesses

The rule description promises an unapproved-process test that the event condition does not implement, creating high benign volume and weak attribution.

## Decision trail

- Candidate improvement: Fix ours by correlating content type with process identity, signer and approved proxy destinations; preserve a content-type-only lower-severity branch when process attribution is absent.
- Independent verification: `Required against Rubeus source analysis, concrete telemetry schemas, and sanitized fixtures before changing canonical logic.`
- Decision: `deferred_pending_rule_improvement_run`
- Reason: `The comparison identifies a detection-engineering gap; no public predicate is copied automatically.`
- Required regeneration: `YARA-L adversarial review, telemetry reconciliation, five translations, and this comparison.`

## Unmatched scope

Public candidates do not cover the full `PROC-013` procedure. Unmatched branches are recorded above; unrelated public Kerberos rules were excluded rather than treated as equivalents.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: Kerberos-over-HTTP attributed to an unapproved process and destination, rather than alerting on every legitimate KDC-proxy request.
- Required telemetry: Process-attributed HTTP telemetry with Content-Type, destination, signer/process identity, and approved KDC-proxy enrichment.
- Validation status: `unvalidated_proposal`

```yaral
rule rubeus_kerberos_over_http_unapproved_process {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "PROC-013"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.additional.fields["http_request_content_type"].value.string_value = "application/kerberos" nocase
    $e.additional.fields["approved_kdc_proxy_client"].value.bool_value = false
    $e.additional.fields["approved_kdc_proxy_destination"].value.bool_value = false
    $e.principal.process.file.full_path != ""
  condition:
    $e
}
```

Makes the rule match its description and turns a protocol-only signal into an attributed, policy-aware branch. It still misses encrypted traffic where Content-Type is unavailable, so process/destination compensation remains necessary.

If adopted, update the canonical YARA-L, adversarial detection review, Rubeus telemetry matrix and master counts, all five translations, dependency hashes, and this comparison.
