# Public-rule comparison: rubeus_kerberos_over_http_proxy

## Identity and independence gate

- Internal tool: `rubeus`
- Internal canonical rule: `detections/rubeus/yaral/rubeus_kerberos_over_http_proxy.yaral`
- Internal SHA-256: `7e730f13ea28ca40c9480cf7f04b8dddfe56aaff105c409349e9e1c97b63aa6a`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `PROC-013`
- Scope mapping rationale: ordered Rubeus procedure behavior and observable security effects; public candidates were selected by procedure and telemetry, not rule names.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberoasting_unusual_process.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/windows/credential_access_kerberoasting_unusual_process.toml) - SHA-256 `3e84a66e6565021a3ad046cdf5fbca7167c01ba0e62e4b28b2970ad18d466881`

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

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/rubeus/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`, although the proposal had already been copied into canonical YARA-L on 2026-08-16 without a recorded decision or review finding; the live rule was re-reviewed before this terminal decision.
- Decision: `modify`.
- Reason: the missing branch is real; the adopted canonical logic diverges from the proposal as follows:
  - The 2026-08-16 rewrite OR-s the client and destination approvals rather than requiring both, so either unapproved side alerts.
  - Unset approval booleans read as false, so the rule fails open by design when enrichment is absent.
  - Process attribution is required, so proxy-only HTTP logs cannot satisfy it (accepted gap, recorded in the re-review section of the 2026-11-21 delta).
- Canonical result: `detections/rubeus/yaral/rubeus_kerberos_over_http_proxy.yaral`, SHA-256 `f8d19c7ad5697408267e8b80b82e9d430db1535d52094fb3be6be89995ee1e77`.
- Regeneration: none required; canonical logic is unchanged.

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

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/windows/credential_access_kerberoasting_unusual_process.toml` changed between 7e91c15 and 9d792a8 only in `updated_date` and classification tags; query logic is identical and the comparison conclusions are unaffected.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Kerberos tunnelled over HTTP (`application/kerberos`) by a process | covered (process-attributed HTTP) | not covered by `credential_access_kerberoasting_unusual_process.toml` (port 88 only) | Content-Type plus process - strong | none | ours_stronger |
| Direct port-88 Kerberos from a non-LSA process | covered by `rubeus_kerberos_transport_from_unexpected_process` | covered | non-LSA port 88 - strong | none | equivalent |

- Current canonical YARA-L `detections/rubeus/yaral/rubeus_kerberos_over_http_proxy.yaral` (`experimental` / `needs_validation`):

```yaral
rule rubeus_kerberos_over_http_proxy {
  meta:
    author = "Detection Research Agent"
    description = "Detects Kerberos messages transported over HTTP where either the initiating process or the destination is not on the approved KDC-proxy allowlist."
    date = "2026-08-16"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Kerberos HTTP proxy use is uncommon outside approved KDC proxy clients and provides strong process context."
    procedure_ids = "PROC-013"
    log_source_prerequisites = "Normalize process-attributed HTTP request Content-Type and proxy destination, plus an approved-KDC-proxy-client and approved-KDC-proxy-destination allowlist enrichment."
    false_positives = "Approved KDC proxy, remote-access, and identity clients where the allowlist enrichment is stale or incomplete."
    references = "RUBEUS_SOURCE_DETECTION_DEEP_DIVE.md; public-rules/comparisons/rubeus/rubeus_kerberos_over_http_proxy.md"
    validation_status = "needs_validation"
    validation_method = "Verify Content-Type parser mapping with authorized KDC proxy fixtures. Verify the allowlist enrichment source is authoritative and current; confirm the OR relationship between the two approved-* flags fires when EITHER the client or the destination is unapproved (not only when both are), since requiring both would miss an unapproved client relayed through an approved destination or an approved client abused against an unapproved destination."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/rubeus/detection-review.md"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.additional.fields["http_request_content_type"].value.string_value = "application/kerberos" nocase
    ($e.additional.fields["approved_kdc_proxy_client"].value.bool_value = false or $e.additional.fields["approved_kdc_proxy_destination"].value.bool_value = false)
    $e.principal.process.file.full_path != ""
  condition:
    $e
}
```

- Re-comparison outcome: the current canonical rule set closes the branch the proposal targeted, within declared telemetry; `public_stronger` rows are recorded gaps with named compensating signals in `reviews/rubeus/detection-review.md`.
