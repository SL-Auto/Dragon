# Public-rule comparison: cobalt_strike_dns_process_context

## Identity and independence gate

- Internal tool: `cobalt-strike-beacon`
- Internal canonical rule: `detections/cobalt-strike-beacon/yaral/cobalt_strike_dns_process_context.yaral`
- Internal SHA-256: `d56bc7d7af9ade225c23a7d0fba876147eced440cc9b4d8248d7c4df0a871958`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `CSB-006`
- Scope mapping rationale: candidates were mapped to the procedure's ordered behavior, observable security effect, and telemetry; names and syntax were not used as equivalence evidence.

Public candidates:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/ml/command_and_control_ml_dns_tunneling.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/ml/command_and_control_ml_dns_tunneling.toml) - SHA-256 `eaa66978039f203084f832a39b78947d13becee680f3ecbfd6bb21bedbd782ea`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite and execution context | Process/entity context is retained | Candidate supplies a narrower implementation-specific context | Process attribution - moderate | identity/session baseline | complementary | Canonical rule and pinned candidate above. |
| sustained process-attributed DNS C2 with encoded-looking labels | long/high-entropy label volume tied to a process | DNS tunneling rules add record-type, byte-volume, and per-domain baselines | process-attributed anomalous DNS labels - moderate | ordered downstream security effect | complementary | Procedure `CSB-006` and the cited public rule cover overlapping but non-identical observables. |
| Resulting security effect or artifact | Partially covered | Partially covered | result correlation - strong when present | host/user/time-bounded sequence | different_scope | Neither rule proves every procedure outcome. |

## Missing detection branches

- Missing from ours: low-volume TXT/NULL-style exchange and high-entropy traffic spread across changing parent domains.
- Missing from the public candidate: the complete tool-independent ordered procedure and all Beacon-supported implementation variants.
- Missing from both: reliable attribution to Cobalt Strike; these are behavioral detections and must not claim tool identity.

## Detection edge cases and blind spots

CDNs and security agents generate high-entropy labels; resolver telemetry may lose originating process. Partial collection, clock skew, event loss, and process or identity key reuse can also break correlations. Low-and-slow activity may fall outside fixed windows, while distributing steps across processes can defeat same-process joins. These are detection limitations, not operational guidance.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| process-attributed anomalous DNS labels | moderate | ours | Close to the relevant security effect and less dependent on mutable names. | Depends on normalized process/entity fields and local baselines. |
| Candidate implementation indicator | moderate | public | Adds a concrete observable branch absent from ours. | Often tied to one implementation, field model, or default. |
| Name, path, or command fragment alone | weak | public where present | Useful only as context, not proof of the procedure. | Mutable and commonly overlaps administration. |

## Public-rule weaknesses

The candidate is useful as an independent compensating branch, but its narrower implementation assumptions do not cover the complete procedure. Any literal names, paths, command fragments, fixed thresholds, or product enrichments remain fragile until validated locally. It must not be copied blindly.

## Internal-rule weaknesses

The canonical rule has broader tool-independent intent, but low-volume TXT/NULL-style exchange and high-entropy traffic spread across changing parent domains. Its correlation also assumes consistent entity normalization and adequate collection across the declared window.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against source analysis, provider field semantics and `reviews/cobalt-strike-beacon/detection-review.md`.
- Prior state: the proposal was copied into canonical YARA-L on 2026-08-16 while this trail read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real, but adversarial review found defects in the proposal as written; the adopted rule diverges as follows:
  - Invalid placeholder comparison in `condition` moved into `events` (DR-17, blocker).
  - Event type `DNS_QUERY` replaced by inventory `NETWORK_DNS` (legacy alias kept) (DR-13).
- Canonical result: `detections/cobalt-strike-beacon/yaral/cobalt_strike_dns_process_context_compensating_signal.yaral`, SHA-256 `ed53f55d149827c21fdb860c810989367b1eaa9a45eb440e7adfe2a83719fd82`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, tool telemetry file, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
## Unmatched scope

The public candidate does not cover all branches in `CSB-006`. Conversely, the canonical rule is not evidence of Cobalt Strike attribution and may detect other tooling with equivalent effects.

## Proposed YARA-L improvement

- Change type: `compensating_rule`
- Addresses branches: low-volume TXT/NULL-style exchange and high-entropy traffic spread across changing parent domains.
- Required telemetry: normalized `DNS_QUERY` plus the entity, enrichment, and correlation fields used below; collection health must be monitored.
- Validation status: `unvalidated_proposal`

```yaral
rule cobalt_strike_dns_process_context_compensating_signal {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    description = "Independent compensating signal proposed after public-rule comparison"
    procedure_ids = "CSB-006"
  events:
    $e.metadata.event_type = "DNS_QUERY"
        $e.principal.hostname = $host
        $e.principal.process.pid = $pid
        $e.network.dns.questions.name = $query
        $e.network.dns.questions.type = $rtype
        $e.additional.fields["domain_baseline_rarity"].value.string_value = "RARE"
  match:
    $host, $pid over 30m
  condition:
    $e and #query >= 8 and ($rtype = 16 or $rtype = 10)
}
```

This proposal is deliberately not canonical. Thresholds, field availability, benign prevalence, and join stability require adversarial review. Remaining gaps include telemetry loss, cross-host clock skew, and variants that do not produce the proposed effect.

If accepted or modified, update the canonical rule in the same run and regenerate every required downstream artifact before marking the comparison complete.

## Re-comparison against revised canonical rule

- Revised rule SHA-256 `ed53f55d149827c21fdb860c810989367b1eaa9a45eb440e7adfe2a83719fd82`, compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- `rules/ml/command_and_control_ml_dns_tunneling.toml` differs from the prior revision only in tag metadata or line endings; its detection logic is unchanged.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Low-volume TXT/MX DNS exchange to rare domains | covered per host/process | `command_and_control_ml_dns_tunneling.toml`: narrower implementation-specific context (original matrix); candidate not re-assessed beyond re-pinning | process-attributed rare-domain TXT/MX queries - moderate | base length/entropy rule - moderate | complementary | Revised canonical rule, re-pinned candidate, `reviews/cobalt-strike-beacon/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule cobalt_strike_dns_process_context_compensating_signal {
  meta:
    author = "Detection Research Agent"
    description = "Detects repeated process-attributed TXT/NULL-type DNS queries to domains flagged as rare by baseline enrichment, covering low-volume record-type-specific tunneling exchanges that the length/entropy-based base rule does not filter by record type."
    date = "2026-11-21"
    status = "experimental"
    severity = "MEDIUM"
    severity_rationale = "TXT/NULL queries to rare domains are a classic DNS-tunneling record-type signature, but security/email products issue high volumes of legitimate TXT lookups (SPF/DKIM/DMARC); the rarity enrichment is required to keep this usable."
    procedure_ids = "CSB-006"
    log_source_prerequisites = "Normalize process-attributed NETWORK_DNS (for example Sysmon 22 or EDR DNS events; DNS Client service-attributed resolver logs cannot attribute the requesting process) with host, process ID, query name/type, and a domain-rarity baseline enrichment field."
    false_positives = "Mail-security appliances and anti-abuse services performing bulk legitimate TXT lookups against rare or newly observed domains; the rarity enrichment must be tenant-tuned before enabling."
    references = "reports/cobalt-strike-beacon/source-analysis.md; public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_dns_process_context.md"
    validation_status = "needs_validation"
    validation_method = "Replay fabricated DNS records mixing benign bulk TXT lookups against rare domains with synthetic tunneling-style query bursts."
    review_status = "reviewed"
    review_reference = "reviews/cobalt-strike-beacon/detection-review.md"
    compensates_for = "cobalt_strike_dns_process_context"
    source_comparison = "public-rules/comparisons/cobalt-strike-beacon/cobalt_strike_dns_process_context.md"
  events:
    $e.metadata.event_type = /^(NETWORK_DNS|DNS_QUERY)$/
    $e.principal.hostname = $host
    $e.principal.process.product_specific_process_id = $pid
    $e.network.dns.questions.name = $query
    ($e.network.dns.questions.type = 16 or $e.network.dns.questions.type = 10)
    $e.additional.fields["domain_baseline_rarity"].value.string_value = "RARE"
  match:
    $host, $pid over 30m
  outcome:
    $queries = count_distinct($query)
  condition:
    $e and $queries >= 8
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. Remaining limits are the accepted gaps in `reviews/cobalt-strike-beacon/detection-review.md`, each with a named compensating rule.
