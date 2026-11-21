# Public-rule comparison: impacket_privilege_path_effects

## Identity and independence gate

- Internal tool: `impacket`
- Internal canonical rule: `detections/impacket/yaral/impacket_privilege_path_effects.yaral`
- Internal SHA-256: `aa2f8752c5d35ad62810ac6e41a89d1ff0dcff2e269d9ba447aa67e73afce627`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `IMP-22`
- Scope mapping rationale: candidates were mapped by procedure, observable effect and telemetry rather than name or syntax.

Public candidate:
- [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml) - SHA-256 `3e78aa4fae6e9c216368f412c301512c30698baffaec39a9da33f6f3c47c35d2`

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Prerequisite or remote access context | Partial; depends on fields present in the canonical events | Candidate provides adjacent behavior but not an Impacket-specific prerequisite | Network logon or authenticated remote caller - moderate | First-seen source/account/host relationship | complementary | Internal `IMP-22` inventory and cited public rule. |
| directory privilege-path mutation followed by anomalous ticket issuance or use | Canonical rule covers the principal event family | Candidate covers an overlapping effect with different assumptions | Sensitive directory mutation joined by object SID to later privileged ticket use - strong | Process, network-session, and resulting-object correlation - moderate | complementary | The security-sensitive effect is closer to intent than executable names. |
| Resulting effect and cleanup | Incomplete | Incomplete or outside candidate scope | Verified resulting state - strong | stop/delete, object access, or later authentication - moderate | different_scope | Neither rule demonstrates every downstream effect. |

## Missing detection branches

- Missing from ours: No proof that the changed object participates in the later ticket identity or authorization path.
- Missing from public: complete Impacket procedure ordering, target-side effect confirmation, and coverage independent of mutable tool names.
- Missing from both: reliable observation when collection is partial, identity normalization fails, or the procedure is split across sources and time windows.

## Detection edge cases and blind spots

The logic must account for NAT and management relays, machine-versus-user identity forms, delayed ingestion, duplicate events, clock skew, host-role differences, and partial endpoint/DC collection. A fixed correlation window can miss low-and-slow activity, while broad host-only joins can connect unrelated administrative work. Legitimate remote administration can produce the same primitives, so approved-source enrichment should inform severity rather than suppress the security effect outright.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Sensitive directory mutation joined by object SID to later privileged ticket use | strong | proposed/internal refinement | Close to the sensitive operation and resistant to binary renaming. | Requires the declared provider fields and semantic enrichment. |
| Remote caller or network-logon context | moderate | ours/compensating | Adds causal attribution but is not independently malicious. | Proxies, jump hosts and logon-ID normalization complicate joins. |
| Tool, image, service, task, or object name | weak | some public branches | Useful investigative context, not durable behavior. | Mutable and may collide with benign administration. |

## Public-rule weaknesses

The candidate is valuable corroboration but covers only an adjacent branch, inherits its backend's field and collection assumptions, and cannot establish the complete Impacket procedure. Name/path indicators and fixed exclusions are weak when not paired with a security effect. Its thresholds are not tenant evidence and must not be copied blindly.

## Internal-rule weaknesses

No proof that the changed object participates in the later ticket identity or authorization path. The canonical rule also needs explicit collection-health assumptions and stronger entity joins. It can over-alert on legitimate administration when the sensitive effect is broad, and under-alert when events are distributed or delayed.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned source analysis, coverage ledger, telemetry file and `reviews/impacket/detection-review.md`.
- Prior state: this trail read `deferred_pending_rule_improvement_run`; decided here with the evidence in hand.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal keeps the base same-actor join, which cannot link a delegation-abuse chain: tickets are requested by the newly created machine account, not by the actor.
  - It replaces the concrete 4768/4769 leg with a `STATUS_UPDATE` event carrying a `sensitive_effect` label that no provider emits, and adds strict ordering (REVIEW-014).
  - The gap it names is real and is closed independently by new `impacket_new_machine_account_s4u`: 4741 followed within 1h by S4U 4769 requested by the same new account. The base rule is unchanged.
- Canonical result: `detections/impacket/yaral/impacket_new_machine_account_s4u.yaral`, SHA-256 `4689f1638c6f24c86d779179ae0561a22a97be5337446d84aab4083aa96fde0d`.
- Regeneration: new canonical rule on 2026-11-21; detection review, coverage, `telemetry/impacket.md`, `telemetry/MASTER.md` (new 4741 row and counts), native translations, dependency/manifest hashes and this re-comparison were regenerated in the same run.

## Unmatched scope

The public candidate does not cover all of `IMP-22`. Unrelated public rules were not treated as equivalents, and no global better/worse claim is made.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: No proof that the changed object participates in the later ticket identity or authorization path.
- Required telemetry: normalized event type, actor/account, source, destination, result, stable object/session identifiers, and the enrichment referenced in the predicate.
- Validation status: `unvalidated_proposal`

```yaral
rule impacket_privilege_path_effects_strong_branch {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "IMP-22"
    source_comparison = "unvalidated_proposal"
  events:
    $a.metadata.product_event_type = /(5136|5137|4741|4742)/
    $a.principal.hostname = $host
    $a.target.resource.attribute.labels["privilege_path_change"] = "true"
    $a.principal.user.userid = $actor
    $b.principal.hostname = $host
    $b.principal.user.userid = $actor
    $b.metadata.event_type = "STATUS_UPDATE"
    $b.target.resource.attribute.labels["sensitive_effect"] = "true"
    $a.metadata.event_timestamp.seconds <= $b.metadata.event_timestamp.seconds
  match:
    $host, $actor over 15m
  condition:
    $a and $b
}
```

This proposal strengthens a procedure-level branch without importing the public predicate. It remains vulnerable to missing source telemetry, semantic mapping errors, and activity outside the correlation period. If adopted, test benign administrative workloads and missing-data behavior, then update every downstream artifact required by the workflow.

## Re-comparison against revised canonical rule

- Compared on 2026-11-21 against candidates re-pinned to elastic-security `9d792a8`, microsoft-sentinel `c3361d9`, splunk-security-content `2150948`, chronicle-community `dbc9beb`.
- All public candidates were re-pinned to the refreshed snapshots; no referenced candidate file changed content.

| Procedure branch / observable effect | Ours (current canonical) | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Directory change followed by Kerberos use by the same actor | covered by base rule | `privilege_escalation_krbrelayup_suspicious_logon.toml` (deprecated): local Kerberos relay logon | 5136/4741 + 4768/4769 same user - weak | new-account S4U rule - strong | different_scope |
| New machine account requesting S4U tickets (delegation abuse) | covered by `impacket_new_machine_account_s4u` | not covered | 4741 then S4U 4769 by the new account - strong | base rule - weak | ours_stronger |

- Current canonical YARA-L `detections/impacket/yaral/impacket_new_machine_account_s4u.yaral` (`experimental` / `needs_validation`):

```yaral
rule impacket_new_machine_account_s4u {
  meta:
    author = "Detection Research Agent"
    description = "Detects a newly created computer account requesting S4U (protocol-transition or constrained-delegation) service tickets within one hour of its creation, proving that the object created in the directory participates in the later ticket path. This is the resource-based constrained delegation chain: account creation, delegation configuration, then S4U ticket requests as the new account."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "A just-created machine account performing S4U impersonation is uncommon in ordinary domain joins and directly yields service tickets for impersonated users."
    procedure_ids = "IMP-07,IMP-11,IMP-22"
    log_source_prerequisites = "Domain-controller Security 4741 (computer account created; new account in target.user.userid) and 4769 (requesting account in target.user.userid) with S4U context in the description, a structured delegation_flow field, or TransmittedServices, from every DC."
    false_positives = "Provisioning or middleware that creates a computer account and immediately configures it for constrained delegation; approve those service accounts after validation."
    references = "reports/impacket/source-analysis.md#imp-22; public-rules/comparisons/impacket/impacket_privilege_path_effects.md; reviews/impacket/detection-review.md#review-014"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized fixtures: an ordinary domain join (4741 then ordinary 4768/4769) must not match; a new account followed by S4U2Self/S4U2Proxy 4769 within one hour must match. Verify which S4U field the parser populates."
    review_status = "reviewed_with_gaps"
    review_reference = "reviews/impacket/detection-review.md"
  events:
    $c.metadata.product_event_type = "4741"
    $c.target.user.userid = $account

    $k.metadata.product_event_type = "4769"
    $k.target.user.userid = $account
    (
      re.regex($k.security_result.description, `(?i)(S4U2Self|S4U2Proxy|protocol transition|transited services)`) or
      re.regex($k.additional.fields["delegation_flow"].value.string_value, `(?i)^(S4U2Self|S4U2Proxy)$`) or
      re.regex($k.additional.fields["TransmittedServices"].value.string_value, `[A-Za-z0-9]`)
    )

    $c.metadata.event_timestamp.seconds <= $k.metadata.event_timestamp.seconds
  match:
    $account over 1h
  outcome:
    $creators = array_distinct($c.principal.user.userid)
    $services = array_distinct($k.target.resource.name)
    $sources = array_distinct($k.principal.ip)
  condition:
    $c and $k
}
```

- Re-comparison outcome: Rejected as written; the branch is covered by an independently designed rule, and the comparison conclusions above stand.
