# Public-rule comparison: bloodhound_remote_security_configuration_reads

## Identity and independence gate

- Internal tool: `bloodhound`
- Internal canonical rule: `detections/bloodhound/yaral/bloodhound_remote_security_configuration_reads.yaral`
- Internal SHA-256: `9c6173a622eee840ac1c22423688d51fc12a3d3ebaace3b01c7025b33df9e877`
- Internal review completed before public comparison: `yes`
- Procedure IDs: `BH-012`
- Scope mapping rationale: candidate chosen by the same procedure branch or closest compensating observable, never by rule-name similarity alone.

Public candidate assessment:
- No credible public counterpart was found in the pinned corpus for this procedure branch. Public coverage is therefore `insufficient_evidence`, not an inferred equivalence.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| remote reads collect CA, Netlogon, LDAP, NTLM or NTDS security settings | broad registry path regex across two hosts | no material remote configuration-read equivalent | remote caller attributed read of a precise security-relevant registry value - strong | generic registry read containing LDAP - weak | ours_stronger | Canonical rule and pinned-corpus search, `coverage/bloodhound.yml` and `reports/bloodhound/source-analysis.md`. |
| Activity is divided across identities, hosts, processes or windows | Usually falls below the current cardinality/join | No credible public counterpart; distributed coverage is also absent | stable entity plus procedure-specific effect - moderate | longer-window baseline/rare relationship - moderate | insufficient_evidence | This is an analytical inference requiring tenant telemetry validation. |

## Missing detection branches

- Missing from ours: local reads after remote execution, named-value specificity, one DC/CA target, and WMI/API alternatives.
- Missing from the pinned public corpus: complete ordered procedure coverage and telemetry-independent attribution beyond its declared data source.
- Missing from both: reliable intent attribution and complete observation when required logging is absent.

## Detection edge cases and blind spots

4656/4663 requires object auditing and often lacks remote source; broad LDAP/Lsa terms can match unrelated keys. Low-and-slow and distributed activity can evade fixed per-entity windows. Partial collection can reduce cardinality without indicating benign behavior. Entity normalization must distinguish user, application, process and host identities.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| remote caller attributed read of a precise security-relevant registry value | strong | ours/proposal | Close to the security-relevant collection effect and resistant to mutable filenames. | Requires the detailed telemetry declared below and authorized-tool baselining. |
| procedure-specific breadth or ordered correlation | moderate | ours | Adds behavioral context without asserting tool identity. | Thresholds and joins require local validation. |
| generic registry read containing LDAP | weak | public or current branch | Useful as a lead but not sufficient proof of collection. | Mutable or common in legitimate administration. |

## Public-rule weaknesses

No behaviorally credible public counterpart was identified. Treating broad AD-property access as equivalent to this RPC/registry procedure would overstate public coverage; comparative strength is therefore `insufficient_evidence`.

## Internal-rule weaknesses

local reads after remote execution, named-value specificity, one DC/CA target, and WMI/API alternatives. The current threshold and entity join are detection hypotheses; collection loss can silently turn a strong sequence into no alert.

## Decision trail

- Candidate improvement: independently add the missing procedure branch shown below; no public predicate is copied.
- Independent verification: compare against pinned collector source, actual provider semantics, sanitized fixtures and benign inventory baselines.
- Decision: `deferred_pending_rule_improvement_run`.
- Reason: comparison code is an unvalidated detection-engineering proposal, not canonical logic.
- Required regeneration: canonical review, coverage, telemetry, all translations, dependencies/hashes and this comparison after acceptance or modification.

## Unmatched scope

The pinned public candidate is not a complete equivalent. Branch-specific differences are retained as `ours_stronger` or `insufficient_evidence` rather than claiming either rule is globally better.

## Proposed YARA-L improvement

- Change type: `rewrite`
- Addresses branches: local reads after remote execution, named-value specificity, one DC/CA target, and WMI/API alternatives.
- Required telemetry: full registry key and value name, source and target host, remote/local access attribution.
- Validation status: `unvalidated_proposal`

```yaral
rule bloodhound_remote_security_configuration_value_reads {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "BH-012"
  events:
    $e.metadata.product_event_type = /(REGISTRY_READ|4656|4663)/
    $e.principal.hostname = $source
    $e.target.hostname = $target
    re.regex($e.target.registry.registry_key, `(?i)(CertSvc\\Configuration|Netlogon\\Parameters|Lsa\\MSV1_0|NTDS\\Parameters)`)
    re.regex($e.target.registry.registry_value_name, `(?i)(StrongCertificateBindingEnforcement|CertificateMappingMethods|RestrictNTLM|LDAPServerIntegrity|LdapEnforceChannelBinding)`)
  match:
    $source over 30m
  outcome:
    $values = count_distinct($e.target.registry.registry_value_name)
  condition:
    $e and $values >= 2
}
```

Remaining gaps: intent is not established; thresholds, normalized fields and benign baselines require authorized telemetry testing. Distributed activity and missing collection require separate compensating analytics and collection-health monitoring.

If adopted, independently revise canonical YARA-L, re-run adversarial review, reconcile telemetry and master counts, regenerate all five translations and dependencies, and re-compare the final logic.
