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

- Candidate improvement: independently add the missing procedure branch shown in the proposal below; no public predicate is copied.
- Independent verification (2026-11-21): checked against the pinned collector source, provider field semantics and the adversarial review `reviews/bloodhound/detection-review.md` (BH-DR-10 to BH-DR-25).
- Prior state: the proposal was copied into `detections/bloodhound/yaral/bloodhound_remote_security_configuration_value_reads.yaral` on 2026-08-16 while this trail still read `deferred_pending_rule_improvement_run`, a non-terminal state the workflow now prohibits. It is re-decided here with the evidence in hand.
- Decision: `modify`.
- Reason: the missing branch is real and worth a compensating rule, but the proposal as written had defects found in adversarial review. The adopted rule diverges as follows:
  - Rewrote the key/value predicates as explicit pairs. The proposal's key regex omitted `Services\Kdc` and `SecurityProviders\Schannel`; `RestrictNTLM` matched no collected value; and the LDAP integrity/channel-binding values are not collector registry reads (BH-DR-20, blocker; evidence: `ein/ad.go#L121-L146`).
  - Added owning-service image and local-service identity exclusions, which do not exclude machine accounts (BH-DR-21).
  - Match key changed from source to actor + target, because 4663 logs on the target.
  - Restricted to EDR REGISTRY_READ, because 4656/4663 do not record value names (BH-DR-25).
- Canonical result: `detections/bloodhound/yaral/bloodhound_remote_security_configuration_value_reads.yaral`, SHA-256 `510a95cb769fb67eb29497acf18ca81c6743faf49b72e8eb154413cdaa2ff8d8`. The original proposal is preserved unchanged under "Proposed YARA-L improvement".
- Regeneration completed in the same run: detection review, coverage ledger, `telemetry/bloodhound.md`, `telemetry/MASTER.md` counts, all five translations, translation review, dependency/manifest hashes, and the re-comparison below.
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

## Re-comparison against revised canonical rule

- Revised rule: `bloodhound_remote_security_configuration_value_reads` (SHA-256 `510a95cb769fb67eb29497acf18ca81c6743faf49b72e8eb154413cdaa2ff8d8`), compared on 2026-11-21 with the public candidate(s) re-pinned to the refreshed snapshots: elastic-security `9d792a8f6731542935156db61eaba88bf337e819`, chronicle-community `dbc9beb79597b519be086fce082214494d75b6a8`. Between revisions, the existing candidates changed only in metadata tags or path, with no query-logic change.

| Procedure branch / observable effect | Revised ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Precise collector value reads on one DC/CA | covered with EDR value-level reads | no counterpart in the public corpus | remote-account read of exact security values - strong | key-level multi-host rule - moderate | insufficient_evidence | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |
| Native-log-only environments | not covered (accepted_gap BH-DR-25) | no counterpart | 4663 key-level access - weak | key-level multi-host rule - moderate | insufficient_evidence | Revised canonical rule, refreshed pinned candidate(s), `reviews/bloodhound/detection-review.md`. |

- Final adopted YARA-L (canonical, `experimental` / `needs_validation`):

```yaral
rule bloodhound_remote_security_configuration_value_reads {
  meta:
    author = "Detection Research Agent"
    description = "Detects one account reading two or more collector-relevant security-configuration registry values (KDC certificate binding, Schannel certificate mapping, LSA/MSV1_0 NTLM restriction and compatibility values, or CA security/enrollment-agent/edit-flag values) on a single target, compensating for single-target reads below bloodhound_remote_security_configuration_reads's multi-host threshold."
    date = "2026-11-21"
    status = "experimental"
    severity = "HIGH"
    severity_rationale = "Exact key/value pairing of certificate-binding, NTLM-restriction and CA configuration reads confirms security-posture reconnaissance even against one high-value DC or CA; local owning-service reads are excluded."
    procedure_ids = "BH-012"
    log_source_prerequisites = "EDR REGISTRY_READ telemetry exposing full registry key path, value name, subject account, reading process path and target host. Windows Security 4656/4663 record the key and access mask but not the value name, so they cannot satisfy this rule (reviews/bloodhound/detection-review.md#bh-dr-25)."
    false_positives = "Security posture assessment, PKI administration, vulnerability management and domain-controller compliance tooling reading several of these values on one host; administrators inspecting values with regedit or reg.exe."
    references = "reports/bloodhound/source-analysis.md#bh-012, sources/bloodhound-ce-src packages/go/ein/ad.go#L121-L146 (5e8e78e), public-rules/comparisons/bloodhound/bloodhound_remote_security_configuration_reads.md, reviews/bloodhound/detection-review.md#bh-dr-20"
    validation_status = "needs_validation"
    validation_method = "Replay sanitized EDR REGISTRY_READ fixtures for each key/value family as a remote domain account and as a remote machine account; confirm local lsass/certsrv/SYSTEM reads and single-value reads do not match."
    review_status = "reviewed"
    review_reference = "reviews/bloodhound/detection-review.md"
  events:
    $e.metadata.product_event_type = "REGISTRY_READ"
    $e.target.hostname = $target
    $e.principal.user.userid = $actor
    $e.target.registry.registry_value_name = $value
    (
      (re.regex($e.target.registry.registry_key, `(?i)\\Services\\Kdc$`) and re.regex($e.target.registry.registry_value_name, `(?i)^StrongCertificateBindingEnforcement$`)) or
      (re.regex($e.target.registry.registry_key, `(?i)\\SecurityProviders\\Schannel$`) and re.regex($e.target.registry.registry_value_name, `(?i)^CertificateMappingMethods$`)) or
      (re.regex($e.target.registry.registry_key, `(?i)\\Control\\Lsa(\\MSV1_0)?$`) and re.regex($e.target.registry.registry_value_name, `(?i)^(RestrictSendingNtlmTraffic|RestrictReceivingNTLMTraffic|NtlmMinClientSec|NtlmMinServerSec|LmCompatibilityLevel|UseMachineId|ClientAllowedNTLMServers)$`)) or
      (re.regex($e.target.registry.registry_key, `(?i)\\CertSvc\\Configuration\\`) and re.regex($e.target.registry.registry_value_name, `(?i)^(Security|EnrollmentAgentRights|EditFlags)$`))
    )
    not re.regex($e.principal.process.file.full_path, `(?i)\\(lsass|certsrv|services|wininit|csrss)\.exe$`)
    not re.regex($e.principal.user.userid, `(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|S-1-5-18|S-1-5-19|S-1-5-20)$`)
  match:
    $actor, $target over 30m
  outcome:
    $values = count_distinct($value)
    $source_hosts = array_distinct($e.principal.hostname)
    $processes = array_distinct($e.principal.process.file.full_path)
  condition:
    $e and $values >= 2
}
```

- Re-comparison outcome: the revised rule closes the branch the proposal targeted, within its declared telemetry. The remaining gaps are the accepted gaps listed in the detection review, each with a named compensating rule. No further change is proposed from this comparison.
