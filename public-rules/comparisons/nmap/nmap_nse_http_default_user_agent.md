# Public-rule comparison: nmap_nse_http_default_user_agent

## Identity and independence gate

- Internal tool: `nmap` (revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`)
- Internal canonical rule: `detections/nmap/yaral/nmap_nse_http_default_user_agent.yaral`
- Internal SHA-256: `792f7648c5b1396f59dfd8b3d7d44f3d1cde7be47c51f7ecff8a80866d57c3d9`
- Internal review completed before public comparison: `yes` (`reviews/nmap/detection-review.md`, NM-DR-01 to NM-DR-07)
- Public candidate: [`public-rules/snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/reconnaissance_web_server_unusual_user_agents.toml`](../../snapshots/elastic-security/9d792a8f6731542935156db61eaba88bf337e819/rules/cross-platform/reconnaissance_web_server_unusual_user_agents.toml) - SHA-256 `d76be9bff5ff7ed6c1c47e942eaabf78958330f43935e633bce559899e739dea`
- Scope mapping rationale: Both detect scanner User-Agents in web logs (T1595). The Elastic rule matches a list of reconnaissance User-Agents, including the Nmap Scripting Engine string.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| NSE default User-Agent in web logs | covered | covered (in its list) | self-identifying string - moderate | launch grammar on host - strong | equivalent |
| Other scanners' User-Agents | not targeted | covered | string list - moderate | none | different_scope |

## Missing detection branches

- Overridden User-Agent (NM-DR-04).

## Detection edge cases and blind spots

- TLS without inspection hides headers from network sensors.

## Signal-quality assessment

- Both: string match - moderate.

## Public-rule weaknesses

- Broad list; generic.

## Internal-rule weaknesses

- Single-string rule.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/nmap/source-analysis.md`, `telemetry/nmap.md` and `reviews/nmap/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal would broaden our rule to other scanners' User-Agents. Those belong to other tools' analyses, and the Nmap branch is already equivalent.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

Other scanners are outside Nmap. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Other scanner User-Agents.
- Required telemetry: HTTP logs with User-Agent.
- Validation status: `unvalidated_proposal`

```yaral
rule nmap_scanner_user_agents_broad {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "NM-P08"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    re.regex($e.network.http.user_agent, `(?i)(Nmap Scripting Engine|masscan|zgrab|nikto)`)
  condition:
    $e
}
```
