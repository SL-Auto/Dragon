# Public-rule comparison: ligolo_websocket_default_user_agent

## Identity and independence gate

- Internal tool: `ligolo-ng` (revision `e543732f4be6dc899096ae322ae620bf010bfbfc`)
- Internal canonical rule: `detections/ligolo-ng/yaral/ligolo_websocket_default_user_agent.yaral`
- Internal SHA-256: `d543b80870fbe5923e1cfbef62fdf798d19cf77c4484b9e5adf5108f96093b04`
- Internal review completed before public comparison: `yes` (`reviews/ligolo-ng/detection-review.md`, LG-DR-01 to LG-DR-09)
- Public candidate: [`public-rules/snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/http_c2_framework_user_agent.yml`](../../snapshots/splunk-security-content/21509485465aaed2cfa4604e3d2ab5ee52975f0a/detections/network/http_c2_framework_user_agent.yml) - SHA-256 `bbdf9f30da1f143befe9871776d7cecbf9921957456b0855ae8a4b16821af300`
- Scope mapping rationale: Both match default C2 User-Agent strings in web telemetry (T1071.001). Splunk joins web logs against `lookups/csv/suspicious_c2_user_agents.csv`.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion |
| --- | --- | --- | --- | --- | --- |
| Ligolo-ng default WebSocket User-Agent (Mozilla/5.0, Chrome/103) | covered (exact string, non-browser process) | not covered (the lookup lists GraphStrike's Mozilla/6.0 Chrome/103 variant, not Ligolo's) | exact default string - weak (mutable) | fan-out and flag rules - strong | ours_stronger |
| Other frameworks' default User-Agents | not targeted | covered | lookup match - weak | none | different_scope |

## Missing detection branches

- A changed User-Agent (one flag) or direct-TLS transport defeats both rules.

## Detection edge cases and blind spots

- TLS without interception hides the header from proxies.
- Legacy kiosks pinned to Chrome 103 produce benign matches.

## Signal-quality assessment

- Ours: exact stale default - weak, corroborating.
- Public: lookup of default strings - weak, broad framework coverage.

## Public-rule weaknesses

- The lookup does not contain Ligolo-ng's actual default.

## Internal-rule weaknesses

- A single flag changes the value; there is no HTTP layer for direct-TLS transport.

## Decision trail

- Candidate improvement: independently implement the branch named in the proposal; no public predicate is copied.
- Independent verification (2026-11-21): checked against `reports/ligolo-ng/source-analysis.md`, `telemetry/ligolo-ng.md` and `reviews/ligolo-ng/detection-review.md`.
- Decision: `reject`.
- Reason: the proposal is not adopted:
  - The proposal generalizes to any Chrome major version below 110 from a non-browser process. Stale-version matching overlaps legacy devices and embedded browsers, and closes no Ligolo-specific branch beyond the exact default already matched.
  - The public lookup lacks the Ligolo string, so there is nothing to adopt from it.
- Canonical result: no canonical logic changed; the proposed code is preserved below.
- Regeneration: none required; canonical logic is unchanged.

## Unmatched scope

The public rule covers many other frameworks' defaults, which are outside Ligolo-ng. No global better or worse claim is made.

## Proposed YARA-L improvement

- Change type: `patch`
- Addresses branches: Stale Chrome version from a non-browser source.
- Required telemetry: NETWORK_HTTP with User-Agent and initiating process.
- Validation status: `unvalidated_proposal`

```yaral
rule ligolo_stale_chrome_user_agent {
  meta:
    status = "experimental"
    validation_status = "needs_validation"
    procedure_ids = "LG-P01"
    source_comparison = "unvalidated_proposal"
  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    re.regex($e.network.http.user_agent, `Chrome/(\d{2}|10\d)\.`)
    not re.regex($e.principal.process.file.full_path, `(?i)\\(chrome|msedge)\.exe$`)
  condition:
    $e
}
```
