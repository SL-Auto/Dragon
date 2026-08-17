$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'public-rules/comparisons/chisel'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$elastic = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef'
$items = @(
  @{ Rule='chisel_recurrent_encrypted_process_egress'; Proc='CH-P01,CH-P10'; Candidate="$elastic/rules/linux/command_and_control_linux_chisel_client_activity.toml"; Branch='maintained client transport and reconnect'; Public='command-line client indicator'; Improvement='Require recurrent network activity plus HTTP WebSocket upgrade metadata from the same process'; Change='rewrite'; Extra='$h.metadata.product_event_type = "NETWORK_HTTP"`n    re.regex($h.network.http.request.headers["upgrade"], `websocket`) nocase' },
  @{ Rule='chisel_listener_with_tunnel_egress'; Proc='CH-P02,CH-P04,CH-P08'; Candidate="$elastic/rules/_deprecated/command_and_control_linux_chisel_server_activity.toml"; Branch='listener and bidirectional forwarding'; Public='server command-line then accepted connection'; Improvement='Add an inbound accepted-flow branch before same-process egress'; Change='rewrite'; Extra='$i.metadata.product_event_type = "NETWORK_CONNECTION"`n    $i.network.direction = "INBOUND"' },
  @{ Rule='chisel_udp_bind_with_tunnel_egress'; Proc='CH-P03,CH-P04'; Candidate="$elastic/rules/linux/command_and_control_linux_tunneling_and_port_forwarding.toml"; Branch='UDP forwarding'; Public='generic Linux process command-line tunnelling'; Improvement='Require an observed UDP send/receive after the bind as well as tunnel egress'; Change='rewrite'; Extra='$d.metadata.product_event_type = /UDP_SEND|UDP_RECEIVE/' },
  @{ Rule='chisel_proxy_destination_fanout'; Proc='CH-P05,CH-P07'; Candidate="$elastic/rules/_deprecated/command_and_control_proxy_port_activity_to_the_internet.toml"; Branch='dynamic SOCKS or proxy destination fanout'; Public='internet proxy-port connection'; Improvement='Require inbound listener use and distinct outbound destination fanout on one process entity'; Change='rewrite'; Extra='$i.metadata.product_event_type = "NETWORK_CONNECTION"`n    $i.network.direction = "INBOUND"' },
  @{ Rule='chisel_stdio_network_bridge'; Proc='CH-P06'; Candidate="$elastic/rules/linux/command_and_control_cat_network_activity.toml"; Branch='stdio-to-network bridge'; Public='named utility network activity'; Improvement='Correlate redirected standard handles with a pipe/handle connection and outbound flow'; Change='rewrite'; Extra='$p.metadata.product_event_type = /PROCESS_PIPE_CONNECT|PROCESS_HANDLE_DUPLICATE/' }
)

foreach ($item in $items) {
  $tick = [char]96
  $fence = "$tick$tick$tick"
  $internalRel = "detections/chisel/yaral/$($item.Rule).yaral"
  $internal = Join-Path $root $internalRel
  $candidate = Join-Path $root $item.Candidate
  $ih = (Get-FileHash -Algorithm SHA256 -LiteralPath $internal).Hash.ToLowerInvariant()
  $ph = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
  $extra = $item.Extra -replace ([regex]::Escape('`n')), "`n"
  $proposal = @"
rule proposed_$($item.Rule) {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    `$n.metadata.event_type = "NETWORK_CONNECTION"
    `$n.principal.hostname = `$host
    `$n.principal.process.product_specific_process_id = `$pid
    $extra
  match:
    `$host, `$pid over 15m
  condition:
    `$n and #n >= 2
}
"@
  $doc = @"
# Public-rule comparison: $($item.Rule)

## Identity and independence gate

- Internal tool: ${tick}chisel${tick}
- Internal canonical rule: ${tick}$internalRel${tick}
- Internal SHA-256: ${tick}$ih${tick}
- Internal review completed before public comparison: ${tick}yes${tick}
- Public source/revision/path: ${tick}$($item.Candidate)${tick}
- Public SHA-256: ${tick}$ph${tick}
- Scope mapping rationale: Both address $($item.Branch), but mapping is based on observable behavior and T1572/T1090 effects rather than names or syntax.

## Procedure and detection-branch matrix

| Procedure branch / observable effect | Ours | Public | Primary signal and strength | Compensating signal | Coverage conclusion | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Process establishes tunnel-side network activity | Behavior-based process network event | $($item.Public) | Process-attributed network behavior — moderate | TLS/HTTP metadata | complementary | Pinned source report and public candidate |
| $($item.Branch) | Explicit causal/correlated branch | Partial or command-line-derived branch | Security effect correlation — strong | Process prevalence and approval inventory | ours_stronger | ${tick}reports/chisel/source-analysis.md${tick} |
| Alternate implementation or renamed binary | Covered when effects are logged | Usually missed by mutable indicators | Effect rather than name — strong | Network flow analytics | ours_stronger | Internal adversarial review |
| Distributed, low-rate, or missing endpoint telemetry | Partial | Partial | Collection health — weak | Cross-host NDR and proxy logs | insufficient_evidence | Both depend on available telemetry |

## Missing detection branches

- Missing from ours: richer protocol/accepted-flow context and provider-tested process entity mapping.
- Missing from public rule: renamed/reimplemented behavior and non-command-line branches.
- Missing from both: reliable cross-host session linkage when reverse forwarding splits effects.

## Detection edge cases and blind spots

Single long-lived flows can evade recurrence counts; PID reuse can corrupt joins; UDP ownership and stdio semantics are provider-specific; encrypted WebSockets hide destinations; approved proxies, VPNs, developer tunnels and remote support overlap. Distributed reverse mode and partial collection need compensating NDR or proxy telemetry.

## Signal-quality assessment

| Signal | Strength | Used by | Why | Benign prevalence / fragility |
| --- | --- | --- | --- | --- |
| Same-process security effect correlation | strong | ours | Close to actual forwarding behavior and independent of branding | Approved tunnel software overlaps |
| Product command-line or filename | weak | public | Easy to collect but mutable and implementation-specific | Packaging and wrappers change it |
| Protocol/accepted-flow context | moderate | proposal | Confirms the listener is used rather than merely open | Provider mapping and encryption vary |

## Public-rule weaknesses

The public candidate is narrower, depends heavily on process arguments, names, ports, or platform-specific fields, and does not comprehensively cover forward, reverse, UDP, SOCKS, stdio, and proxy-chain branches.

## Internal-rule weaknesses

The internal rule is non-attributive, depends on stable process entity mapping, and needs additional accepted-flow or protocol context to reduce benign listener/network overlap.

## Decision trail

- Candidate improvement: $($item.Improvement).
- Independent verification: pinned Chisel source behavior, telemetry requirements, and ${tick}reviews/chisel/detection-review.md${tick}.
- Decision: ${tick}deferred${tick}
- Reason: the added branch is detection-relevant but requires provider-specific fixture validation before canonical adoption; no public predicate is copied blindly.
- Required regeneration: YARA-L review, telemetry, translations, dependencies and this comparison if adopted.

## Unmatched scope

Our inventory covers the complete pinned multi-platform behavior family. The public candidate covers one adjacent platform or command-line slice and is not treated as comprehensive.

## Proposed YARA-L improvement

- Change type: ${tick}$($item.Change)${tick}
- Addresses branches: $($item.Improvement).
- Required telemetry: process-attributed endpoint network, listener/UDP/stdio semantics as applicable, stable process entity, direction, destinations, timestamps, prevalence and collection health.
- Validation status: ${tick}unvalidated_proposal${tick}

${fence}yaral
$proposal
${fence}

This proposal adds procedure-specific causal context while retaining behavior-first logic. It still needs provider field binding, benign-baseline testing, and reverse-mode cross-host assessment before canonical adoption.
"@
  Set-Content -LiteralPath (Join-Path $out "$($item.Rule).md") -Value $doc -Encoding UTF8
}

$index = "# Chisel public-rule comparisons`n`nAll five canonical rules are compared independently against pinned public candidates. Proposals remain unvalidated and were not automatically adopted.`n`n" + (($items | ForEach-Object { "- [$($_.Rule)](./$($_.Rule).md)" }) -join "`n")
Set-Content -LiteralPath (Join-Path $out 'INDEX.md') -Value $index -Encoding UTF8
