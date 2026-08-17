$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$output = Join-Path $repoRoot 'public-rules/comparisons/havoc'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$utf8 = New-Object Text.UTF8Encoding($false)

$sentinelBeacon = 'public-rules/snapshots/microsoft-sentinel/5f947544657288586559c41b218eaaf182636728/Detections/ASimNetworkSession/PossibleBeaconingActivity.yaml'
$splunkPipe = 'public-rules/snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_suspicious_named_pipe.yml'
$elasticShell = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/execution_command_shell_started_by_unusual_process.toml'
$splunkInject = 'public-rules/snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_process_injection_remote_thread.yml'
$elasticToken = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules/windows/privilege_escalation_via_token_theft.toml'
$elasticDiscovery = 'public-rules/snapshots/elastic-security/7e91c156324cdc64cda27f7fec7067b1148074ef/rules_building_block/discovery_generic_process_discovery.toml'
$splunkScreen = 'public-rules/snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_screen_capture_in_temp_folder.yml'
$chronicleForward = 'public-rules/snapshots/chronicle-community/234e9223c3b8f3d1c30209d9663797ba69057533/rules-community/microsoft/windows/port_proxy_forwarding_T1090_cisa_report.yaral'
$splunkKerberos = 'public-rules/snapshots/splunk-security-content/457ce9f5ea69a8d5be9463989ee23b9366858d16/detections/endpoint/windows_steal_or_forge_kerberos_tickets_klist.yml'

$items = @(
  @{ Rule='havoc_recurrent_process_egress'; Procedures='HV-P01, HV-P03'; Candidate=$sentinelBeacon; Public='destination-aware flow recurrence'; Ours='process-aware recurrence across destination changes'; E1='NETWORK_CONNECTION'; E2='NETWORK_CONNECTION'; Decision='adopted'; Change='compensating_rule'; Branch='stable-destination recurrence'; Strength='complementary' },
  @{ Rule='havoc_stable_destination_beaconing'; Procedures='HV-P01, HV-P03'; Candidate=$sentinelBeacon; Public='destination-aware flow recurrence'; Ours='process and destination recurrence with active-minute threshold'; E1='NETWORK_CONNECTION'; E2='NETWORK_CONNECTION'; Decision='deferred'; Change='patch'; Branch='collection-health and prevalence context'; Strength='complementary' },
  @{ Rule='havoc_named_pipe_network_context'; Procedures='HV-P02, HV-P15'; Candidate=$splunkPipe; Public='known or suspicious pipe naming'; Ours='same-process pipe and network behavior'; E1='NAMED_PIPE_CREATE'; E2='SMB_SESSION'; Decision='rejected'; Change='compensating_rule'; Branch='remote SMB session confirmation'; Strength='ours_stronger' },
  @{ Rule='havoc_spawned_command_execution'; Procedures='HV-P05'; Candidate=$elasticShell; Public='unusual parent to command shell'; Ours='network-active parent to interpreter child'; E1='PROCESS_LAUNCH'; E2='NETWORK_CONNECTION'; Decision='deferred'; Change='compensating_rule'; Branch='rare-parent fallback when network attribution is absent'; Strength='complementary' },
  @{ Rule='havoc_file_activity_from_network_process'; Procedures='HV-P06, HV-P07, HV-P08'; Candidate=$null; Public='no credible same-procedure public counterpart'; Ours='same-process file lifecycle and egress'; E1='FILE_READ'; E2='NETWORK_CONNECTION'; Decision='deferred'; Change='split'; Branch='sensitive read versus staging and deletion'; Strength='insufficient_evidence' },
  @{ Rule='havoc_memory_execution_from_network_process'; Procedures='HV-P09, HV-P10, HV-P11'; Candidate=$splunkInject; Public='remote-thread process injection'; Ours='broader verified memory execution plus egress'; E1='PROCESS_ACCESS'; E2='REMOTE_THREAD'; Decision='deferred'; Change='split'; Branch='direct cross-process access and execution sequence'; Strength='complementary' },
  @{ Rule='havoc_token_authentication_sequence'; Procedures='HV-P12'; Candidate=$elasticToken; Public='token theft from sensitive process'; Ours='explicit credentials or token semantic followed by execution'; E1='PROCESS_ACCESS'; E2='TOKEN_IMPERSONATION'; Decision='deferred'; Change='compensating_rule'; Branch='sensitive token-source process access'; Strength='complementary' },
  @{ Rule='havoc_discovery_fanout'; Procedures='HV-P04, HV-P13'; Candidate=$elasticDiscovery; Public='local process-discovery behavior'; Ours='process-attributed multi-target directory network discovery'; E1='LDAP_SEARCH'; E2='SMB_SESSION'; Decision='deferred'; Change='split'; Branch='single sensitive query and local discovery'; Strength='complementary' },
  @{ Rule='havoc_screen_capture_then_egress'; Procedures='HV-P14'; Candidate=$splunkScreen; Public='screenshot-like file creation'; Ours='verified capture semantic plus same-process egress'; E1='FILE_CREATION'; E2='NETWORK_CONNECTION'; Decision='deferred'; Change='compensating_rule'; Branch='file-backed capture when semantic telemetry is absent'; Strength='complementary' },
  @{ Rule='havoc_listener_and_forwarding'; Procedures='HV-P16'; Candidate=$chronicleForward; Public='configured Windows port-proxy state'; Ours='same-process listen and outbound relay effect'; E1='NETWORK_LISTEN'; E2='NETWORK_CONNECTION'; Decision='deferred'; Change='compensating_rule'; Branch='host configuration forwarding branch'; Strength='complementary' },
  @{ Rule='havoc_kerberos_ticket_effect'; Procedures='HV-P17'; Candidate=$splunkKerberos; Public='command-line ticket listing or purge'; Ours='LSA ticket mutation followed by resource use'; E1='KERBEROS_TICKET_SUBMIT'; E2='KERBEROS_RESOURCE_AUTHENTICATION'; Decision='rejected'; Change='compensating_rule'; Branch='command-line fallback for missing LSA telemetry'; Strength='ours_stronger' },
  @{ Rule='havoc_cleanup_after_network_activity'; Procedures='HV-P20'; Candidate=$null; Public='no credible cleanup sequence counterpart'; Ours='same-process deletion or termination after egress'; E1='FILE_DELETION'; E2='PROCESS_TERMINATION'; Decision='deferred'; Change='compensating_rule'; Branch='helper-process and delayed cleanup'; Strength='insufficient_evidence' },
  @{ Rule='havoc_server_control_plane_change'; Procedures='HV-P21'; Candidate=$null; Public='no credible Havoc control-plane audit counterpart'; Ours='sanctioned listener build task and service audit'; E1='LISTENER_CREATE'; E2='NETWORK_LISTEN'; Decision='deferred'; Change='compensating_rule'; Branch='server audit to resulting listener'; Strength='insufficient_evidence' }
)
$items = @($items | Where-Object Rule -ne 'havoc_server_control_plane_change')

foreach ($item in $items) {
  $canonical = Join-Path $repoRoot "detections/havoc/yaral/$($item.Rule).yaral"
  $internalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $canonical).Hash.ToLowerInvariant()
  if ($item.Candidate) {
    $candidatePath = Join-Path $repoRoot $item.Candidate
    $candidateHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidatePath).Hash.ToLowerInvariant()
    $relativeCandidate = $item.Candidate.Substring('public-rules/'.Length)
    $candidateBlock = "- [``$($item.Candidate)``](../../$relativeCandidate) - SHA-256 ``$candidateHash``"
  } else {
    $candidateBlock = '- No credible public counterpart found after procedure/effect search; adjacent rules were rejected as insufficient evidence.'
  }

  if ($item.Rule -eq 'havoc_server_control_plane_change') {
    $proposal = @"
rule havoc_server_audit_listener_confirmation_proposal {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    `$a.metadata.product_event_type = "LISTENER_CREATE"
    `$a.target.hostname = `$server
    `$l.metadata.product_event_type = "NETWORK_LISTEN"
    `$l.principal.hostname = `$server
  match:
    `$server over 10m
  condition:
    `$a and `$l
}
"@
  } else {
    $proposalName = "$($item.Rule)_proposal"
    $proposal = @"
rule $proposalName {
  meta:
    status = "experimental"
    validation_status = "unvalidated_proposal"
  events:
    `$a.metadata.product_event_type = "$($item.E1)"
    `$a.principal.hostname = `$host
    `$a.principal.process.product_specific_process_id = `$pid
    `$b.metadata.product_event_type = "$($item.E2)"
    `$b.principal.hostname = `$host
    `$b.principal.process.product_specific_process_id = `$pid
  match:
    `$host, `$pid over 10m
  condition:
    `$a and `$b
}
"@
  }

  $decisionReason = if ($item.Decision -eq 'adopted') { 'Independently verified destination grouping reduces accidental aggregation; implemented as havoc_stable_destination_beaconing without copying the public predicate.' } elseif ($item.Decision -eq 'rejected') { 'The public branch depends on mutable names or command implementation and would weaken behavioral coverage; proposal is retained only as unvalidated comparative code.' } else { 'Potentially useful compensating branch, but required parser fields and benign prevalence are not yet validated; canonical logic is unchanged.' }
  $content = @"
# Public-rule comparison: $($item.Rule)

## Identity and independence gate

- Internal rule: ``detections/havoc/yaral/$($item.Rule).yaral``
- Internal SHA-256: ``$internalHash``
- Internal review completed before public comparison: ``true``
- Procedures: $($item.Procedures)
- Public candidates were consulted only after independent source analysis, rule generation and adversarial review.

$candidateBlock

## Procedure and detection-branch matrix

| Branch | Our rule | Public rule | Primary signal and strength | Gap |
| --- | --- | --- | --- | --- |
| Preconditions and context | process/entity context | source-specific context | moderate — establishes causal scope | Both depend on source completeness |
| Security-sensitive action | $($item.Ours) | $($item.Public) | strong when close to the effect; weak when name/default based | $($item.Branch) |
| Resulting effect | correlated endpoint/network effect | candidate-specific effect | moderate to strong depending parser fidelity | Missing entity fields break joins |
| Cleanup or low-and-slow | partial | partial or absent | weak — neither proves completeness | Distributed, sparse and delayed behavior remains difficult |

## Missing detection branches

- Primary missing or weak branch: $($item.Branch).
- Neither rule can compensate for absent collection or unbounded extension behavior.
- Tool attribution is not inferred from shared behavior.

## Detection edge cases and blind spots

- Stable process identity can be lost through PID reuse, parser mismatch or sensor restart.
- Low-volume, distributed and delayed activity may fall outside the correlation window or threshold.
- Vendor semantic events require tenant verification; configurable names and infrastructure are not reliable gates.
- Benign administration, monitoring and security products can produce overlapping effects.

## Signal-quality assessment

- Our primary signal: $($item.Ours); ``moderate`` to ``strong`` because it correlates behavior/effect but remains telemetry-dependent.
- Public primary signal: $($item.Public); strength varies with proximity to the effect and reliance on mutable implementation details.
- Scoped conclusion: ``$($item.Strength)`` for the listed procedures only.

## Public-rule weaknesses

- The candidate is narrower, implementation-specific, product-specific, or absent for some Havoc branches.
- Public exclusions, thresholds and data-model assumptions are not trusted without independent validation.

## Internal-rule weaknesses

- $($item.Branch).
- Canonical joins and thresholds remain experimental pending representative tenant fixtures.

## Decision trail

- Candidate improvement: $($item.Branch)
- Independent verification: pinned Havoc report, internal review, telemetry contract and candidate hash/path above
- Decision: ``$($item.Decision)``
- Reason: $decisionReason
- Required regeneration: canonical review, telemetry, translations, dependencies and comparison when adopted

## Unmatched scope

- Public logic does not bound Havoc external services, in-memory job state or unavailable victim/server telemetry.
- Our logic does not inherit candidate-specific allowlists, ML models or command-name coverage.

## Proposed YARA-L improvement

- Change type: ``$($item.Change)``
- Addresses branches: $($item.Branch)
- Required telemetry: concrete $($item.E1) and $($item.E2) mappings with stable entity fields and collection health
- Validation status: ``unvalidated_proposal``

``````yaral
$proposal
``````

This proposal is actual detection logic for the scoped missing branch, not an automatic adoption. It must be compiled, mapped, benign-baselined and adversarially reviewed before canonical use. The only accepted comparison change in this pass is the independently implemented stable-destination recurrence rule documented above.
"@
  [IO.File]::WriteAllText((Join-Path $output "$($item.Rule).md"), $content, $utf8)
}

$index = @('# Havoc public-rule comparison index', '', 'Pinned revisions: Elastic `7e91c156324cdc64cda27f7fec7067b1148074ef`; Chronicle `234e9223c3b8f3d1c30209d9663797ba69057533`; Microsoft Sentinel `5f947544657288586559c41b218eaaf182636728`; Splunk `457ce9f5ea69a8d5be9463989ee23b9366858d16`.', '', 'All 13 canonical Havoc rules have procedure-level comparisons. Public logic remains untrusted comparative evidence.', '', '| Canonical rule | Comparison |', '| --- | --- |')
foreach ($item in $items) { $index += "| ``$($item.Rule)`` | [$($item.Rule).md](./$($item.Rule).md) |" }
[IO.File]::WriteAllText((Join-Path $output 'INDEX.md'), (($index -join "`n") + "`n"), $utf8)
Write-Host 'Generated 13 Havoc comparisons.'
