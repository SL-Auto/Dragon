# Nmap adversarial detection-logic review

## Review scope

- Revision `80dd68b8d88cbc89e584941e9ba68e57247d2230`, procedures NM-P01 to NM-P16 in `reports/nmap/source-analysis.md`.
- 13 rules under `detections/nmap/yaral/`, including two added after public comparison (NM-DR-08, NM-DR-09).
- Method: every rule was assumed wrong until supported. Regexes, joins, thresholds and exclusions were traced against the option parser, scan engines, NSE libraries, Ncat options and the Windows installer.

## Overall assessment

Launch-time grammar and binary identity are the strongest host signals. Network breadth covers raw scans that hosts cannot attribute, and target-side authentication fan-out covers brute scripts. Per-script exploitation (NM-P10) has no generic host signature and relies on launch grammar plus IDS content. No blocker remains.

## Findings

### NM-DR-01 — raw scans are not process-attributed

- Severity: `high`
- Procedures: NM-P01, NM-P03, NM-P04, NM-P06.
- Gap or failure mode: SYN, flag, UDP, OS-detection and ARP probes are crafted through Npcap or raw sockets. Sysmon Event ID 3 and most EDR network events do not attribute them to the process.
- Resolution: `accepted_gap` on the host, inherent to collection. Compensating signals: `nmap_network_scan_flow_pattern` (flow breadth at NDR or firewall, with denied and reset flows retained), `nmap_cli_option_grammar`, `nmap_binary_identity_execution` and `nmap_npcap_driver_install`.

### NM-DR-02 — option-grammar collisions

- Severity: `medium`
- Rule: `nmap_cli_option_grammar`
- Assumption challenged: that `-s?` plus `-p` identifies Nmap.
- Gap or failure mode: other tools use `-s` and `-p` flags.
- Resolution: `fixed` in design. The rule requires an Nmap scan-type token from the exact `-s` letter set together with a second Nmap-specific option (`-Pn`, `-P?`, `-O`, `-A`, `-T0-5`, `--top-ports`, `--script`, `-o?`, `--min-rate`, `--open`, or a port list). Standalone `--script` with an NSE category or `.nse` name, and Nping's long options, are separate branches. Default invocations with no options are covered by NM-DR-08.

### NM-DR-03 — connect-scan fan-out overlaps scanners

- Severity: `medium`
- Rule: `nmap_process_connect_scan_fanout`
- Gap or failure mode: approved vulnerability scanners and discovery agents reach 50 hosts or ports.
- Resolution: `accepted_gap`, with a fail-open signature exclusion and medium severity. Approved scanner hosts must be allowlisted in triage. Slow scans (for example `-T0` or `-T1`) stay below 50 in 5 minutes and depend on launch-grammar rules.

### NM-DR-04 — the NSE User-Agent can be overridden

- Severity: `low`
- Rule: `nmap_nse_http_default_user_agent`
- Gap or failure mode: the `http.useragent` script argument replaces the default string (`http.lua` L160).
- Resolution: `accepted_gap`. The rule is a corroborating signal; `nmap_cli_option_grammar` catches `--script-args` on the host.

### NM-DR-05 — Ncat short flags collide with shells

- Severity: `high`
- Rule: `ncat_exec_or_broker_grammar`
- Gap or failure mode: `-c` plus any `-?l?` token matched `bash -c "ls -al"`.
- Resolution: `fixed`:
  - The listen token is restricted to Ncat's companion letters (`-[nvk]*l[nvkp]*` or `--listen`).
  - A port argument is required.
  - Ncat-only long options (`--sh-exec`, `--lua-exec`, `--broker`, `--chat`, `--keep-open`) remain a standalone branch.

### NM-DR-06 — the authentication fan-out is generic

- Severity: `medium`
- Rule: `nmap_auth_failure_fanout_from_source`
- Gap or failure mode: any brute-force tool, a misconfigured service or a NAT gateway produces the same pattern, and NSE brute scripts against non-Windows services need normalized service logs.
- Resolution: `accepted_gap`. The rule is attributed to Nmap only in conjunction with host-side signals from the same source. Medium severity.

### NM-DR-07 — the installation artifacts are optional

- Severity: `low`
- Rules: `nmap_npcap_driver_install`, `nmap_tcpip_performance_tweak`
- Gap or failure mode: the installer accepts `/NPCAP=NO` (`Nmap.nsi` L8), portable copies skip the installer, and Npcap may already be present from Wireshark.
- Resolution: `accepted_gap`. These are corroborating, medium-severity signals; Wireshark installations are a documented false positive.

### NM-DR-08 — default invocations carry no option grammar (from comparison)

- Severity: `medium`
- Rule: new `nmap_binary_identity_execution`
- Gap or failure mode: `nmap <target>` with no options never matches `nmap_cli_option_grammar`.
- Resolution: `compensating_signal`. The Windows PE `OriginalFilename` is `nmap.exe` (`mswin32/nmap.rc` L37) and survives renaming. On other platforms the image name `nmap` is used, which is mutable and noted as such.

### NM-DR-09 — the shell effect of a socket-bound Ncat (from comparison)

- Severity: `medium`
- Rule: new `ncat_socket_bound_shell_child`
- Gap or failure mode: the grammar rule sees the Ncat launch only. A renamed netcat variant with different long options, or one launched by a wrapper, is visible through its child shell.
- Resolution: `compensating_signal`. A shell child whose parent command line binds a program (`-e`, `--exec`, `-c`, `--sh-exec`) with listen mode or an IP address and port. The parent name is not used.

## Not observable or excluded

- Zenmap and Ndiff are excluded in the report: Zenmap is a front end that launches `nmap`, and Ndiff only compares local files.
- NM-P10 per-script exploitation is detected through launch grammar. Per-exploit target signatures belong to IDS content and are not reproduced here.

## Re-review of revised rules

- All 13 rules were re-traced after NM-DR-05, NM-DR-08 and NM-DR-09.
- Backslashes in path regexes were verified as literal (`\\`).
- Ports use integer equality, joins carry host and process ID, thresholds are computed in `outcome`, and exclusions fail open.
- No unresolved `blocker` remains.

## Required follow-up

- Verify OriginalFileName and ParentCommandLine mappings in the tenant.
- Retain denied and reset flows at network sensors.
- Baseline approved scanners and administrators.
- Keep all rules experimental.
