---
title: Nmap comprehensive source analysis
domain: tool-analysis
type: evidence
authority: reference
---

# Nmap comprehensive source analysis

## Scope and safety

- **Revision:** static analysis of official revision `80dd68b8d88cbc89e584941e9ba68e57247d2230` (committed 2026-11-20) from <https://github.com/nmap/nmap>, accessed 2026-11-21.
- **Handling:** shallow source clone to `sources/nmap-src/` (gitignored). It was not built or run, and the checkout contains no binaries.
- **Eligibility:** attackers run Nmap, Ncat and Nping on compromised hosts for discovery, brute force and relays. Execution, installation artifacts and the resulting network and authentication effects are observable on the host and on the targets. The analysis covers those effects. Scan-evasion options are described only by their observable consequence.

## Completeness inventory

| Component | Paths | Disposition |
| --- | --- | --- |
| Option parsing and scan selection | `nmap.cc` (scan types L1044-1309; `-oA` outputs L916-923) | Analyzed |
| Scan engines | `scan_engine.cc`, `scan_engine_connect.cc`, `scan_engine_raw.cc`, `idle_scan.cc`, `nmap_ftp.cc` | Analyzed |
| Host discovery, OS detection, traceroute, DNS | `targets.cc`, `osscan2.cc`, `FPEngine.cc`, `traceroute.cc` (L1547), `nmap_dns.cc` (L161) | Analyzed |
| Service and version detection | `service_scan.cc` (L2790), `nmap-service-probes` | Analyzed |
| Nmap Scripting Engine | `nse_*.cc`, `nse_main.lua`, `nselib/` (including `http.lua` L160), 620 `scripts/*.nse` | Analyzed by declared category and protocol behavior |
| Ncat | `ncat/` (long options `ncat_main.c` L245-285) | Analyzed |
| Nping | `nping/` | Analyzed |
| Windows installer | `mswin32/nsis/Nmap.nsi` (Npcap L229-236; performance tweak L248-252), `mswin32/nmap_performance.reg` | Analyzed |
| Zenmap | `zenmap/` | Excluded: a GUI front end that launches `nmap`, so its effect is identical to the procedures below |
| Ndiff | `ndiff/` | Excluded: offline comparison of local XML files |
| Bundled libraries, docs, tests, fuzzers | `lib*`, `nbase`, `nsock`, `liblua`, `docs/`, `tests/`, `fuzz/` | Excluded: implementation dependencies and non-deployed material; their behavior surfaces through the procedures above |

The 620 scripts declare these categories: safe 350, discovery 310, intrusive 216, default 124, vuln 105, brute 73, version 47, broadcast 47, exploit 45, auth 38, external 32, dos 12, malware 10, fuzzer 4. Every script belongs to at least one of procedures NM-P08 to NM-P12.

## Procedure analysis

| ID | Procedure | Ordered behavior and interfaces | Security effect | Telemetry and gaps | ATT&CK | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| NM-P01 | Host discovery | ICMP echo, timestamp or netmask; TCP SYN/ACK and UDP pings; ARP or Neighbor Discovery on local segments; raw packets when privileged, `connect()` probes otherwise | Live-host map | Raw probes are not process-attributed by common sensors. Use NDR or firewall flows; connect probes appear as process network events | T1018, T1046 | High |
| NM-P02 | TCP connect scan | Unprivileged default, using OS `connect()` per port (`scan_engine_connect.cc`) | Open-port map | Process-attributed outbound connections to many ports or hosts | T1046 | High |
| NM-P03 | Raw port scans | SYN, FIN, NULL, Xmas, ACK, Window, Maimon, UDP, SCTP INIT/COOKIE-ECHO and IP-protocol scans with crafted packets (`scan_engine_raw.cc`); needs administrator rights and Npcap on Windows | Port and firewall-state map | Half-open or flag-anomalous flows at NDR or firewall; no per-process attribution | T1046 | High |
| NM-P04 | Idle and FTP bounce scans | Spoofed probes inferred through a zombie host's IP ID (`idle_scan.cc`), or port scanning relayed through an FTP server's PORT command (`nmap_ftp.cc`) | Scans attributed to a third party | Zombie sees SYN/ACK-RST churn; the FTP server logs PORT commands to many ports | T1046, T1090 | High |
| NM-P05 | Service and version detection | Connects and sends `nmap-service-probes` payloads, matching banners (`service_scan.cc` L2790) | Software inventory | Many short connections with protocol probes; target service logs show malformed or probe requests | T1046 | High |
| NM-P06 | OS fingerprinting and traceroute | Crafted TCP, UDP and ICMP probe set (`osscan2.cc`, `FPEngine.cc`); TTL-stepped traceroute (`traceroute.cc` L1547) | OS and topology map | NDR signatures for fingerprint probe sets; no process attribution | T1082, T1016 | High |
| NM-P07 | Reverse DNS resolution | Mass PTR lookups for live hosts by default (`nmap_dns.cc` L161; `noresolve` and `resolve_all` options) | Host naming | Process-attributed DNS (Sysmon Event ID 22) or resolver logs with PTR bursts | T1018 | High |
| NM-P08 | NSE discovery, safe, default and version scripts | Lua scripts enumerate SMB, LDAP, SNMP, HTTP, DNS, RPC, SSL and other protocols; the HTTP library sends a default User-Agent naming the Nmap Scripting Engine (`http.lua` L160) | Detailed service and account enumeration | Target protocol logs; web and proxy logs show the default User-Agent unless overridden by script arguments | T1046, T1087, T1135 | High |
| NM-P09 | NSE brute and auth scripts | Credential guessing and default-credential checks across many protocols (73 brute, 38 auth) | Credential access | Authentication failures on targets (for example Security 4625 and 4771, service auth logs) from one source | T1110.001, T1110.003 | High |
| NM-P10 | NSE vuln, exploit, intrusive, dos, fuzzer and malware scripts | Vulnerability checks and exploitation attempts (105 vuln, 45 exploit, 12 dos, 4 fuzzer, 10 malware checks) | Exploitation or service disruption | Target IDS and application logs, specific to each script; launch command line names the categories | T1190, T1210, T1499 | High |
| NM-P11 | NSE broadcast scripts | Local-segment discovery over broadcast and multicast (LLMNR, mDNS, SSDP, NBNS, DHCP, WS-Discovery and others; 47 scripts) | Discovery without targets | Process network events to multicast and broadcast discovery ports | T1018, T1046 | High |
| NM-P12 | NSE external scripts | Queries third-party services (for example WHOIS, geolocation, reputation; 32 scripts) | Target enrichment | Egress to external APIs from the scanning host; launch command line | T1596 | Medium |
| NM-P13 | Output files | `-oN`, `-oX`, `-oG`, `-oS`, and `-oA` writing `<base>.nmap`, `<base>.xml` and `<base>.gnmap` (`nmap.cc` L916-923) | Collected results stored on host | File creation; the `.gnmap` extension is distinctive | T1074.001 | High |
| NM-P14 | Windows installation artifacts | The installer installs the bundled Npcap driver (`Nmap.nsi` L229-236) and optionally runs `regedt32 /S nmap_performance.reg`, setting `MaxUserPort` and `TcpTimedWaitDelay` (L248-252) | Packet-capture capability; TCP/IP tuning for scanning | Service and driver installation (System 7045, Sysmon Event ID 6); registry value sets (Sysmon Event ID 13); `regedt32 /S` process creation | T1543.003, T1112 | High |
| NM-P15 | Ncat | Connect or listen (`-l`), command execution bound to a socket (`-e`/`--exec`, `-c`/`--sh-exec`, `--lua-exec`), `--keep-open`, connection brokering and chat, `--ssl`, HTTP/SOCKS proxying (`ncat_main.c` L245-285) | Shells, relays and file transfer | Process creation with Ncat option grammar; listener or egress process spawning a shell | T1059, T1090, T1105 | High |
| NM-P16 | Nping | Packet generation (TCP, UDP, ICMP, ARP) and echo client and server modes | Reachability testing and covert echo channel | Process creation with Nping grammar; NDR flows | T1046, T1095 | High |

## Observed facts versus inference

- **Observed:** option grammar, scan-engine selection, output naming, the NSE User-Agent string, the Ncat flags and the installer actions.
- **Inference:**
  - Script categories are mapped to observable classes, because 620 scripts cannot each have a distinct rule. Per-script target signatures belong to IDS content.
  - Thresholds are detection hypotheses.
