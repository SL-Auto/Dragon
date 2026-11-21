# Emerging attacker tooling monitor - 2026-11-09

**Window:** 2026-11-04 13:14:14.892 UTC through 2026-11-09 00:56 UTC  
**Cutoff note:** `state/last-successful-run.txt` remains stale at 2026-08-15. The scheduler's prior-run timestamp is the comparison cutoff, consistent with prior monitor runs.  
**Safety:** Public webpages and metadata only. No repositories, code, archives, binaries, or malware samples were downloaded, cloned, built, unpacked, opened, or executed.

## Material finding

### Lindnor backdoor and clustered BYOVD security-tool tampering

- **Date:** 2026-11-05 (publication); activity observed in October 2026.
- **Capability:** Symantec and Carbon Black documented a previously unpublished Windows backdoor, Backdoor.Lindnor, on two Microsoft SQL Server hosts during an Anubis ransomware intrusion. It appeared to run as a Windows service, reported host and identity context to primary and fallback command-and-control infrastructure over port 443, and was also found at two unrelated organizations. In the same intrusion, the actor dropped at least 13 security-disabling executables within roughly one hour, including five publicly known vulnerable signed drivers, then configured AnyDesk for Safe Mode access. The ransomware payload was blocked before encryption.
- **Evidence level:** **New publication + real-world attacker adoption + defensive detection; no independent technical validation.** The primary incident evidence is the [Symantec/Carbon Black investigation](https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware). Cyware independently indexed the publication and the associated behaviors, but this is secondary reporting rather than an independent incident or sample analysis: [Cyware daily briefing](https://www.cyware.com/resources/threat-briefings/daily-threat-briefing/cyware-daily-threat-intelligence-november-05-2026). SOCRadar separately structured 26 published indicators, which is catalogue inclusion of the report's data rather than independent validation: [SOCRadar IOC record](https://ioc.socradar.io/reports/new-lindnor-backdoor-and-glut-of-security-killers-used-in-ransomware-attack-on-u-s-org-d9de8113fdf5).
- **Why it matters:** A custom service-based backdoor plus rapid deployment of many BYOVD security killers gives ransomware affiliates redundant persistence and defense-impairment paths. The concentration of previously unpublished executables is more material than another Anubis branding update, but the public evidence does not establish a new credential-access primitive.
- **Affected systems:** Windows servers and endpoints, particularly exposed or high-value Microsoft SQL Server hosts and environments where vulnerable-driver block rules, service creation controls, or Safe Mode remote-access controls are weak.
- **Defensive leads:** Correlate new services from vendor-themed or user-writable paths with outbound TLS to rare destinations; alert on bursts of newly written executables and signed vulnerable-driver loads; monitor kernel callback removal or security-service termination attempts; review Safe Mode boot configuration changes, new local accounts, and remote-access software configured to survive Safe Mode; enforce the Microsoft vulnerable-driver blocklist and application control. Treat hashes and filenames as short-lived pivots.
- **Repository decision:** Registered as `blocked_source`. The public incident report supports the behaviors above but cannot provide the complete victim-side source/module inventory required for a comprehensive procedure ledger and full detection workflow.
- **Mimikatz-scale assessment:** **No.** Lindnor and the associated security killers require an existing foothold and do not demonstrate a general Windows, AD, Kerberos, NTLM, DPAPI, token, or credential-recovery breakthrough.

## Evidence classification

| Category | Post-cutoff material change |
|---|---|
| New publication | Lindnor and the clustered security-killer/BYOVD activity (2026-11-05) |
| Independent validation | None; secondary reports restate the primary investigation |
| Defensive detections | Symantec reports endpoint blocking; published IOCs were indexed by SOCRadar |
| Real-world attacker adoption | Lindnor observed in an Anubis intrusion and at two unrelated organizations |
| Structured-catalogue inclusion | SOCRadar indexed 26 report-derived indicators; no new ATT&CK/LOLBAS/LOLDrivers/GTFOBins inclusion verified |

## Checks and exclusions

- MITRE ATT&CK still identifies v20, released 2026-10-13, as the current major release; the visible v20.1 patch predates this run's cutoff. [MITRE ATT&CK October 2026 update](https://attack.mitre.org/resources/updates/updates-october-2026/)
- Microsoft's 2026-11-05 ARTEX reporting is a material observation of an agentic offensive framework, but ARTEX is an attacker-side orchestration/control-plane platform and is excluded by the victim-host eligibility gate. [Microsoft ARTEX report](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)
- Elastic's November threat report is dated 2026-11-04 without a verifiable post-cutoff time and summarizes April-September activity; it cannot be established as a new post-cutoff item. [Elastic November 2026 report](https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust)
- Black Hat Europe Arsenal is prospective for December and its schedule alone does not establish release, victim-host execution, or attacker adoption. [Black Hat Europe Arsenal schedule](https://blackhat.com/europe/arsenal/schedule/index.html)
- Searches of CISA advisories, The DFIR Report, Microsoft Threat Intelligence, Google Threat Intelligence/Mandiant, Elastic, Symantec, GitHub security topics, LOLBAS, LOLDrivers, GTFOBins, DEF CON, Black Hat Arsenal, and MalwareBazaar metadata found no other sufficiently evidenced, in-scope material post-cutoff change. Search and catalogue indexing can lag; this is a time-bounded assessment.

## Knowledge retrieval evidence

- Default retrieval failed with `sqlite3.OperationalError: unable to open database file` before a receipt could be created.
- The documented temporary writable-index recovery succeeded: `query_id=1`, timestamp `2026-11-09T00:55:10.978939+00:00`, purpose: recover the prior cutoff and audit blockers for the post-2026-11-04 monitor; result count: 5.
- Sources used: `research/emerging-attacker-tooling-2026-10-22.md`, `research/emerging-attacker-tooling-2026-10-18.md`, and `research/emerging-attacker-tooling-2026-10-17.md`.

## Run integrity

- Action journal: [`runs/actions/monitor-20261109-01a1bdcc.jsonl`](../runs/actions/monitor-20261109-01a1bdcc.jsonl)
- `tools/runlog/cli.py` could not append after initialization (`OSError: [Errno 9] Bad file descriptor`); the permitted append-only patch fallback was used and verified by read-back.
- Lindnor stopped at `blocked_source`; no incomplete coverage, rule, review, telemetry, translation, or comparison artifacts were created.
- Public-rule sync, context-index refresh, and validation were attempted but PowerShell `AuthorizationManager` blocked all three scripts before execution. Existing public-rule snapshots were preserved, generated context may be stale, and `state/last-successful-run.txt` was not advanced. This run is partial.
