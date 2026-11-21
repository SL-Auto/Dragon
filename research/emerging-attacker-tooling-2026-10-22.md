# Emerging attacker tooling monitor - 2026-10-22

**Window:** 2026-10-18 11:01:33.480 UTC through 2026-10-22 17:52 UTC  
**Cutoff note:** `state/last-successful-run.txt` remains stale at 2026-08-15. The scheduler's prior-run timestamp is the comparison cutoff, consistent with prior monitor runs.  
**Safety:** Public webpages and metadata only. No repositories, code, archives, binaries, or malware samples were downloaded, cloned, built, unpacked, opened, or executed.

## Material findings

### HOOKEDGE operational expansion and previously undocumented loader

- **Date:** 2026-10-20.
- **Capability:** Symantec and Carbon Black documented HOOKEDGE activity against a law-enforcement agency, naval shipbuilder, and military-aircraft-engine manufacturer in two NATO states. On a Windows victim, operators used the backdoor for command execution and discovery, staged an SSH private key and persistent reverse tunnel, captured local NTLM challenge-response material, and deployed a previously undocumented reflective loader (`ld.exe`) whose final payload was not recovered.
- **Evidence level:** **Independent validation + real-world attacker adoption + new defensive leads.** Recorded Future originally documented HOOKEDGE in August as a Windows batch backdoor used by BlueDelta/APT28, including scheduled-task persistence, hidden Edge-based webhook C2, task execution, and exfiltration. Symantec's later endpoint investigation independently confirms operational use and materially extends the known post-compromise behavior. Sources: [Symantec/Broadcom investigation](https://www.security.com/threat-intelligence/swallowtail-russia-nato-targets) and [Recorded Future original analysis](https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge).
- **Why it matters:** This moves HOOKEDGE from an initial-access/backdoor description to observed hands-on-keyboard use for credential access and internal reachability at defense-relevant targets. The new loader is notable but remains functionally unresolved because its encrypted payload was unavailable.
- **Affected systems:** Windows endpoints in targeted government and defense organizations; environments permitting macro-enabled Office documents, script execution, scheduled tasks, outbound webhook traffic, and OpenSSH client use are especially exposed.
- **Defensive leads:** Correlate Office attachment-cache execution with macro child processes; scheduled tasks launching scripts from user-writable paths; hidden/off-screen Edge instances using `data:` URLs or webhook services; rapid task fetch/output-upload/delete cycles; unusual ownership/ACL changes on private-key files; background `ssh.exe` reverse forwarding; loopback HTTP listeners followed by forced local authentication; and reflective-loader command lines taking an encrypted data file plus a key. Treat static IOCs as pivots, not durable coverage.
- **Repository decision:** Registered as `blocked_source`. The public reports provide strong campaign evidence but not the complete victim-side source/module inventory required for a comprehensive procedure ledger and full detection workflow.

### DarkCore RAT capability publication

- **Date:** 2026-10-22.
- **Capability:** BlackFog published a DarkCore RAT analysis describing credential theft, hidden-desktop access, and a dedicated browser intended to reuse stolen sessions while routing through victim IP space. Public metadata independently identifies Windows-targeted DarkCoreRAT script delivery and associated process injection, scheduled-task persistence, scripting, PowerShell, discovery, and C2-related behaviors.
- **Evidence level:** **New publication + pre-existing defensive detection and structured malware metadata; real-world adoption not independently established.** The primary analysis is [BlackFog's DarkCore report](https://www.blackfog.com/darkcore-a-data-theft-rat-with-a-session-hijacking-browser/). MalwareBazaar records a DarkCoreRAT-labelled JavaScript item first seen on 2026-10-13 with multiple independent vendor verdicts and behavioral summaries; no sample was downloaded. [MalwareBazaar metadata](https://bazaar.abuse.ch/sample/440a48160f778b7682e9c52e99b1f71a5c99785675650bdfd197695e6d19e0b2/). ANY.RUN listed DarkCore behavior and network coverage in its September detection update, showing the family predates this publication. [ANY.RUN September coverage update](https://any.run/cybersecurity-blog/release-notes-august-2026/).
- **Why it matters:** Browser-session reuse and victim-IP proxying would extend credential theft into active session abuse, but the strongest capability claims currently rest on one new primary analysis. This is not a Mimikatz-scale breakthrough: it appears to depend on prior endpoint compromise and stolen browser state, and no general Windows, AD, Kerberos, NTLM, DPAPI, or token primitive was demonstrated.
- **Affected systems:** Windows endpoints and browsers holding reusable credentials or authenticated sessions.
- **Defensive leads:** Hunt for deceptive double-extension script attachments; `wscript.exe` or `cscript.exe` spawning PowerShell or `msbuild.exe`; script execution from temporary/user-writable paths; scheduled-task creation by scripting engines; cross-process memory writes/thread-context changes; and unusual browser processes or outbound sessions following credential-store access.
- **Repository decision:** Registered as `blocked_source`. Public metadata and one report are insufficient for the complete, safely reviewable victim-side procedure inventory required by the repository.

## Evidence classification

| Category | Post-cutoff material change |
|---|---|
| New publication | DarkCore RAT analysis (2026-10-22); Symantec HOOKEDGE operational expansion (2026-10-20) |
| Independent validation | Symantec independently validates and extends Recorded Future's HOOKEDGE reporting |
| Defensive detections | DarkCore had pre-existing ANY.RUN behavior/network coverage; new report adds hunting context |
| Real-world attacker adoption | HOOKEDGE observed in targeted NATO-state government/defense intrusions |
| Structured-catalogue inclusion | DarkCoreRAT present in MalwareBazaar metadata before the cutoff; no new post-cutoff ATT&CK/LOLBAS/LOLDrivers/GTFOBins inclusion verified |

## Checks and exclusions

- MITRE ATT&CK's current visible release remains v20 from 2026-10-13, before the cutoff. [MITRE ATT&CK October 2026 update](https://attack.mitre.org/resources/updates/updates-october-2026/)
- No qualifying post-cutoff addition was verified in LOLBAS, LOLDrivers, or GTFOBins. Black Hat Europe 2026's Arsenal schedule contains prospective tools, but the schedule does not establish a post-cutoff release or attacker adoption, and BAS/adversary-emulation/operator-only entries are out of scope. [Black Hat Europe Arsenal schedule](https://blackhat.com/europe/arsenal/schedule/index.html)
- Symantec's 2026-10-21 “Skynet” report describes an offensive orchestration agent running through hijacked exposed LLM services. It is excluded because the agent is an attacker-side/control-plane system rather than a victim-host component, even though it directs attacks against servers. [Symantec/Broadcom Skynet report](https://www.security.com/threat-intelligence/ai-llmjacking-skynet)
- Unit 42's post-cutoff PAN-OS update concerns exploitation activity and ransomware-actor attribution without new endpoint-resident tooling or post-access behavior, so it does not create a tooling entry. [Unit 42 CVE-2026-0257 update](https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/)
- Searches of CISA advisories, The DFIR Report, Microsoft Threat Intelligence, Cisco Talos, Google Threat Intelligence/Mandiant, GitHub security topics, DEF CON, and MalwareBazaar metadata found no other sufficiently evidenced in-scope material change in the window. Search and catalogue indexing can lag; this is a time-bounded assessment.

## Knowledge retrieval evidence

- Query receipt: `query_id=1`, timestamp `2026-10-22T17:49:14.477436+00:00`, purpose: recover the prior monitor's cutoff, evidence categorization, safety decisions, and validation blockers; result count: 5.
- Sources used: `research/emerging-attacker-tooling-2026-10-18.md`, `research/emerging-attacker-tooling-2026-10-17.md`, `research/emerging-attacker-tooling-2026-10-13.md`, and `research/emerging-attacker-tooling-2026-09-18.md`.
- The default repository index and required narrower retry failed with `sqlite3.OperationalError: unable to open database file`; the documented temporary writable-index recovery returned the records above.

## Run integrity

- Action journal: [`runs/actions/monitor-20261022-871f88b1.jsonl`](../runs/actions/monitor-20261022-871f88b1.jsonl)
- HOOKEDGE and DarkCore RAT stopped at `blocked_source`; no incomplete coverage, rule, review, telemetry, translation, or comparison artifacts were created.
- Public-rule refresh, context-index refresh, and validation were attempted, but PowerShell `AuthorizationManager` blocked all three scripts before execution. Existing public-rule snapshots were preserved, `state/last-successful-run.txt` remains 2026-08-15, and the run is partial.
