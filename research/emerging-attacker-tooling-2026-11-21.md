# Emerging attacker tooling monitor - 2026-11-21

Cutoff: `2026-11-20T19:22:08.824Z` (scheduler record). Accessed: 2026-11-21.

## Knowledge retrieval evidence

- The default task-specific query and required narrower retry failed with `sqlite3.OperationalError: unable to open database file`.
- Temporary writable-index recovery succeeded: `query_id=1`, timestamp `2026-11-21T12:47:39.059105+00:00`, purpose: retrieve the prior monitor cutoff and audit recovery decisions; result count: 5.
- Sources used: `research/emerging-attacker-tooling-2026-11-09.md`, `research/emerging-attacker-tooling-2026-11-09-1901.md`, `research/emerging-attacker-tooling-2026-10-22.md`, `research/emerging-attacker-tooling-2026-10-18.md`, and `research/emerging-attacker-tooling-2026-10-17.md`.
- Action journal: [`../runs/actions/monitor-20261121-124739-01a1fe25.jsonl`](../runs/actions/monitor-20261121-124739-01a1fe25.jsonl).

## Material finding

### UNC6671 Browser Implant (CL-CRI-1192 / Helix)

- **Date and change type:** Unit 42 publication metadata records `2026-11-20T22:00:25Z`, after the cutoff. This is a new publication and operational corroboration of a browser implant first technically documented on 2026-09-10. It is not a newly created implant, a new structured-catalogue inclusion, or proof of a new credential primitive.
- **Capability:** A manually sideloaded Chromium extension masquerading as `Google Chrome` keylogs browser frames; collects cookies, local/session storage and IndexedDB data; scans QR codes; streams webcam data; and exposes remote browser control through the Chrome DevTools Protocol. Unit 42 found versions 1.6.111 and 1.6.112 sharing a C2 and API key.
- **Evidence level:** **High for code capability; moderate for actor attribution and operational use.** Kevin Pham's September static analysis independently documents the same builds and capabilities. Unit 42 now ties the extension to incident-response investigation involving CL-CRI-1192/UNC6671 and assesses the actor linkage with moderate confidence. Operator tasking was not recovered.
- **Why it matters:** The implant operates inside an authenticated browser, so it can expose session cookies, MFA-enrollment QR material, clipboard data, and SaaS content after interactive social engineering. This turns a malicious extension into a browser-scoped RAT and credential/session collector rather than a simple phishing accessory.
- **Affected systems:** Windows, macOS, or Linux desktops/laptops running Chromium-based browsers where a user is induced to enable Developer Mode and manually sideload the extension; Unit 42 explicitly names Chrome and Edge. The campaign primarily targeted U.S., UK, and Australian financial-services, healthcare, legal, and other data-rich organizations.
- **Defensive leads:** Enforce browser extension allowlists and block developer-mode/sideloading where feasible; inventory extension ID `lbakgdabeflabhecgpegbcncjhpbdhgc`; alert on unexpected `chrome.debugger` use and browser developer-mode warnings; inspect access to the published C2 paths and domains; correlate new extensions with cookie/session access, QR scanning, webcam use, and unusual SaaS data exports; require phishing-resistant MFA and strong help-desk identity verification.
- **Sources:** [Unit 42 primary report](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/), [independent static analysis by Kevin Pham](https://deoxy.net/blog/inside-unc6671s-browser-implant/), [GTIG's prior UNC6671 campaign context](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments), [publication timestamp metadata](https://www.cert24.eu/article.php?item_id=d3dc40fe108c14e320d6b78e&lang=en&report_id=cert-2026-11-20).

## Assessment

This is **not Mimikatz-scale**. It is a consequential credential and session-theft implant, but it requires user-assisted sideloading and privileged extension permissions and does not introduce a general Windows, Kerberos, NTLM, DPAPI, token, Active Directory, or Entra credential-extraction primitive.

The item is registered as `blocked_source`: public reporting and excerpts do not provide a complete, authoritative victim-side source/module inventory sufficient for the repository's full detection workflow. No sample, extension package, repository, offensive code, binary, archive, or malware payload was downloaded, opened, or executed.

## Other source review

No additional material post-cutoff change was verified in the named government, incident-report, structured-catalogue, or major research sources. Bazuka reporting was excluded because the primary ThreatFabric publication predates the cutoff; same-day articles were secondary republications. CAIRN and similar agentic frameworks were excluded as operator-side tooling. The current Unit 42 finding was retained because its publication timestamp is after the cutoff and it adds incident-response corroboration of endpoint-resident malware.
