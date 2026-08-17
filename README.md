# Attacker Tool Detection Research

This repository is the durable memory and output surface for a defensive detection-research agent. It supports an initial baseline and a daily incremental sweep while enforcing a strict **never execute malware** policy.

## Repository layout

| Path | Purpose |
| --- | --- |
| `registry/tools.yml` | Master list, aliases, provenance, versions, and lifecycle state |
| `CHANGELOG.md` | Historical and unreleased agent capabilities and workflow changes |
| `reports/<tool>/` | Procedure-level source/intelligence analysis |
| `detections/<tool>/` | Canonical one-rule-per-file YARA-L under `yaral/`, followed by secondary SPL, KQL, SQL, Elastic EQL, and Sigma translations |
| `reviews/<tool>/` | Adversarial reviews of rule logic, assumptions, gaps, and bypass-resistant coverage |
| `coverage/<tool>.yml` | Complete source/module and procedure coverage ledger |
| `telemetry/<tool>.md` | Consolidated collection plan and rule-by-rule telemetry requirements |
| `telemetry/MASTER.md` | Atomic event inventory with linked per-tool counts of dependent Critical/High/Medium/Low rules |
| `manifests/<tool>.yml` | Compact tool entry point, artifact hashes, rule index, and independent completeness states |
| `dependencies/<tool>/<rule>.yml` | Atomic rule-to-procedure, telemetry, field, correlation, translation, and hash record |
| `summaries/<tool>.md` | Compact generated procedure view; full reports remain the evidence layer |
| `schemas/` | Shared Chronicle, Splunk, Sentinel, SQL, Elastic, and Sigma field/correlation assumptions |
| `context/` | Phase loading profiles, stop conditions, and size budgets |
| `knowledge/` | Human-maintained retrieval guidance and knowledge metadata |
| `tools/knowledge/` | Local heading-aware knowledge index and search interface |
| `dashboard/` | Read-only full web application for tools, procedures, detections, reports, comparisons, telemetry, runs, and source code |
| `sources/` | Source manifests and pinned references; no malware payloads |
| `runs/` | Append-only run summaries |
| `state/` | Incremental-run cursor |
| `templates/` | Required report and detection structures |
| `scripts/validate.ps1` | Safety and structural quality gates |
| `public-rules/catalog.json` | Allowlisted upstream public-rule sources, paths, formats, and license metadata |
| `public-rules/snapshots/<source>/<commit>/` | Immutable, filtered text-only snapshots used only for independent validation |
| `public-rules/comparisons/<tool>/` | Rule-by-rule, dimension-specific comparisons with decision trails |

Generated context indexes are refreshed with `powershell -NoProfile -File scripts/update-context-index.ps1`. Use `-Check` to detect stale indexes without writing them.

Use `python tools/knowledge/cli.py index` to build or incrementally refresh the ignored local knowledge index. Retrieve only relevant sections with `python tools/knowledge/cli.py search "<question>"`; use `--domain`, `--authority`, `--top-k`, and `--include-neighbours` to constrain context. Search refreshes stale source documents and returns source paths and heading attribution. See `knowledge/README.md` for the agent contract.

Existing baseline research remains at the repository root and is indexed from the master list. It is prior evidence, not proof of comprehensive completion, and must be reconciled into the coverage ledger as each item is refreshed.

## Web dashboard

Run `powershell -NoProfile -File scripts/start-dashboard.ps1`, then open `http://127.0.0.1:8787`. The local read-only application assembles the repository into portfolio, tool, rule, comparison, telemetry, run-history, search, and downloaded-source views. See `dashboard/README.md` for configuration, safety constraints, architecture, and tests.

## Safe operating contract

- Public source repositories may be read and statically analyzed, but never built or run.
- Captured malware may only be referenced if it is already protected as a `.cart` container.
- `.cart` payloads remain opaque in this repository: no extraction, decryption, unpacking, or execution.
- When source is unavailable, use cited intelligence and label confidence and inference.
- Detection output is labeled `experimental` or `needs_validation` and is expected to stay that way in normal operation — this pipeline feeds an automated downstream process, not a human analyst who tests against live telemetry. That label is a permanent, honest property of the output, not a blocking incompleteness state; a rule must still ship as the agent's best recommendation, and the label is upgraded to `validated` only if and when live-telemetry validation evidence is actually supplied.

## Run prompts

Baseline: `Run the detection research agent in baseline mode. Follow AGENTS.md, update the registry, inventory every capability for each pinned tool revision, complete procedure and telemetry analysis, generate YARA-L for every observable procedure, adversarially review and revise the canonical logic, reconcile telemetry, translate finalized YARA-L into secondary SPL, KQL, SQL, Elastic EQL, and Sigma drafts with fidelity notes, validate, and continue until the comprehensive backlog is complete.`

Daily: `Run the detection research agent in daily mode. Follow AGENTS.md. Search for new or materially changed attacker tooling since the last successful run, update the registry, analyze safe new/changed items, generate and adversarially refine canonical YARA-L 2.0 rules, update telemetry, then translate changed rules into secondary SPL, KQL, SQL, Elastic EQL, and Sigma drafts. After our logic is complete, refresh commit-pinned public-rule snapshots and perform evidence-backed rule-by-rule comparisons without blindly adopting external changes. Validate and write today's run log. Never execute or unpack malware.`

Refresh allowlisted public rules with `powershell -NoProfile -File scripts/sync-public-rules.ps1`. The sync uses an ignored cache, retains only catalog-declared text rule files, and writes immutable snapshot manifests. Third-party rules are reference evidence and never become canonical merely because they are newer or public. Comparative reviews are detection-engineering assessments: they enumerate procedure branches, uncovered observables, strong versus weak signals, compensating coverage, telemetry blind spots, and false-negative edge cases. Query syntax is relevant only when it changes what behavior can actually be detected.

Every comparison must end with actual proposed YARA-L 2.0 code, classified as a patch, compensating rule, split, rewrite, or new rule. The proposal is then adversarially reviewed against the identified detection gap. Accepted or modified proposals must be applied to canonical YARA-L in the same run and trigger telemetry, translation, dependency, manifest, review, and comparison regeneration. Rejected proposals remain documented with evidence and do not change canonical logic.

## Validation

```powershell
powershell -NoProfile -File scripts/validate.ps1
```

The validator rejects suspicious binary/sample extensions outside `.cart`, rejects `.cart` files outside `samples-quarantine/`, rejects non-YARA-L rule formats, enforces exactly one rule per correctly named file, requires review metadata and a per-tool review artifact, checks required folders, and checks core registry fields. It does not certify detection correctness or YARA-L compilation.
