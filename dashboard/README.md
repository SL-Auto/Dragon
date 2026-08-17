# Detection Research Dashboard

A local, read-only web application over the repository's authoritative and generated detection-research artifacts.

The interface uses a dark, high-contrast security-operations theme optimized for dense reports, detection logic, timelines, and long analyst sessions.

## Start

From the repository root:

```powershell
python -m pip install -r dashboard/requirements.txt
python dashboard/server.py
```

Open `http://127.0.0.1:8787`. To use a different bind address or port:

```powershell
python dashboard/server.py --host 127.0.0.1 --port 9000
```

The default loopback bind is intentional. The application has no authentication and exposes defensive research and locally downloaded source code; do not bind it to a shared interface without placing it behind an appropriately secured reverse proxy.

## Views

- Portfolio metrics and lifecycle status
- Tool-level procedures, completeness, canonical YARA-L rules, and all translations
- Reports, coverage ledgers, detection and translation reviews, telemetry, and comparison indexes
- Rule-level public comparisons beside every canonical rule
- Timestamped run action timelines and narrative logs
- Safe, text-only browsing of downloaded source repositories under `sources/`
- Contained artifact-library browsing across manifests, dependencies, schemas, research, public-rule snapshots, state, templates, and every output directory
- Ranked full-repository search across reports, detections, reviews, telemetry, comparisons, runs, and source code
- Class-aware Markdown presentations: procedure dossiers for reports, finding cards for reviews, branch/decision workspaces for comparisons, collection matrices for telemetry, operational run narratives, compact summaries, research briefs, and change-history views
- Line-numbered YARA-L 2.0 syntax highlighting for canonical `.yaral` files and YARA-L snippets embedded in reviews and comparisons
- Language-aware, line-numbered source views for KQL, Splunk SPL, portable SQL, Elastic EQL, and Sigma YAML translations and embedded snippets
- Procedure-to-rule-to-telemetry signal explorer and reverse dependency navigation
- Interactive coverage-gap dashboard, unified telemetry requirements/availability workspace, ATT&CK navigator, run diffs, and source-evidence maps
- Rule workbench combining canonical logic, translations, procedures, atomic telemetry, public comparison conclusions, annotations, bookmarks, and validation evidence
- Faceted search, saved analyst views, keyboard command palette, and JSON/CSV/Markdown/print exports
- Live cache invalidation, paginated large result sets, shareable telemetry scenarios, canonical/proposed-rule comparison, validation progress, and removable local workspace items
- Interactive atomic telemetry inventory with collection specifications, posture classification, provider/tool/severity filters, rule drill-down, per-tool requirements, multi-selection, and simulator handoff
- Telemetry provider landscape, impact-ranked fragile collection queue, severity-weighted sorting, documented compensating support, quick-filter navigation, and complete atomic inventory exports
- Additive telemetry availability lab that starts from no assumed collection, distinguishes unavailable from unmodelled dependencies, reports full/partial/unsupported rule coverage, and makes coverage improve as collected event types are selected
- Tool-scoped telemetry modeling, provider bundles, per-tool coverage, and ranked next-best collection recommendations based on rules unlocked and severity-weighted gain
- Progressive-disclosure telemetry navigation: overview and atomic-inventory views for requirements, plus separate collection-input and coverage-impact steps in the availability lab
- Detection-engineering terminology throughout telemetry views, describing data availability, event requirements, detection dependencies, coverage gaps, and collection priorities without requiring knowledge of repository internals
- Direct data-availability states for detections—every requirement available, some missing, all missing, or requirements undocumented—with collection suggestions expressed as detections enabled or strengthened rather than abstract scores
- Task-led telemetry workflow with question-based navigation, explicit selection criteria, prominent next-step actions, and readiness definitions displayed next to detection results
- Concise telemetry copy using explicit log-collection terminology throughout; no standalone “collection” wording or implementation-facing atomic/provider language in the rendered workflow
- Single directional telemetry flow—required logs, available data, detection readiness—with one navigation layer and responsive left-to-right or top-to-bottom presentation
- Precise rule terminology throughout telemetry views: “detection rule” or “rule” for executable logic, never the ambiguous standalone “detection”
- Two operational telemetry backlogs: event types ranked by dependent rules with persistent Have/Missing controls, and rules ranked by missing required event types; both provide direct priority sorting and filtering

## Architecture

`RepositoryCatalog` is the deep read-only module at the repository seam. Its small interface hides registry reconciliation, manifest/coverage joins, detection-format discovery, run-log assembly, path containment, source-tree traversal, and search. `MarkdownPresenter` classifies Markdown and turns headings, matrices, code, findings, procedures, decisions, lists, and evidence into one stable view model. `AnalystWorkspace` is the investigation seam: it reconciles procedures, rules, dependencies, telemetry, comparisons, ATT&CK references, runs, validation, annotations, bookmarks, saved views, and exports behind `query`, `change`, and `export`. The HTTP adapter exposes those interfaces as JSON.

The server reads artifacts on request and creates no application database. Restart it after registry membership changes because the registry is loaded at startup; ordinary report, rule, comparison, telemetry, run-log, and source changes are visible immediately.

## Safety and limitations

- No repository code or malware is executed.
- Source browsing is restricted to `sources/` and text-like extensions.
- Artifact paths are resolved and checked against the repository root.
- Inline artifacts are capped at 2 MB and search candidates at 1 MB.
- The application is read-only and intended for local analyst use.
- Canonical repository artifacts remain read-only. Analyst annotations, bookmarks, saved views, and validation evidence are written only to the ignored local file `dashboard/state/analyst-workspace.json`.

## Tests

```powershell
python -m unittest discover -s dashboard/tests -v
```
