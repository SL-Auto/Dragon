# Changelog

All notable agent capabilities and workflow changes are recorded here. The structure follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semantic release versions are not yet assigned.

## Unreleased

- Include historical daily run narratives and the root-level 2026-08-22 findings report in knowledge retrieval.

### Fixed

- Anchored unanchored short event-ID alternations in canonical YARA-L (for example `/(4778|4779|23|24|25)/`), which matched any ID containing those digits, such as 4625, 4720 and 1102. A repository-wide search now finds none remaining.
- Removed two invented, structurally unresolvable workflow states that had stalled 100% of the translation backlog and 87% of public-rule comparisons: `backend_validation: pending_external_mapping` (waited on a human analyst who never validates output in this pipeline) and comparison `Decision: deferred_pending_rule_improvement_run` (waited on a future run that was never scheduled to sweep it). `scripts/update-context-index.ps1` no longer fabricates these into `state/work-items.yml` and manifests; it instead reports the real per-rule `validation_status` labels already present in each rule's metadata. AGENTS.md step 17 and the quality gates now explicitly prohibit deferred/non-terminal comparison decisions and state that `experimental`/`needs_validation` is a legitimate, permanent terminal label for this pipeline rather than an incomplete state pending human sign-off.
- `scripts/update-master-telemetry-rule-counts.ps1` no longer counts a rule as depending on an event type because the type's name appears in meta prose. Dependencies are now taken only from the rule's `events:` section and its `log_source_prerequisites` (documented normalized aliases), with case-sensitive identifier matching. This removes false `telemetry/MASTER.md` dependencies such as every rule mentioning "path" under Linux auditd `PATH`, or "authentication" under Exchange `AUTHENTICATION`.
- Moved the one-off Cobalt Strike compensating-translation generator from `detections/cobalt-strike-beacon/` to `scripts/generate-cobalt-strike-compensating-translations.ps1` (path roots adjusted). Its location outside a recognized format directory had failed repository validation since 2026-08-23.
- Prevented telemetry card labels from growing on repeated filter clicks by removing a non-idempotent wording substitution and adding a regression test for repeated renders.

### Added

- `scripts/native_translations/`: a deterministic renderer and per-rule correlation specs that regenerate native secondary translations. KQL/SQL get exact ordered joins, SPL a stats correlation, EQL `sequence ... by` with per-event keys, and Sigma `temporal_ordered`/`value_count` correlations with aliases. Covers 29 rules that previously had no translations.
- Historical run logs and action journals were migrated to the validated format at the owner's request. Originals are preserved in `runs/_pre-migration-20261121/`; receipts were cited only where the local receipt store holds them.

- Replaced the telemetry workflow with two direct, sortable work queues: log data priorities ranked by dependent rule count with explicit Have/Missing state, and the reverse rule-readiness view ranked by missing required event types. Both views support search, state, tool, severity, log-source, and ordering controls as applicable.
- Reduced telemetry workspace complexity with progressive-disclosure views: a decision-focused requirements overview, a separate searchable atomic inventory, and a two-step availability lab separating collection inputs from coverage impact while preserving scenario state.
- Reworked telemetry interface terminology for detection engineers: data requirements, available event types, detection dependencies, collection limitations, and covered/degraded/uncovered detection states replace repository- and workflow-specific labels.
- Simplified telemetry data-availability assessment by removing percentages and abstract coverage/impact scores. Results now use concrete required-data states and collection suggestions show detections enabled or strengthened; standalone “provider” labels are replaced with “log source” or “telemetry provider.”
- Reframed telemetry as an explicit engineer workflow with question-based navigation, prominent start-here instructions, a single obvious next action, and four plain readiness states—Ready, Limited, Unavailable, and Unknown—defined beside the results.
- Removed legacy implementation-facing telemetry copy and qualified collection terminology consistently as log collection, including gaps, priorities, requirements, settings, and limitations.
- Replaced competing telemetry mode/subview tabs with one directional three-step workflow: review required logs, mark available data, then see which detections can run; the flow stacks vertically on narrow screens.
- Standardized telemetry terminology so the executable detection logic is always called a “detection rule” or “rule,” reserving “detection” for an actual detection result.

- Consolidated telemetry requirements and availability modeling into one Telemetry workspace with in-page Requirements and Availability Lab modes, one sidebar entry, shared event selection and backwards-compatible redirection from the former lab route.
- Redesigned the telemetry availability lab around additive collection planning: it now starts with no assumed telemetry, uses explicit available/not-collected states and Select all/Clear all actions, reports modeled coverage percentage, separates fully/partially/unsupported/unmodelled rules, filters impact states, and never treats absent dependency metadata as viable coverage.
- Extended the telemetry lab with per-tool scoping, provider filtering and bulk selection, per-tool coverage bars, and severity-weighted “collect next” recommendations showing which event type unlocks or improves the most rules.
- Replaced the telemetry Markdown landing page with an interactive atomic-event collection workspace: provider/posture/tool/severity filtering, field and enablement specifications, known-gap classification, severity-weighted rule dependencies, tool/rule drill-down, multi-selection, and direct telemetry-simulator handoff.
- Added a telemetry provider landscape, severity-weighted impact scoring, highest-impact fragile collection queue, impact/provider/event sorting, documented compensating-support display, quick-filter drill-down, and complete atomic-row JSON/CSV/Markdown exports.
- Improved interactive analysis with automatic repository-cache invalidation, paginated gap/comparison results, shareable telemetry simulation URLs, canonical-versus-proposed YARA-L workbench views, validation progress, removable notes/saved views, and action feedback.
- Added the interactive analyst workspace: procedure/signal graphs, detection-gap filtering, telemetry availability simulation, public-rule workspaces, ATT&CK navigation, run diffs, source-evidence maps, faceted search, rule validation checklists, local annotations/bookmarks/saved views, keyboard command palette, and JSON/CSV/Markdown/print exports.
- Added the deep `AnalystWorkspace` module, keeping canonical repository artifacts read-only while persisting analyst state separately in an ignored local state file.
- Extended detection-source highlighting to KQL, Splunk SPL, portable SQL, Elastic EQL, and Sigma YAML files and fenced Markdown snippets, with language-specific keywords and visual identities.
- Added native YARA-L 2.0 syntax highlighting with line numbers for canonical rule files and YARA-L proposal snippets embedded in Markdown reviews and comparisons.
- Made dashboard artifacts full-page navigable views instead of side-panel overlays and established a 14pt minimum text size throughout the web application.
- Full local web application that assembles portfolio status, procedure coverage, canonical rules and all translations, reports, adversarial reviews, telemetry, public-rule comparisons, run narratives, timestamped action timelines, and downloaded source code into a responsive analyst interface.
- Read-only repository catalog module with path containment, text-only source browsing, artifact size limits, resilient ranked search, JSON resources, interface-level tests, and a loopback-only launcher.
- Dark security-operations visual system with restrained telemetry accents, high-density data panels, code-focused artifact views, subtle grid/scan treatment, and reduced-motion-aware status animation.
- Class-aware Markdown presentation module and tailored analyst views for source reports, adversarial reviews, public comparisons, telemetry specifications, run narratives, procedure summaries, research notes, changelogs, and general documentation.
- Enforced knowledge-first bootstrap: indexed retrieval now precedes direct repository inspection, every search returns an auditable receipt, and completed run logs must record retrieval evidence.
- Append-only per-run JSONL action journals with UTC timestamps, ordered events, explicit targets/outcomes, narrative-log linkage, and structural validation.
- Victim-host eligibility gate: BAS/adversary-emulation platforms and C2 server/operator/control-plane behavior are excluded; C2 research is limited to implants/agents and endpoint-observable effects.
- Repository-contained knowledge retrieval with stable Python command-line and programmatic interfaces.
- Incremental SHA-256 indexing of configured knowledge sources into a disposable SQLite FTS5 index.
- Heading-aware chunks with source, heading, domain, type, authority, version, and tag attribution.
- Filtered, limited, authority-aware, and source-diversified retrieval with optional neighbouring context.
- Automatic stale-document refresh, deleted-document cleanup, atomic rebuilds, and SQLite WAL concurrency.
- Separate local query telemetry covering every attempted query, normalized request frequency, filters, zero-result searches, latency, and frequently returned sources and headings.
- Retrieval tests, configuration validation, an agent loading policy, and `.knowledge/` Git exclusion.
- Living capability changelog with required same-change maintenance and repository validation.

### Changed

- Agent context loading now begins with narrow retrieval before targeted source access or `rg` fallback.
- Phase profiles prohibit recursive documentation dumps by default.
- Daily and backlog processing now use a full-cycle completion unit: every selected tool must proceed from comprehensive inventory through canonical rule development, adversarial improvement, telemetry, translations, public comparison, downstream reconciliation, and validation in the same run unless genuinely blocked by safety or unavailable source.
- Secondary translation now creates missing backend directories automatically for newly added tools instead of failing mid-cycle.
- Removed superseded bundled Rubeus YARA-L and Sigma drafts after confirming the one-rule-per-file canonical and translated artifacts replace them; registry evidence now points only to maintained artifacts.
- Pruned an unreferenced older Microsoft Sentinel snapshot after a fresher commit-pinned snapshot was stored; the removed revision remains available through Git history.
- Removed repository-local editor preferences that were unrelated to the detection-agent workflow.

## 2026-08-15 — Public-rule comparison completion

### Added

- Threat-detection comparisons for all 100 canonical YARA-L rules across BloodHound, Cobalt Strike Beacon, Impacket, Mimikatz, Rubeus, and Sliver.
- Per-rule procedure-branch matrices, missing branches, edge cases, signal-strength assessments, internal/public weaknesses, and decision trails.
- Concrete YARA-L proposals classified as patches, compensating rules, splits, rewrites, or new rules.
- Comparison generation scripts and per-tool indexes.

### Changed

- Comparison review was refocused from syntax to detection engineering and false-negative coverage.
- Misleading or merely adjacent public mappings are rejected as `insufficient_evidence`.
- Validation rejects incomplete comparison sections and placeholder proposal logic.

## 2026-08-15 — Public detection-rule corpus

### Added

- Allowlisted upstream catalogue for public Google Chronicle YARA-L, Microsoft Sentinel KQL, Elastic EQL, and Splunk SPL rules.
- Commit-pinned, immutable, text-only snapshots with provenance, licenses, hashes, and freshness records.
- Daily public-rule refresh workflow and ignored working cache.
- Independent-generation gate requiring canonical rule authoring and review before public comparison.

### Security

- Public ingestion is restricted to declared text formats and never makes third-party logic canonical automatically.

## 2026-08-15 — Comprehensive workflow and context graph

### Added

- Comprehensive procedure coverage for BloodHound, Cobalt Strike Beacon, Impacket, Mimikatz, Rubeus, and Sliver at pinned revisions.
- Generated tool manifests, compact procedure summaries, rule dependency records, and incremental work-item state.
- Phase-specific context profiles, context-pressure stop conditions, and artifact size budgets.
- Atomic master telemetry inventory linking concrete provider event IDs/types to dependent rule counts by severity and tool.
- Schema profiles for Chronicle UDM, Splunk CIM, Sentinel/ASIM, normalized SQL, Elastic ECS, and Sigma.
- Completeness validation across reports, coverage, reviews, telemetry, dependencies, translations, and registry state.

### Changed

- `analyzed` means comprehensive for a pinned revision with zero unassessed procedures and explicit exclusions.
- Context management moved from broad loading to manifests and per-rule dependency records.

## 2026-08-15 — Secondary detection translations

### Added

- Per-tool subdirectories for canonical YARA-L and secondary SPL, KQL, SQL, Elastic EQL, and Sigma.
- Translation workflow preserving rule identity, procedures, severity, telemetry, false positives, references, status, and fidelity.
- Backend assumptions and explicit unsupported correlation, aggregation, absence, join, and field behavior.
- Translation review and regeneration requirements following canonical changes.

### Changed

- YARA-L 2.0 became the primary generation and refinement target; other formats are secondary experimental drafts.

## 2026-08-15 — One rule per file and expanded tooling

### Added

- Cobalt Strike Beacon and BloodHound to the analyzed tool set.
- One canonical `.yaral` file per rule, named exactly after its rule.
- Tool-level coverage ledgers and detection folders for every supported output language.

### Changed

- Bundled YARA-L content was split into independently reviewable rule files.

## 2026-08-15 — Detection review and telemetry engineering

### Added

- Full procedure ledgers for Impacket, Mimikatz, Rubeus, and Sliver.
- Adversarial reviews of branches, correlations, joins, windows, fields, parsers, false positives, false negatives, and telemetry gaps.
- Same-run rule improvement requirement; a review artifact alone no longer completes a tool.
- Per-tool collection plans, rule matrices, and atomic master telemetry aggregation.
- Compensating signals and explicit `not_observable`, `blocked_source`, and accepted-gap handling.

## 2026-08-15 — Initial baseline

### Added

- Defensive attacker-tool research agent with baseline and daily modes.
- Master registry with aliases, provenance, revisions, and lifecycle state.
- Pinned-source procedure analysis for initial Impacket, Mimikatz, Rubeus, and Sliver coverage.
- Experimental YARA-L drafts, templates, run logs, repository validation, discovery research, prioritization, and ATT&CK mapping.

### Security

- Strict prohibition on downloading, unpacking, reconstructing, or executing malware.
- Malware evidence limited to pre-existing opaque `.cart` containers; source repositories are static-analysis-only and are never built or run.
- Safety and provenance failures receive explicit blocked states instead of unsafe workarounds.

## Current feature inventory

- Baseline and daily attacker-tool discovery with incremental state.
- Comprehensive pinned-revision source and intelligence analysis.
- Procedure-level behavior, OS-interface, artifact, ATT&CK, telemetry, and validation documentation.
- Canonical one-rule-per-file YARA-L 2.0 detection engineering.
- Adversarial logic review followed by mandatory same-run improvements.
- Atomic event-level telemetry requirements and severity-weighted tool dependencies.
- Secondary SPL, KQL, SQL, Elastic EQL, and Sigma translations with fidelity tracking.
- Commit-pinned public-rule collection and independent rule-by-rule comparison.
- Generated manifests, summaries, dependency records, work queues, and phase profiles.
- Local attributed knowledge retrieval and private query telemetry.
- Repository-wide safety, completeness, structure, dependency, translation, telemetry, comparison, and context validation.
