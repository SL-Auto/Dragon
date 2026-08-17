---
title: Knowledge retrieval contract
domain: operations
type: standard
authority: mandatory
version: 1
tags: [context, retrieval, agent]
---

# Knowledge retrieval contract

`AGENTS.md` remains the small mandatory operating contract. This directory and configured repository artifacts are authoritative inputs to a disposable local index. `.knowledge/` is derived data and must never be committed.

## Agent loading policy

Start with a narrow search phrased around the decision being made. Except for the injected `AGENTS.md` safety and operating contract, this search must happen before directly reading repository documentation, registries, manifests, reports, rules, or source trees. Use metadata filters where possible and load no more than five chunks initially. Open a cited source only when the returned section is insufficient, a claim must be verified, or the source must be edited. Prefer a second refined query over loading a complete document. Two useful retrieval attempts are required before falling back to targeted `rg`.

Every response includes a receipt containing the local query ID, timestamp, result count, and latency. Copy the receipt ID, timestamp, purpose, result count, and sources actually used into the run log under `## Knowledge retrieval evidence`. Query text and aggregate frequency remain private in `.knowledge/queries.db`; the run log contains only sufficient audit evidence. A run without this section is incomplete.

For tool-specific work, combine retrieval with the existing dependency graph: load `manifests/<tool>.yml`, then retrieve the relevant procedure, telemetry, review, schema, or comparison section. Canonical artifacts remain authoritative over generated summaries.

## Authority

Results preserve `source`, `heading`, and optional front-matter authority. `mandatory` requirements override `recommended` and `reference` guidance. Retrieval score never changes authority. Resolve conflicts by reading the cited source.

## Commands

```powershell
python tools/knowledge/cli.py index
python tools/knowledge/cli.py index --rebuild
python tools/knowledge/cli.py search "YARA-L adversarial review requirements" --domain detection-engineering --top-k 5
python tools/knowledge/cli.py stats
python tools/knowledge/cli.py query-stats
```

Search returns JSON so agents and automation share one interface. Use neighbouring chunks only when a matching section depends on adjacent text.

## Query telemetry

Every search attempt, including zero-result and empty-term searches, is logged locally to `.knowledge/queries.db`. Records include the original and normalized query, timestamp, filters, requested result count, actual result count, latency, and each returned source, heading, rank, and score. `query-stats` reports the most requested normalized queries, zero-result searches, average latency, and the most frequently returned sources and headings.

The database is intentionally ignored by Git because query text can expose current defensive priorities. Delete the local database to reset telemetry; doing so does not affect authoritative knowledge or the search index.

## Maintenance

The index is incremental and content-hash based. Deleted sources are removed. Full rebuilds use a replacement database and atomic swap. Query logs are separate because they may reveal work priorities. Semantic retrieval is optional: its absence must degrade to SQLite FTS5 rather than prevent retrieval.
