# Public detection-rule sources for daily comparison

Research date: 2026-08-15

## Scope and selection

These four repositories are the primary upstream, vendor-maintained sources recommended for the first daily mirror. They cover the requested native formats or, in Elastic's case, the vendor's rule container with embedded EQL. This is a strong authoritative baseline, not a claim that every public rule on the internet has been enumerated. Community forks and aggregators should be registered separately, with provenance and licence review, rather than silently mixed into these vendor corpora.

| Corpus | Upstream and branch | Rule paths and representation | Licence and mirroring caveat |
|---|---|---|---|
| Elastic Security prebuilt rules (EQL) | `https://github.com/elastic/detection-rules.git`, default branch `main` | `rules/**/*.toml` and `rules_building_block/**/*.toml`; select records whose rule type/language is EQL and retain the complete TOML metadata, query, exceptions and references. The repository identifies these directories as the roots for ordinary and building-block rules and exposes tooling that searches rules using EQL/KQL. [Upstream README](https://github.com/elastic/detection-rules#overview-of-this-repository) | Elastic License 2.0, not an OSI open-source licence. Elastic states that everything in the repository is ELv2 and that rules are intended for Elastic Security's Detection Engine. Preserve `LICENSE.txt` and `NOTICE.txt`, keep the mirror segregated, and have repository owners confirm that the intended storage/redistribution complies with ELv2 before publishing the mirror. [Elastic licensing statement](https://github.com/elastic/detection-rules#licensing) |
| Microsoft Sentinel analytics (KQL) | `https://github.com/Azure/Azure-Sentinel.git`, default branch `master` | Primarily `Solutions/**/Analytic Rules/*.yaml`; also inventory legacy `Detections/**/*.yaml` without assuming it duplicates packaged solution content. Extract the `query` only for indexing while retaining the full YAML because scheduling, data connectors, entity mappings and metadata affect comparison. Microsoft describes the repository as containing out-of-box detections and hunting queries, and its contribution checks validate both template structure and embedded KQL. [Upstream README](https://github.com/Azure/Azure-Sentinel#readme) | MIT. Retain the copyright and permission notice with copies or substantial portions. [Upstream licence](https://github.com/Azure/Azure-Sentinel/blob/master/LICENSE) |
| Splunk Security Content (SPL) | `https://github.com/splunk/security_content.git`, default branch `develop` | `detections/**/*.yml` is the canonical detection set; retain associated `macros/`, `lookups/`, `data_sources/` and `baselines/` references because the SPL may not be semantically complete without them. Splunk calls `detections/` its growing detection-search collection and explicitly warns that macros and lookups are dependencies. [Upstream README](https://github.com/splunk/security_content#content-parts-) | Apache-2.0. Preserve the licence and applicable notices; mark modified copies. [Upstream licence statement](https://github.com/splunk/security_content#license) |
| Google SecOps example/community detections (YARA-L) | `https://github.com/chronicle/detection-rules.git`, default branch `main` | `rules/community/` contains YARA-L rules from Google SecOps team members and the user community. Mirror the rule files verbatim plus their paths. Google explicitly distinguishes these examples from licensed, non-public SecOps Curated Detections and recommends testing/tuning before deployment. [Upstream README](https://github.com/chronicle/detection-rules#google-security-operations-detection-rules) | Apache-2.0. Preserve the licence and applicable notices; mark modified copies. [Upstream licence](https://github.com/chronicle/detection-rules/blob/main/LICENSE) |

## Daily version-pinned mirror contract

For each source, fetch its named default branch without executing any repository code, resolve the remote branch to an immutable full commit SHA, and copy only the registered rule/dependency paths into a source-specific snapshot. A daily manifest should record:

- stable source ID, upstream URL, default branch and exact commit SHA;
- upstream commit author/committer timestamp and local fetch time in UTC;
- previous mirrored SHA and comparison range (`previous_sha..current_sha`);
- selected and excluded paths, file count, and a SHA-256 for every mirrored file;
- upstream licence identifier plus hashes of the mirrored licence and notice files;
- additions, modifications, renames and deletions derived from Git, preserving deletion history;
- parser/schema version used to inventory rules, plus parse failures without dropping the original files;
- upstream-native identity where present (rule UUID/ID), upstream path, title, language/type, status, severity, ATT&CK mappings, data sources and last-modified metadata.

Store immutable snapshots by source and commit, with a separate `current` index or manifest pointing to the newest successful SHA. Do not overwrite an old snapshot and do not use a moving branch name as evidence in comparison reports. Tags/releases may be recorded as additional labels, but the commit SHA remains the pin because repositories do not all publish releases consistently and the default branch can contain fresher unreleased content. Elastic specifically notes that its repository may contain rules newer than released Stack content. [Elastic README](https://github.com/elastic/detection-rules#questions-problems-suggestions)

## Comparison safeguards

Third-party content is evidence for independent verification, not a template for generating the canonical YARA-L. Complete this project's source/procedure analysis, canonical rule, adversarial review and telemetry reconciliation before loading candidate third-party matches. Compare at procedure and observable-signal level rather than by title or ATT&CK technique alone.

For each plausible rule pairing, record separately:

- behavioral scope and procedures covered or omitted;
- required event providers, concrete event types/IDs, fields, parsers and enablement;
- predicates, joins, event ordering, windows, thresholds, cardinality and absence logic;
- mutable indicators and environment assumptions;
- false-positive controls and the risk introduced by exclusions;
- realistic false-negative classes, platform/version gaps and correlation fidelity;
- validation evidence and whether each conclusion is observed, documented or inferred;
- outcome: ours stronger, upstream stronger, complementary, incomparable, or insufficient evidence, with rationale.

Never apply an upstream change automatically. Create a review finding and a proposed local change linked to evidence; then subject that proposal to the same adversarial review, telemetry reconciliation, translation refresh and validation gates as independently authored logic. An upstream rule's vendor origin, recency, popularity or passing syntax checks is not evidence that its detection assumptions are correct for this repository's telemetry model.

## Important corpus limitations

- Elastic rules are TOML detection objects containing queries, not standalone `.eql` files; filtering and comparison must respect their declared rule language/type.
- Microsoft and Splunk rules often depend on surrounding schemas, parsers, macros, lookups or connector assumptions, so query-only copies would create misleading comparisons.
- The Chronicle repository contains examples/community rules, not the commercial Google SecOps Curated Detections corpus. Do not imply that the public mirror includes the latter. [Google SecOps repository distinction](https://github.com/chronicle/detection-rules#google-security-operations-detection-rules)
- Upstream repositories can contain deprecated, disabled, test, hunting, building-block or otherwise non-alerting content. Preserve those states and compare like with like.
