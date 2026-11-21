# Cobalt Strike Beacon translation review

- Canonical rules: 38 YARA-L rules under `detections/cobalt-strike-beacon/yaral/`.
- Secondary drafts reviewed: 190 files; 38 each in SPL, KQL, SQL, Elastic EQL, and Sigma.
- Parity: complete by basename and source linkage.
- Fidelity: the 21 original rules and 5 regenerated base rules are `partial` generator drafts; the 17 compensating signals are `high` or `partial` per the 2026-11-21 exceptions below. None claim equivalence or validation.
- Shared backend limitations: `schemas/splunk-cim.yml`, `schemas/sentinel-asim.yml`, `schemas/normalized-sql.yml`, `schemas/elastic-ecs.yml`, and `schemas/sigma.yml`.
- Tool-specific exceptions: none beyond the per-rule `fidelity` and `assumptions_and_gaps` metadata.
- Required follow-up: map the declared schema for each backend, implement the canonical logic natively, compile, and test positive, negative, reordered, missing-event, and boundary-window fixtures before use.

## 2026-11-21 exceptions — 17 compensating signals and 5 base-rule regenerations

- **17 `*_compensating_signal` rules:** native translations rendered from a per-rule correlation spec mirroring the revised YARA-L. They use one normalized column vocabulary, declared in each file's `field_mapping`; EQL uses ECS equivalents.
  - **KQL and SQL** (`high`): exact time-bounded per-pair joins, with first-event-before-second ordering and native distinct-count thresholds.
  - **SPL:** `high` for single-event aggregations. `partial` for two-event sequences, because the `stats` correlation compares the earliest first-leg time with the latest second-leg time per key, which is weaker than per-pair ordering.
  - **EQL:** `high` where a native `sequence ... with maxspan` with per-event join keys expresses the rule. `partial` where a distinct-count threshold or a regex-derived join value (remote service image name) must be applied downstream.
  - **Sigma:** `temporal_ordered` or `value_count`/`event_count` correlations with `aliases` for differently named join keys. `partial` where counts or derived join values are not expressible.
- **5 base rules** (`directory_discovery`, `dns_process_context`, `file_cleanup_or_timestomp`, `named_pipe_peer_activity`, `sensitive_file_activity`): regenerated with `scripts/translate-yaral.ps1` after the additive event-type fix (DR-13). They remain generator candidate-retrieval drafts (`partial`).
- `high` means the canonical logic is expressed natively in the target. It does not mean equivalent or validated: column names are tenant assumptions, and every file stays `experimental_needs_backend_mapping_and_validation`.

