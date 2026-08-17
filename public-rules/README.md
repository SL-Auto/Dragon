# Public detection-rule validation corpus

This tree is deliberately separate from `detections/`. Rules here are untrusted third-party comparison inputs; they are never canonical and are never automatically merged into internally generated logic.

- `catalog.json` allowlists upstream repositories, rule-bearing paths, formats, and license provenance.
- `snapshots/<source>/<commit>/` contains filtered, immutable, text-only upstream snapshots and a hash manifest.
- `state.json` records the freshest revision observed by the last successful refresh.
- `comparisons/<tool>/` records rule-by-rule, dimension-specific analysis after internal generation and adversarial review are complete.
- `.cache/` is ignored and exists only to fetch upstream Git objects.

Run `powershell -NoProfile -File scripts/sync-public-rules.ps1` daily. A new upstream revision creates a new snapshot rather than overwriting history. Review licensing before redistributing snapshots outside this repository.

Comparisons must conclude with concrete YARA-L 2.0 improvement code and an explicit `patch`, `compensating_rule`, `split`, `rewrite`, or `new_rule` classification. Proposed code is untrusted until independently reviewed. If accepted, it must be applied to canonical YARA-L and all downstream telemetry, translations, hashes, reviews, and comparisons in the same run; public logic is never copied automatically.
