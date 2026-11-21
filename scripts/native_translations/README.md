# Native secondary translations

These scripts regenerate hand-specified secondary translations (SPL, KQL, SQL, Elastic EQL, Sigma) for rules whose canonical YARA-L logic is expressed as a correlation spec instead of generator candidate retrieval (`scripts/translate-yaral.ps1`).

| File | Rules |
| --- | --- |
| `translate_lib.py` | Shared renderer for single-event aggregations and two-event ordered sequences. It supports per-event join-key aliases and regex-derived join values. |
| `specs_csb.py` | 17 Cobalt Strike `*_compensating_signal` rules |
| `specs_ri.py` | 4 Rubeus and 3 Impacket rules added 2026-08-16 |
| `bloodhound_compensating.py` | 5 BloodHound compensating rules (hand-authored per backend) |
| `specs_ligolo.py` | 4 single-event Ligolo-ng rules (the 3 multi-event correlations use the generator) |

Usage, from any directory (the scripts do not execute detection content):

```
python -I scripts/native_translations/specs_csb.py
python -I scripts/native_translations/specs_ri.py
python -I scripts/native_translations/bloodhound_compensating.py
python -I scripts/native_translations/specs_ligolo.py
```

When a canonical rule in these sets changes:

1. Update its spec so the spec still mirrors the revised YARA-L events, keys, window, ordering and thresholds.
2. Rerun the script.
3. Update the tool's `reviews/<tool>/translation-review.md` exceptions.

Output is deterministic; rerunning without spec changes produces identical files. Fidelity rules:

- KQL and SQL use exact time-bounded joins.
- SPL sequences are `partial`: the `stats` correlation compares the earliest first-leg time with the latest second-leg time per key, which is weaker than per-pair ordering.
- EQL and Sigma are `partial` wherever distinct counts, field-to-field comparisons or regex-derived join values cannot be expressed.
- Column names follow one normalized vocabulary declared in each file's `field_mapping`; tenant mapping is still required.
