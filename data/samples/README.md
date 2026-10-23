# Auxiliary exploration sample

`exploration_sample.parquet` is included directly in the repository. It contains 250,000 rows selected from all 884,137 cleaned records using stable SHA256 ranking within ecosystem and seed 5872026. Its exact delivered byte count and SHA256 are recorded in `data/distribution/manifest.json`; `python tools/data_artifacts.py verify` checks and prints the sample checksum.

| Ecosystem | Population rows | Sample quota |
|---|---:|---:|
| Cargo | 2,735 | 2,735 |
| npm | 375,126 | 94,978 |
| PyPI | 448,966 | 94,977 |
| RubyGems | 57,310 | 57,310 |

Cargo and RubyGems are censused. The larger npm and PyPI strata are selected across their full populations. The stable selection fingerprint is `d599bb51310b9da9d0d046380394c01189580c7d4f294d47f397b5a52501a9e3`; `results/sampling.json` records the exact selection contract.

After installing `requirements.txt`, inspect it without loading every column into pandas:

```python
from src.data_access import load_processed
sample = load_processed("data/samples/exploration_sample.parquet")
print(sample.aggregate("count(*) AS records, sum(sampling_weight) AS weighted_population").fetchall())
```

The allocation balances the larger strata and therefore is **not automatically representative of the population proportions**. Use the stored `inclusion_probability` and `sampling_weight` for association-population estimates, and respect clustering by package/advisory when designing uncertainty estimates. The weighted row total is 884,137 up to numerical rounding. The sample supports rapid secondary exploration; all reported primary counts, severity comparisons and package/advisory analyses use the complete cleaned population.

## Current delivered bytes

Byte count: 31,121,625. SHA256: `7a9407ab350bf284c240567323642a01436eb3664db0f09e2d42eb7517327504`. The distribution manifest identifies this exact encoding; regeneration can preserve logical records while changing encoded bytes.
