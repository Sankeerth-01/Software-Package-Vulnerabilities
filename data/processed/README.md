# Processed data delivery

The repository includes exact processed Parquet bytes as ordered parts in `data/distribution/` and the complete 250,000-record auxiliary sample in `data/samples/`. Each part is at most 40,000,000 bytes. No external hosting, database restoration or raw-data download is needed to load these artifacts.

From the repository root, using Python 3.12 or another supported Python 3 version:

```powershell
python tools/data_artifacts.py verify
python tools/data_artifacts.py restore
```

The standard-library-only tool checks every part, the complete reconstructed SHA256, the sample SHA256 and the schema checksum against `data/distribution/manifest.json`. Restore streams the parts into a temporary file and replaces `data/processed/associations.parquet` atomically only after verification succeeds; a corrupted part leaves an existing target intact. An optional `--output PATH` restores to another directory.

After installing `requirements.txt`, load the full processed population lazily:

```python
from src.data_access import load_processed
associations = load_processed("data/processed/associations.parquet")
print(associations.aggregate("count(*) AS records").fetchall())
```

The expected population is 884,137 normalized association payloads, 17,583 ecosystem-qualified packages and 279,284 package versions. `schema.json` records the typed columns, compound identifier hashes, source CSV SHA256, severity status/bands and retained source multiplicity. Distinct full payloads are preserved and flagged if one association key has conflicting metadata. Recorded zeros remain separate from missing/invalid scores; zero does not establish safety.

The assembled Parquet and working DuckDB database are excluded from Git. Regenerate them from the original CSV with the documented pipeline command. `quarantine.parquet` has zero records in the verified source population and can be regenerated with the pipeline. Primary EDA/analytics use the full processed population, not the auxiliary sample.

After intentionally regenerating final outputs, maintainers refresh delivery checksums and parts with `python tools/data_artifacts.py build --overwrite`. Check the final data against the source/results before any later manual integration of the refreshed manifest and parts. Regeneration can change physical Parquet byte order while preserving all logical results; the distribution manifest always records the exact delivered bytes.

## Current delivered bytes

Byte count: 105,974,077. SHA256: `b3cb139ea834031044e19da50627f93981376de3b38681ecbd1e6ba345252293`. The distribution manifest identifies this exact encoding; regeneration can preserve logical records while changing encoded bytes.
