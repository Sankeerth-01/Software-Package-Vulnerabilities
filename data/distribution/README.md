# Exact processed-data parts

This directory delivers the full analysis-ready Parquet as unchanged ordered byte parts, each no larger than 40,000,000 bytes. `manifest.json` specifies the part order, individual byte counts and SHA256 values, full processed-data checksum, schema checksum and the included representative sample checksum.

Run these commands from the repository root:

```powershell
python tools/data_artifacts.py verify
python tools/data_artifacts.py restore
```

Restore reassembles `data/processed/associations.parquet` atomically and rejects missing or modified files before replacing the target. These are ordinary repository files, so no shared-storage login or separate download URL is needed. Do not concatenate parts manually without checking the manifest. The assembled file and the working DuckDB database remain excluded from Git.
