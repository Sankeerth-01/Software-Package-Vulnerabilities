# Software package vulnerabilities

EAS 587 Phase 2, Fall 2026. Team: Manik Kashikar, Praveen Kumar, Sankeerth Reddy.

Our complete Python/DuckDB project profiles, cleans and analyzes the data across npm, PyPI, RubyGems and Cargo. The raw CSV has 911,279 records; conservative payload reconciliation retains 884,137 associations, 17,583 ecosystem-qualified packages, 279,284 package versions, 24,586 raw advisory IDs and 26,640 ecosystem-advisory pairs. Primary findings use the complete processed population. The 250,000-record weighted sample is auxiliary.

The code, nine analytical figures, interpreted report, executed notebook, editable slides, PDF, are done by our team. Technical and content review was performed during preparation.

## Install dependencies

Before installing anything inside the extracted folder or regenerating outputs, verify the exact shipped bytes using only standard-library Python:

```powershell
python -B tools/verify_final.py --inventory-only
```

After intentionally rerunning the pipeline, use `tools/verify_final.py --skip-inventory`: it checks working data/content while allowing normal local environment/cache/spill directories and excluding their package documentation from project-link checks. By default, verification strictly checks the delivered-file hashes and requires a clean delivery structure.

Use Python 3.12. Run the following from this project root. On macOS/Linux substitute `.venv/bin/python` for `.\.venv\Scripts\python.exe`.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-render.txt
.\.venv\Scripts\python.exe -m pip check
```

Both requirements files are pinned. Core processing, notebook execution and testing use `requirements.txt`; PDF preview/checking additionally uses `requirements-render.txt`. No database server, Docker or distributed cluster is required. No environment is bundled in this delivery; creating one locally later is optional setup.

## Run the complete pipeline

This standalone folder includes the checksum-verified original CSV at `data/raw/data.csv`, the assembled full Parquet, the three exact processed-data parts and the actual sample. The portable configuration is unchanged and uses project-relative paths. The pipeline resolves configured data/output paths against this project root and does not depend on the original E: or C: locations.

```powershell
.\.venv\Scripts\python.exe -m src.pipeline --config config/phase2.yaml
```

Our pipeline hashes and strictly validates the raw input, profiles every field, cleans/reconciles payloads, writes schema/Parquet, generates a seeded exploration sample and computes all nine figures/results. It overwrites the named generated outputs without changing the authored report or notebook narrative. Default resources: two DuckDB threads, 768 MB engine memory, disk spill; allow several GB free disk. Total process RSS can exceed the engine budget. The verification report lists the earlier and final resource measurements separately.

For a smaller repository transfer without the large raw/full files, the exact population can be restored from the included parts alone:

```powershell
.\.venv\Scripts\python.exe tools/data_artifacts.py verify
.\.venv\Scripts\python.exe tools/data_artifacts.py restore
```

These two commands use only the standard library. Restore verifies all part hashes and the complete reconstructed hash before atomically replacing `data/processed/associations.parquet`. It does not need the raw CSV or external storage. The distributed sample and schema are also verified. After intentionally rebuilding the pipeline, refresh the precise encoded byte parts:

```powershell
.\.venv\Scripts\python.exe tools/data_artifacts.py build --overwrite
```

Physical Parquet bytes may vary after re-encoding; logical counts and deterministic sample membership must agree. The [distribution manifest](data/distribution/manifest.json) identifies the exact delivered bytes.

## Execute the notebook and checks

```powershell
.\.venv\Scripts\python.exe notebooks/execute.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe tools/validate_handoff.py
.\.venv\Scripts\python.exe tools/verify_final.py --skip-inventory
```

The notebook executor starts a new kernel using the invoking Python, replaces all code outputs and execution counts, records its exact notebook hash, and cleans its temporary Jupyter workspace outside the project. The notebook loads the configured processed population instead of doing the cleaning in its cells. `tools/verify_final.py` checks delivered integrity, executable syntax/imports, typed data, count reconciliation, relative links, figures, report, notebook and slides. An intentional rerun changes output hashes; because the checksum inventory records the shipped revision, regenerated outputs may no longer match it.

## Dataset and analytical scope

Source: [DiB-25 Zenodo record 15432733 version 3](https://zenodo.org/records/15432733), DOI `10.5281/zenodo.15432733`. Source CSV: 820,011,561 bytes; SHA256 `fd3aa9b14c366b9a3759a0e3c99741e0f665f10cc01abee25920a9ae5ed24445`. Original archive/source documentation and reacquisition instructions are in [data/raw/README.md](data/raw/README.md). The published corpus and the analyzed CSV have different units and counts.

The export lacks validated release timestamps, a complete safe-release denominator and resolved dependency edges. It supports association/entity descriptions, not all-package prevalence, latest-release risk, chronology, causal effects or direct/transitive fractions. Recorded score zero is separate from missingness and does not prove safety. Advisory aliases remain unresolved.

## Structure and manual repository integration

`src/` builds data; `notebooks/` explores it; `figures/` and `results/` hold evidence; `data/` contains raw, processed, sample and portable parts; `config/` controls paths; `docs/` contains requirements, decisions and supporting materials; `presentation/` contains status updates; and `tools/` support verification; `verification/` contains final executed evidence, change log, inventory and checksums.


