# Original CSV and dataset attribution

The complete standalone delivery includes data.csv:820,011,561bytes,911,279records, SHA256 fd3aa9b14c366b9a3759a0e3c99741e0f665f10cc01abee25920a9ae5ed24445. The portable configuration uses data/raw/data.csv. No original-drive path is required.

Source: [DiB-25 Zenodo record15432733 version3](https://zenodo.org/records/15432733), DOI [10.5281/zenodo.15432733](https://doi.org/10.5281/zenodo.15432733). The dataset's supplied [readme](../source/DiB-25_readme.txt) and [graph queries](../source/querys.cypher) are retained as provenance/supporting source material; graph dumps are not needed for this CSV workflow.

To reacquire if the raw file is intentionally omitted from a repository copy, download [DiB-25.zip](https://zenodo.org/records/15432733/files/DiB-25.zip?download=1), verify published archive MD5 bd8f2008f0b201225840dc4dea792043, and extract data/data.csv to this directory. The archive was not newly downloaded in final verification; the exact existing extracted CSV was hashed and included. A source ZIP MD5 is not a claim that the original ZIP was independently reverified here.

Header: package_name,package_manager,version_name,vuln_id,vuln_impact,vuln_description.

Run `python -m src.pipeline --config config/phase2.yaml` from the project root. The source hash/schema are checked before processing. Raw source and full assembled Parquet are intentionally excluded by the unchanged .gitignore for later manual Git integration; this standalone delivery retains them. Processed data can alternatively be restored from the delivered parts using `python tools/data_artifacts.py restore` without an external host.
