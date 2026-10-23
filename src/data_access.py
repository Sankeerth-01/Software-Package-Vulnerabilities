"""Validated data access."""
import hashlib
import json
from pathlib import Path

SOURCE_COLUMNS = ['package_name','package_manager','version_name','vuln_id','vuln_impact','vuln_description']

def portable_path(path, repository_root):

    path = Path(path).resolve()
    root = Path(repository_root).resolve()
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()

def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"

def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def file_manifest(path):
    path=Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f'Input not found: {path}. Set input_csv in config/phase2.yaml to the extracted Zenodo CSV.')
    return {'name':path.name,'bytes':path.stat().st_size,'sha256':checksum(path)}

def load_processed(path, connection=None):
    """Return a lazy DuckDB relation without a full-data pandas load."""
    import duckdb
    connection=connection or duckdb.connect()
    return connection.read_parquet(str(Path(path)))

def write_json(path,value):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,default=str)+'\n',encoding='utf-8')
