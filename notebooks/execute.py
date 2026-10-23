"""Execute the analysis notebook with the invoking environment's Python kernel."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import tempfile
import time

import nbformat
from nbclient import NotebookClient
import yaml


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=os.environ.get('PHASE2_CONFIG', 'config/phase2.yaml'))
    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    config_path = config_path.resolve()
    config = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    results_dir = root / Path(config.get('results_dir', 'results'))
    results_dir.mkdir(parents=True, exist_ok=True)

    os.environ['PHASE2_CONFIG'] = str(config_path)
    path = root / "notebooks/phase2_analysis.ipynb"
    nb = nbformat.read(path, as_version=4)
    start = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="phase2-jupyter-") as workspace:
        workspace = Path(workspace)
        kernel_root = workspace / "kernels/phase2"
        kernel_root.mkdir(parents=True)
        (kernel_root / "kernel.json").write_text(json.dumps({
            "argv": [sys.executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"],
            "display_name": "Phase 2 current environment", "language": "python"}), encoding="utf-8")
        previous = {name: os.environ.get(name) for name in ["JUPYTER_PATH", "JUPYTER_RUNTIME_DIR", "IPYTHONDIR"]}
        os.environ["JUPYTER_PATH"] = str(workspace) + os.pathsep + os.environ.get("JUPYTER_PATH", "")
        os.environ["JUPYTER_RUNTIME_DIR"] = str(workspace / "runtime")
        os.environ["IPYTHONDIR"] = str(workspace / "ipython")
        Path(os.environ["JUPYTER_RUNTIME_DIR"]).mkdir()
        try:
            NotebookClient(nb, timeout=1200, kernel_name="phase2", resources={"metadata": {"path": str(root)}}).execute()
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
    nbformat.write(nb, path)
    record = {"status": "passed", "python": sys.version, "executable": sys.executable,
              "config": str(config_path),
              "notebook_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "elapsed_seconds": time.perf_counter() - start,
              "code_cells": sum(c.cell_type == "code" for c in nb.cells),
              "error_outputs": sum(o.output_type == "error" for c in nb.cells if c.cell_type == "code" for o in c.outputs),
              "method": "New kernel process using the invoking environment; existing notebook execution counts and outputs replaced"}
    (results_dir / "notebook_execution.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
