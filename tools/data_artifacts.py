"""Build, verify and restore the exact processed dataset using repository files.

Only Python's standard library is needed. Parquet bytes are split unchanged into
parts no larger than 40,000,000 bytes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_PART_BYTES = 40_000_000
BLOCK_BYTES = 1024 * 1024
MANIFEST = 'data/distribution/manifest.json'
PROCESSED = 'data/processed/associations.parquet'
SAMPLE = 'data/samples/exploration_sample.parquet'
SCHEMA = 'data/processed/schema.json'


def _file(root: Path, relative: str) -> Path:
    """Reject traversal, platform-specific absolute paths and escaping symlinks."""
    if not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative:
        raise ValueError(f'Unsafe artifact path: {relative!r}')
    name = PurePosixPath(relative)
    if name.is_absolute() or any(part in {'', '.', '..'} for part in relative.split('/')):
        raise ValueError(f'Unsafe artifact path: {relative!r}')
    path = (root/name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f'Artifact escapes repository: {relative!r}')
    return path


def _record(root: Path, relative: str) -> dict:
    path = _file(root, relative)
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as source:
        while block := source.read(BLOCK_BYTES):
            digest.update(block)
            size += len(block)
    return {'path': relative, 'bytes': size, 'sha256': digest.hexdigest()}


def _validate_record(root: Path, value: dict, *, part=False) -> None:
    if not isinstance(value, dict):
        raise ValueError('Malformed artifact record')
    _file(root, value.get('path'))
    if type(value.get('bytes')) is not int or value['bytes'] < 0:
        raise ValueError('Invalid artifact byte count')
    if not re.fullmatch('[0-9a-f]{64}', value.get('sha256', '')):
        raise ValueError('Invalid SHA256 in manifest')
    if part and (not value['path'].startswith('data/distribution/')
                 or not 0 < value['bytes'] <= MAX_PART_BYTES):
        raise ValueError('Part must be a nonempty repository distribution file <=40,000,000 bytes')


def load_manifest(root=ROOT) -> dict:
    root = Path(root).resolve()
    manifest = json.loads(_file(root, MANIFEST).read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 1 or manifest.get('encoding') != 'ordered_raw_byte_parts':
        raise ValueError('Unsupported data distribution manifest')
    processed = manifest.get('processed', {})
    _validate_record(root, processed)
    if processed['path'] != PROCESSED:
        raise ValueError('Unexpected processed-data target')
    parts = processed.get('parts')
    if not isinstance(parts, list) or not parts:
        raise ValueError('Processed-data parts are missing')
    for part in parts:
        _validate_record(root, part, part=True)
    if len({part['path'].casefold() for part in parts}) != len(parts):
        raise ValueError('Duplicate data part in manifest')
    if sum(part['bytes'] for part in parts) != processed['bytes']:
        raise ValueError('Part sizes do not reconcile to processed-data size')
    for key, expected in [('sample', SAMPLE), ('schema', SCHEMA)]:
        _validate_record(root, manifest.get(key))
        if manifest[key]['path'] != expected:
            raise ValueError(f'Unexpected {key} path')
    return manifest


def _verify_file(root: Path, expected: dict) -> None:
    actual = _record(root, expected['path'])
    if any(actual[key] != expected[key] for key in ['bytes', 'sha256']):
        raise ValueError(f"Size or SHA256 mismatch: {expected['path']}")


def _stream_parts(root: Path, processed: dict, sink=None) -> None:
    full_digest, full_size = hashlib.sha256(), 0
    for part in processed['parts']:
        digest, size = hashlib.sha256(), 0
        with _file(root, part['path']).open('rb') as source:
            while block := source.read(BLOCK_BYTES):
                digest.update(block)
                full_digest.update(block)
                size += len(block)
                full_size += len(block)
                if sink is not None:
                    sink.write(block)
        if size != part['bytes'] or digest.hexdigest() != part['sha256']:
            raise ValueError(f"Size or SHA256 mismatch: {part['path']}")
    if full_size != processed['bytes'] or full_digest.hexdigest() != processed['sha256']:
        raise ValueError('Reassembled processed-data size or SHA256 mismatch')


def verify(root=ROOT) -> dict:
    root = Path(root).resolve()
    manifest = load_manifest(root)
    _stream_parts(root, manifest['processed'])
    for key in ['sample', 'schema']:
        _verify_file(root, manifest[key])
    return {'status': 'passed', 'manifest': str(_file(root, MANIFEST)),
            'verified_parts': len(manifest['processed']['parts']),
            'processed_bytes': manifest['processed']['bytes'],
            'processed_sha256': manifest['processed']['sha256'],
            'sample_bytes': manifest['sample']['bytes'],
            'sample_sha256': manifest['sample']['sha256']}


def restore(root=ROOT, output=None) -> dict:
    """Reassemble, hash-check and atomically replace the target only on success."""
    root = Path(root).resolve()
    manifest = load_manifest(root)
    target = Path(output).resolve() if output is not None else _file(root, PROCESSED)
    protected = [_file(root, MANIFEST), _file(root, SCHEMA), _file(root, SAMPLE)]
    protected += [_file(root, part['path']) for part in manifest['processed']['parts']]
    if target in protected:
        raise ValueError('Restore output cannot replace a distribution input')
    for key in ['sample', 'schema']:
        _verify_file(root, manifest[key])
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staging_name = tempfile.mkstemp(prefix='.'+target.name+'.', suffix='.partial',
                                               dir=target.parent)
    staging = Path(staging_name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            _stream_parts(root, manifest['processed'], stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, target)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    return {'status': 'passed', 'restored_path': str(target),
            'bytes': manifest['processed']['bytes'], 'sha256': manifest['processed']['sha256'],
            'atomic_replace': True}


def build(root=ROOT, part_bytes=MAX_PART_BYTES, overwrite=False) -> dict:
    """Package existing final outputs; does not execute or change the pipeline."""
    root = Path(root).resolve()
    if type(part_bytes) is not int or not 0 < part_bytes <= MAX_PART_BYTES:
        raise ValueError('part_bytes must be between1 and40,000,000')
    destination = _file(root, 'data/distribution')
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = _file(root, MANIFEST)
    if manifest_path.exists() and not overwrite:
        raise FileExistsError('Distribution exists; use build --overwrite after final output changes')
    sample = _record(root, SAMPLE)
    schema = _record(root, SCHEMA)
    if sample['bytes'] > MAX_PART_BYTES:
        raise ValueError('The committed sample exceeds40,000,000 bytes; choose a smaller delivery artifact')
    source = _file(root, PROCESSED)
    before = (source.stat().st_size, source.stat().st_mtime_ns)
    full_digest, full_size, parts = hashlib.sha256(), 0, []
    with tempfile.TemporaryDirectory(prefix='.distribution-build-', dir=destination.parent) as work:
        work = Path(work)
        with source.open('rb') as stream:
            while True:
                digest, size = hashlib.sha256(), 0
                staging = work/f'part-{len(parts)+1:03d}'
                with staging.open('wb') as output:
                    while size < part_bytes:
                        block = stream.read(min(BLOCK_BYTES, part_bytes-size))
                        if not block:
                            break
                        output.write(block)
                        digest.update(block)
                        full_digest.update(block)
                        size += len(block)
                        full_size += len(block)
                if not size:
                    staging.unlink()
                    break
                parts.append({'staging': staging, 'bytes': size, 'sha256': digest.hexdigest()})
        if (source.stat().st_size, source.stat().st_mtime_ns) != before:
            raise RuntimeError('Processed source changed while building distribution')
        if not parts:
            raise ValueError('Processed data is empty')
        full_sha = full_digest.hexdigest()
        analysis_path = root/'results/analytics.json'
        analysis = json.loads(analysis_path.read_text(encoding='utf-8')) if analysis_path.exists() else {}
        if analysis.get('processed_sha256') not in {None, full_sha}:
            raise ValueError('Processed data no longer matches analytics provenance; rerun/verify final outputs')
        records = []
        for number, part in enumerate(parts, 1):
            relative = f'data/distribution/associations-{full_sha[:16]}.part-{number:03d}'
            os.replace(part['staging'], _file(root, relative))
            records.append({'path': relative, 'bytes': part['bytes'], 'sha256': part['sha256']})
        schema_content = json.loads(_file(root, SCHEMA).read_text(encoding='utf-8'))
        sampling_path = root/'results/sampling.json'
        sampling = json.loads(sampling_path.read_text(encoding='utf-8')) if sampling_path.exists() else {}
        manifest = {'schema_version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                    'encoding': 'ordered_raw_byte_parts',
                    'source_csv_sha256': schema_content.get('source_sha256'),
                    'processed': {'path': PROCESSED, 'bytes': full_size, 'sha256': full_sha,
                                  'rows': analysis.get('totals', {}).get('associations'), 'parts': records},
                    'sample': {**sample, 'rows': sampling.get('sample_rows'),
                               'seed': sampling.get('seed'), 'quotas': sampling.get('quotas'),
                               'selection_fingerprint': sampling.get('fingerprint'),
                               'weighting': 'Balanced strata; use inclusion_probability and sampling_weight; not used for primary results.'},
                    'schema': schema,
                    'delivery': 'All parts, schema and sample are ordinary repository files; no external host required.'}
        staging_manifest = work/'manifest.json'
        staging_manifest.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        os.replace(staging_manifest, manifest_path)
    result = verify(root)
    # Publish and verify the new manifest before removing superseded encodings.
    # Only this builder's exact content-addressed part names are eligible;
    # unrelated files and symbolic links are never cleanup targets.
    current = {record['path'] for record in records}
    removed = []
    for candidate in sorted(destination.iterdir()):
        if (not re.fullmatch(r'associations-[0-9a-f]{16}\.part-[0-9]{3,}', candidate.name)
                or candidate.is_symlink() or not candidate.is_file()):
            continue
        relative = candidate.relative_to(root).as_posix()
        if relative in current:
            continue
        resolved = candidate.resolve()
        if resolved.parent != destination.resolve() or not resolved.is_relative_to(root):
            raise ValueError(f'Refusing unsafe superseded-part cleanup: {candidate}')
        candidate.unlink()
        removed.append(relative)
    result['removed_superseded_parts'] = removed
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ['build', 'verify', 'restore']:
        command = commands.add_parser(name)
        command.add_argument('--root', type=Path, default=ROOT)
        if name == 'build':
            command.add_argument('--part-bytes', type=int, default=MAX_PART_BYTES)
            command.add_argument('--overwrite', action='store_true')
        elif name == 'restore':
            command.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        result = build(args.root, args.part_bytes, args.overwrite)
    elif args.command == 'restore':
        result = restore(args.root, args.output)
    else:
        result = verify(args.root)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
