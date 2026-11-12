"""Verify the published notebooks or an isolated execution bundle."""
import argparse
import json
from pathlib import Path

import nbformat

from cybershield.db import ROOT, file_hash


def verify(bundle=None):
    folder=Path(bundle).resolve() if bundle else ROOT
    manifest_path=folder/'execution_manifest.json' if bundle else ROOT/'reports/research/notebook_execution.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    errors=[]
    if manifest.get('kind') not in {'cybershield_notebooks_v1','cybershield_notebook_revalidation_v1'}:
        errors.append('Unsupported notebook manifest')
    if not manifest['notebooks'] or (bundle and manifest.get('status')!='passed'):
        errors.append('Manifest does not describe a completed notebook execution')
    for relative,expected in manifest['files'].items():
        path=(folder/relative).resolve()
        if not path.is_relative_to(folder) or not path.is_file() or file_hash(path)!=expected:
            errors.append(f'Missing or changed artifact: {relative}')
    for record in manifest['notebooks']:
        source=(ROOT/record['source']).resolve()
        path=folder/'notebooks'/source.name if bundle else source
        if not source.is_relative_to(ROOT) or not path.is_file():
            errors.append(f'Invalid notebook path: {record["source"]}')
            continue
        notebook=nbformat.read(path,as_version=4)
        nbformat.validate(notebook)
        code=[cell for cell in notebook.cells if cell.cell_type=='code']
        if not code or any(cell.execution_count is None for cell in code):
            errors.append(f'Incomplete execution: {path.name}')
        if any(output.output_type=='error' for cell in code for output in cell.outputs):
            errors.append(f'Saved execution error: {path.name}')
        relative=path.relative_to(folder).as_posix()
        if relative not in manifest['files']:
            errors.append(f'Notebook is absent from the hash manifest: {relative}')
        if bundle:
            if file_hash(source)!=record['source_sha256']:
                errors.append(f'Source changed since execution: {source.name}')
            original=nbformat.read(source,as_version=4)
            if [cell.source for cell in code[1:]]!=[cell.source for cell in original.cells if cell.cell_type=='code']:
                errors.append(f'Executed code differs from source: {source.name}')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Verified {len(manifest["files"])} hashes and {len(manifest["notebooks"])} completed, error-free notebooks.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,help='Verify an optional local execution bundle instead of the published notebooks')
    verify(parser.parse_args().bundle)


if __name__=='__main__':
    main()
