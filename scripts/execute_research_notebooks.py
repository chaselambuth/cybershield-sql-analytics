"""Clean-execute copies; preserve user notebooks and historical research artifacts."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import uuid

import nbformat
from nbclient import NotebookClient
from nbconvert import HTMLExporter
from cybershield.db import ROOT, file_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', nargs='?', default='')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=int, default=1200)
    args = parser.parse_args()
    paths = sorted(p for p in (ROOT/'notebooks').glob('*.ipynb') if p.name.startswith(args.prefix))
    if not paths:
        parser.error('No matching source notebooks')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = (args.output or ROOT/'reports/notebook_revalidation'/f'{stamp}_{uuid.uuid4().hex[:8]}').resolve()
    for protected in ['notebooks','reports/prototype','reports/research','data','power_bi']:
        if output.is_relative_to(ROOT/protected):
            parser.error('Output must be outside protected notebooks, evidence, sources and app bundles')
    output.mkdir(parents=True, exist_ok=False)
    research = output/'research'
    for folder in ['snapshot', 'sql_audit', 'sources']:
        shutil.copytree(ROOT/'reports/research'/folder, research/folder)
    for folder in ['notebooks', 'html', 'runtime', 'ipython']:
        (output/folder).mkdir()
    os.environ.update(JUPYTER_PATH=str(ROOT/'.jupyter'), JUPYTER_RUNTIME_DIR=str(output/'runtime'),
                      IPYTHONDIR=str(output/'ipython'))
    for name in ['OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'NUMEXPR_NUM_THREADS']:
        os.environ[name] = '1'
    records = []
    failure = None
    for path in paths:
        print('Clean-executing copy:', path.name, flush=True)
        notebook = nbformat.read(path, as_version=4)
        source_hash = file_hash(path)
        for cell in notebook.cells:
            if cell.cell_type == 'code':
                cell.outputs = []
                cell.execution_count = None
        bootstrap = nbformat.v4.new_code_cell(
            'from pathlib import Path\n'
            'import cybershield.research as _research\n'
            'import cybershield.source_audit as _audit\n'
            'import cybershield.robustness as _robustness\n'
            f'_research.RESEARCH = Path({str(research)!r})\n'
            '_audit.RESEARCH = _research.RESEARCH\n'
            '_robustness.RESEARCH = _research.RESEARCH\n'
            'print("Isolated revalidation output:", _research.RESEARCH)')
        notebook.cells.insert(1, bootstrap)
        notebook.metadata['cybershield_revalidation'] = {
            'source_path': path.relative_to(ROOT).as_posix(), 'source_sha256': source_hash,
            'harness': 'one bootstrap cell redirects outputs; original code cells unchanged',
            'run_directory': str(output), 'clean_kernel': True}
        status = 'passed'
        try:
            NotebookClient(notebook, timeout=args.timeout, startup_timeout=60, kernel_name='cybershield',
                resources={'metadata': {'path': str(ROOT)}}, allow_errors=False,
                on_cell_start=lambda cell, cell_index, **_: print(f'  Cell {cell_index+1}', flush=True)
                if cell.cell_type == 'code' else None).execute()
        except Exception as exc:
            status = 'failed'
            failure = type(exc).__name__
            print(f'Failed: {failure}; partial executed copy retained.', flush=True)
        nbformat.write(notebook, output/'notebooks'/path.name)
        html, _ = HTMLExporter().from_notebook_node(notebook)
        (output/'html'/f'{path.stem}.html').write_text(html, encoding='utf-8')
        if file_hash(path) != source_hash:
            raise RuntimeError('Original notebook changed during execution')
        records.append({'source': path.relative_to(ROOT).as_posix(), 'source_sha256': source_hash,
                        'status': status, 'error_type': failure})
        if failure:
            break
    artifacts = [p for base in ['research', 'notebooks', 'html'] for p in (output/base).rglob('*')
                 if p.is_file() and '.ipynb_checkpoints' not in p.parts]
    manifest = {'kind': 'cybershield_notebook_revalidation_v1', 'status': 'failed' if failure else 'passed',
                'created_utc': datetime.now(timezone.utc).isoformat(), 'notebooks': records,
                'harness_sha256': file_hash(Path(__file__)),
                'files': {p.relative_to(output).as_posix(): file_hash(p) for p in sorted(artifacts)}}
    (output/'execution_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('Revalidation bundle:', output, flush=True)
    if failure:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
