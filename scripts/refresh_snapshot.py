"""Copy curated derived results and regenerate the README from the evidence ledger."""
from pathlib import Path
import csv
import hashlib
import json
import shutil
from decimal import Decimal

ROOT=Path(__file__).resolve().parents[1]
metadata=json.loads((ROOT/'reports/latest_real.json').read_text(encoding='utf-8'))
source=Path(metadata['output_directory']).resolve()
if metadata.get('synthetic') or metadata['status']!='development_only' or not source.is_relative_to(ROOT/'reports/runs'):
    raise ValueError('Expected a completed, real-data development run inside this project')
target=ROOT/'reports/prototype'; target.mkdir(parents=True,exist_ok=True)
names=['data_quality.json','metrics.csv','claim_evidence.csv','findings.md','triage_queue.csv',
       'triage_evidence.csv','development_protocol.json','query_plans.json','config.yaml']
for name in names:
    shutil.copyfile(source/name,target/name)
for folder in ['analytics','figures']:
    (target/folder).mkdir(exist_ok=True)
    for path in (source/folder).iterdir():
        if path.is_file():shutil.copyfile(path,target/folder/path.name)
portable={k:v for k,v in metadata.items() if k!='output_directory'}
(target/'summary.json').write_text(json.dumps(portable,indent=2),encoding='utf-8')
with (target/'claim_evidence.csv').open(newline='',encoding='utf-8') as stream:
    claims={r['claim']:r for r in csv.DictReader(stream)}
accepted=claims['accepted_flows']; rejected=claims['quarantined_flows']
text=[f"Loaded **{int(Decimal(accepted['value'])):,} accepted flows** from **{int(Decimal(accepted['denominator'])):,} input rows**; quarantined **{int(Decimal(rejected['value'])):,}**.",
      '', '| Method | Caught / attack windows | False alerts / benign windows |', '|---|---:|---:|']
for method,label in [('sql_combined','Combined SQL rules'),('logistic_regression','Logistic regression'),('flow_count_baseline','Flow-count baseline')]:
    recall=claims[f'{method}_development_recall']; false=claims[f'{method}_development_false_positives']
    text.append(f"| {label} | {recall['numerator']} / {recall['denominator']} | {false['numerator']} / {false['denominator']} |")
text.extend(['',f"Run `{metadata['experiment_id']}`. These are sparse, correlated development windows; no independent-attack inference is supported."])
readme=ROOT/'README.md'; original=readme.read_text(encoding='utf-8')
start='<!-- RESULTS:START -->';end='<!-- RESULTS:END -->'
prefix,remainder=original.split(start,1);_,suffix=remainder.split(end,1)
readme.write_text(prefix+start+'\n'+'\n'.join(text)+'\n'+end+suffix,encoding='utf-8')
files={str(p.relative_to(target)):hashlib.sha256(p.read_bytes()).hexdigest()
       for p in sorted(target.rglob('*')) if p.is_file() and p.name!='output_manifest.json'}
(target/'output_manifest.json').write_text(json.dumps(files,indent=2),encoding='utf-8')
print(f'Updated {len(files)} curated report files and generated the README results table.')

