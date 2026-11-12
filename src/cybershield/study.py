"""Opt-in corrected-data study commands; never update prototype or app snapshots."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import uuid

import pandas as pd

from .corrected import CorrectedAdapter, audit_archive
from .db import ROOT, connect, file_hash, migrate
from .evaluate import FEATURES, build_features, frame
from .ingest import ingest
from .protocol import allocate, validate_protocol, write_support


def save_json(path, value):
    path.write_text(json.dumps(value,indent=2,default=str,allow_nan=False),encoding='utf-8')


def code_files():
    paths=[ROOT/'src/cybershield'/name for name in ['study.py','study_benchmark.py','protocol.py','corrected.py',
           'ingest.py','db.py','evaluate.py','research.py']]
    paths += list((ROOT/'sql/migrations').glob('*.sql'))
    paths += [ROOT/'sql/features/source_windows.sql',ROOT/'sql/features/window_labels.sql',ROOT/'sql/detection/scores.sql']
    return sorted(paths)


def safe_new_output(path):
    path=Path(path).resolve()
    for protected in ['reports/prototype','reports/research','notebooks','data','power_bi']:
        if path.is_relative_to(ROOT/protected):
            raise ValueError('Output is inside protected evidence/input/application paths')
    path.mkdir(parents=True,exist_ok=False)
    return path


def register(config_path, archive, output=None):
    config_path,archive=Path(config_path).resolve(),Path(archive).resolve()
    config=validate_protocol(json.loads(config_path.read_text(encoding='utf-8')))
    if not archive.is_file() or archive.suffix.lower()!='.zip':
        raise ValueError('Supply an existing owner-approved local ZIP archive')
    run_id=str(uuid.uuid4())
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output=safe_new_output(output or ROOT/'reports/studies'/f'corrected_{stamp}_{run_id[:8]}')
    (output/'protocol.json').write_bytes(config_path.read_bytes())
    files={p.relative_to(ROOT).as_posix():file_hash(p) for p in code_files()}
    for relative in files:
        target=output/'source_code'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((ROOT/relative).read_bytes())
    packages=['numpy','pandas','scikit-learn','psycopg','xgboost','lightgbm','catboost','threadpoolctl']
    versions={p:importlib.metadata.version(p) for p in packages}
    git=subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True)
    value={'kind':'cybershield_corrected_design_v1','run_id':run_id,
           'created_utc':datetime.now(timezone.utc).isoformat(),
           'protocol_sha256':file_hash(output/'protocol.json'), 'source_config':str(config_path),
           'archive_path':str(archive),'archive_sha256':file_hash(archive),'members':config['members'],
           'code_files':files,'versions':versions,'git_commit':git.stdout.strip() if git.returncode==0 else None,
           'git_note':'Exact code hashes bind this local design; no committed source history is claimed.',
           'purpose':'development/validation only; no final test; all prior access disclosed in protocol'}
    save_json(output/'registration.json',value)
    digest=file_hash(output/'registration.json')
    # This receipt is convenient storage, not an external seal. Evaluator requires the
    # expected hash supplied explicitly by its caller rather than trusting a recomputation.
    (output/'design_registration.sha256').write_text(digest+'\n',encoding='ascii')
    print(json.dumps({'directory':str(output),'run_id':run_id,'registration_sha256':digest}),flush=True)
    return output,digest


def verify_design(output, expected):
    output=Path(output).resolve()
    if not expected or file_hash(output/'registration.json')!=expected:
        raise ValueError('Design registration differs from separately supplied expected hash')
    registration=json.loads((output/'registration.json').read_text())
    if registration.get('kind')!='cybershield_corrected_design_v1':
        raise ValueError('Unsupported registration')
    if file_hash(output/'protocol.json')!=registration['protocol_sha256']:
        raise ValueError('Registered protocol changed')
    for relative,digest in registration['code_files'].items():
        path=(ROOT/relative).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or file_hash(path)!=digest:
            raise ValueError(f'Registered source changed: {relative}; create a new design registration')
        archived=(output/'source_code'/relative).resolve()
        if not archived.is_relative_to(output/'source_code') or not archived.is_file() or file_hash(archived)!=digest:
            raise ValueError(f'Registered source snapshot changed: {relative}')
    for name,version in registration['versions'].items():
        if importlib.metadata.version(name)!=version:
            raise ValueError(f'Registered dependency changed: {name}')
    config=validate_protocol(json.loads((output/'protocol.json').read_text()))
    return output,registration,config


def artifact_hashes(folder):
    return {p.relative_to(folder).as_posix():file_hash(p) for p in sorted(folder.rglob('*')) if p.is_file()}


def audit_support(bundle, protocol, output, revision_note=None):
    """Allocation/support audit only. No SQL features or model scores are fabricated."""
    bundle=Path(bundle).resolve();protocol=Path(protocol)
    config=validate_protocol(json.loads(protocol.read_text()))
    manifest=json.loads((bundle/'audit_manifest.json').read_text())
    if manifest['protocol_sha256']!=file_hash(protocol) and not revision_note:
        raise ValueError('Audit was not bound to this protocol')
    if [x['member'] for x in manifest['members']]!=config['members']:
        raise ValueError('Audit members differ from protocol')
    for relative,digest in manifest['files'].items():
        path=(bundle/relative).resolve()
        if not path.is_relative_to(bundle) or file_hash(path)!=digest:
            raise ValueError('Source audit file changed')
    data=pd.read_csv(bundle/'window_support.csv')
    data=data.rename(columns={'flows':'flow_count'})
    data['episode_labels']=data.families.map(json.loads)
    allocated=allocate(data,config)
    output=safe_new_output(output)
    gate=write_support(allocated,config,output)
    allocated['episode_groups']=allocated.episode_groups.map(json.dumps)
    allocated.to_csv(output/'audit_split_membership.csv',index=False)
    save_json(output/'audit_support_context.json',{'audit_manifest_sha256':file_hash(bundle/'audit_manifest.json'),
        'protocol_sha256':file_hash(protocol),'source_audit_protocol_sha256':manifest['protocol_sha256'],
        'protocol_revision_note':revision_note,
        'scope':'source-derived support only; SQL feature/target reconciliation and model evaluation require PostgreSQL',
        'gate':gate,'files':artifact_hashes(output)})
    print(json.dumps(gate),flush=True)
    return gate


def prepare(output, expected):
    output,registration,config=verify_design(output,expected)
    archive=Path(registration['archive_path'])
    if file_hash(archive)!=registration['archive_sha256']:
        raise ValueError('Registered source archive changed')
    if (output/'prepare_attempt.json').exists():
        raise ValueError('Preparation already attempted; preserve it and register a new run')
    schema='cs_study_'+registration['run_id'].replace('-','')[:16]
    attempt={'schema':schema,'started_utc':datetime.now(timezone.utc).isoformat(),'status':'running'}
    save_json(output/'prepare_attempt.json',attempt)
    try:
        # Check availability before heavy ingestion; no source/prototype schema is reused.
        with connect(schema) as conn:
            migrate(conn,schema)
            audits=[]
            for member in config['members']:
                audit=ingest(conn,archive,member,adapter=CorrectedAdapter(member,config['members']))
                audits.append(audit)
                print(f"Ingested {member}: {audit['accepted_rows']:,} accepted; {audit['rejected_rows']:,} rejected",flush=True)
            feature_config={'status':'development_only','window_minutes':5,'window_origin':config['window_origin'],
                            'timestamp_policy':config['timestamp_policy'],'study_registration':expected}
            feature_id=build_features(conn,[a['source_id'] for a in audits],feature_config,registration['protocol_sha256'])
            data=frame(conn,'''SELECT host(f.src_ip) src_ip,f.window_start,f.flow_count,f.unique_ports,
                f.unique_destinations,f.service_flows,f.packets,f.bytes,f.mean_duration_us,
                l.attack_flows,l.unknown_flows,l.categories AS attack_categories,
                bounds.min_flow_start,bounds.max_flow_end,bounds.episode_labels,bounds.source_members
                FROM window_features f JOIN window_label l USING(feature_run_id,src_ip,window_start)
                JOIN LATERAL (
                  SELECT min(raw.reported_start) min_flow_start,max(raw.reported_end) max_flow_end,
                    array_agg(DISTINCT lab.label) FILTER (WHERE lab.label!='BENIGN') episode_labels,
                    array_agg(DISTINCT src.filename) source_members
                  FROM flow raw JOIN flow_label lab USING(flow_id) JOIN source_file src USING(source_id)
                  WHERE raw.source_id=ANY(%s) AND raw.clock_usable AND raw.src_ip=f.src_ip
                    AND raw.reported_end>=f.window_start AND raw.reported_end<f.window_start+interval '5 minutes'
                ) bounds ON true WHERE f.feature_run_id=%s ORDER BY f.window_start,f.src_ip''',
                ([a['source_id'] for a in audits],feature_id))
            data['episode_labels']=data.episode_labels.map(lambda x:x if isinstance(x,list) else [])
            data=allocate(data,config)
            # Independently reconcile normalized flow and feature/target memberships.
            eligible=conn.execute('SELECT count(*) FROM flow WHERE clock_usable AND source_id=ANY(%s)',
                                  ([a['source_id'] for a in audits],)).fetchone()[0]
            if int(data.flow_count.sum())!=eligible:
                raise ValueError('Normalized temporal flows and SQL windows do not reconcile')
            if len(data)!=conn.execute('SELECT count(*) FROM window_label WHERE feature_run_id=%s',(feature_id,)).fetchone()[0]:
                raise ValueError('Feature and target window keys do not reconcile')
            prepared=output/'prepared';prepared.mkdir()
            save_json(prepared/'ingestion_audits.json',audits)
            gate=write_support(data,config,prepared)
            # Arrays are explicit JSON, never Python repr evaluated on input.
            for column in ['attack_categories','episode_labels','episode_groups','source_members']:
                data[column]=data[column].map(json.dumps)
            data.to_csv(prepared/'windows.csv',index=False,float_format='%.17g')
            membership=data[['src_ip','window_start','role','role_reason','known','is_attack','episode_groups']]
            membership.to_csv(prepared/'split_membership.csv',index=False)
            value={'kind':'cybershield_corrected_prepared_v1','run_id':registration['run_id'],
                   'design_sha256':expected,'schema':schema,'feature_run_id':str(feature_id),
                   'source_ids':[a['source_id'] for a in audits], 'eligible_flows':eligible,
                   'support_gate_passed':gate['passed'],'files':artifact_hashes(prepared)}
            save_json(output/'prepared.json',value)
            prepared_hash=file_hash(output/'prepared.json')
            (output/'prepared.sha256').write_text(prepared_hash+'\n',encoding='ascii')
            attempt.update(status='prepared',prepared_sha256=prepared_hash,feature_run_id=str(feature_id))
    except Exception as exc:
        attempt.update(status='blocked_or_failed',error_type=type(exc).__name__)
        # Do not serialize connection strings or raw credential-containing exceptions.
        save_json(output/'prepare_attempt.json',attempt)
        raise
    attempt['finished_utc']=datetime.now(timezone.utc).isoformat()
    save_json(output/'prepare_attempt.json',attempt)
    print(json.dumps(attempt),flush=True)


def load_prepared(output, design_hash, prepared_hash):
    output,registration,config=verify_design(output,design_hash)
    if not prepared_hash or file_hash(output/'prepared.json')!=prepared_hash:
        raise ValueError('Prepared input registration differs from separately supplied expected hash')
    prepared=json.loads((output/'prepared.json').read_text())
    if prepared.get('kind')!='cybershield_corrected_prepared_v1' or prepared['design_sha256']!=design_hash:
        raise ValueError('Input registration is not bound to this design')
    if prepared.get('run_id')!=registration['run_id']:
        raise ValueError('Prepared experiment identity differs from design')
    for relative,digest in prepared['files'].items():
        path=(output/'prepared'/relative).resolve()
        if not path.is_relative_to(output/'prepared') or not path.is_file() or file_hash(path)!=digest:
            raise ValueError(f'Prepared input changed: {relative}')
    data=pd.read_csv(output/'prepared/windows.csv',float_precision='round_trip')
    for column in ['attack_categories','episode_labels','episode_groups','source_members']:
        data[column]=data[column].map(json.loads)
    allocated=allocate(data,config)
    for column in ['role','role_reason','known','is_attack','episode_groups','dependency_block','day']:
        if not allocated[column].equals(data[column]):
            raise ValueError(f'Frozen membership cannot be reproduced: {column}')
    return output,registration,config,prepared,allocated


def benchmark(output, design_hash, prepared_hash):
    output,registration,config,prepared,data=load_prepared(output,design_hash,prepared_hash)
    from .study_benchmark import run_benchmark
    def sql_rules(scales):
        with connect(prepared['schema']) as conn:
            # Use the actual registered SQL expression, not an invented fused detector.
            result=frame(conn,(ROOT/'sql/detection/scores.sql').read_text(encoding='utf-8'),
                {'feature_run_id':prepared['feature_run_id'],**scales})
        keys=data[['src_ip','window_start']].merge(result,on=['src_ip','window_start'],validate='one_to_one',how='left')
        if keys.sql_combined.isna().any():
            raise ValueError('SQL scores do not cover identical registered windows')
        return keys.sql_combined.to_numpy(dtype=float)
    result=run_benchmark(data,config,output/'benchmark',sql_rules,run_id=registration['run_id'])
    save_json(output/'benchmark_registration.json',{'design_sha256':design_hash,'prepared_sha256':prepared_hash,
              'status':result['status'],'run_id':registration['run_id'],'files':artifact_hashes(output/'benchmark')})
    print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    audit=sub.add_parser('audit');audit.add_argument('--archive',required=True,type=Path)
    audit.add_argument('--protocol',type=Path,default=ROOT/'configs/corrected_development_v1.json')
    audit.add_argument('--output',required=True,type=Path)
    aud_support=sub.add_parser('audit-support');aud_support.add_argument('--bundle',required=True,type=Path)
    aud_support.add_argument('--protocol',type=Path,default=ROOT/'configs/corrected_development_v1.json')
    aud_support.add_argument('--output',required=True,type=Path)
    aud_support.add_argument('--revision-note',help='Explicitly disclose a pre-model support-only design revision; never rewrite the original audit')
    reg=sub.add_parser('register');reg.add_argument('--archive',required=True,type=Path)
    reg.add_argument('--protocol',type=Path,default=ROOT/'configs/corrected_development_v1.json')
    reg.add_argument('--output',type=Path)
    for name in ['prepare','benchmark','verify']:
        cmd=sub.add_parser(name);cmd.add_argument('--run',required=True,type=Path)
        cmd.add_argument('--design-sha256',required=True)
        if name in ['benchmark','verify']:cmd.add_argument('--prepared-sha256',required=True)
    args=parser.parse_args()
    try:
        if args.command=='audit':
            config=validate_protocol(json.loads(args.protocol.read_text()))
            audit_archive(args.archive,config['members'],args.output,protocol_sha256=file_hash(args.protocol))
        elif args.command=='audit-support':audit_support(args.bundle,args.protocol,args.output,args.revision_note)
        elif args.command=='register':register(args.protocol,args.archive,args.output)
        elif args.command=='prepare':prepare(args.run,args.design_sha256)
        elif args.command=='benchmark':benchmark(args.run,args.design_sha256,args.prepared_sha256)
        else:
            output,_,_,_,_=load_prepared(args.run,args.design_sha256,args.prepared_sha256)
            manifest=json.loads((output/'benchmark_registration.json').read_text())
            if manifest['design_sha256']!=args.design_sha256 or manifest['prepared_sha256']!=args.prepared_sha256:
                raise ValueError('Benchmark registration does not match expected inputs')
            for relative,digest in manifest['files'].items():
                path=(output/'benchmark'/relative).resolve()
                if not path.is_relative_to(output/'benchmark') or file_hash(path)!=digest:
                    raise ValueError(f'Benchmark artifact changed: {relative}')
            if manifest['status']=='completed_development_validation':
                from .study_benchmark import verify_scores
                verify_scores(output/'benchmark')
                print('Verified registered design, inputs, matched score/cutoff metrics and benchmark files.')
            elif manifest['status']=='blocked_support':
                gate=json.loads((output/'benchmark/support_gate.json').read_text())
                if gate['passed'] or (output/'benchmark/metrics.csv').exists():
                    raise ValueError('Support-blocked result has inconsistent gate or unexpected metrics')
                print('Verified registered design, inputs and support-blocked report; no model metrics or scoring are claimed.')
            else:
                raise ValueError('Benchmark has no completed or support-blocked status')
    except Exception as exc:
        print(f'Study stopped ({type(exc).__name__}): {exc if isinstance(exc,ValueError) else "inspect phase status; no result claim made"}',file=sys.stderr)
        raise SystemExit(1) from None


if __name__=='__main__':
    main()
