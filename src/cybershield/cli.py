from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .db import ROOT, connect, file_hash, migrate
from .evaluate import build_features, evaluate
from .fixture import make_fixture
from .ingest import ingest
from .reports import export_analyses, figures, findings


def run(args):
    synthetic=args.mode=='fixture'
    schema=args.schema or ('cs_fixture' if synthetic else 'cs_tuesday')
    config_path=(args.config or ROOT/'configs/prototype.yaml').resolve()
    config=yaml.safe_load(config_path.read_text(encoding='utf-8'))
    expected={'window_minutes':5,'lookback_minutes':60,'window_origin':'2000-01-01 00:00:00',
              'timestamp_policy':'strict_unrepaired','scoring_entity':'source_ip'}
    for key,value in expected.items():
        if config.get(key)!=value:
            raise ValueError(f'Prototype SQL currently requires {key}={value!r}')
    if synthetic:
        path=make_fixture(ROOT/'data/sample/synthetic_flows.csv'); member=None
    else:
        if not args.archive:
            raise ValueError('Use --archive PATH to the existing GeneratedLabelledFlows.zip')
        path=args.archive.resolve()
        with zipfile.ZipFile(path) as archive:
            matches=[name for name in archive.namelist() if 'Tuesday' in name and name.endswith('.csv')]
        if len(matches)!=1:
            raise ValueError('Expected exactly one Tuesday CSV in the labeled-flow archive')
        member=matches[0]
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=ROOT/'reports/runs'/f'{args.mode}_{stamp}_{uuid.uuid4().hex[:8]}'
    out.mkdir(parents=True)
    (out/'config.yaml').write_bytes(config_path.read_bytes())
    with connect(schema) as conn:
        migrate(conn,schema)
        print(f'[{args.mode}] Ingesting {member or path.name}',flush=True)
        audit=ingest(conn,path,member,synthetic=synthetic)
        (out/'data_quality.json').write_text(json.dumps(audit,indent=2),encoding='utf-8')
        print(f"Accepted {audit['accepted_rows']:,}; rejected {audit['rejected_rows']:,}; reused={audit['skipped']}",flush=True)
        feature_id=build_features(conn,[audit['source_id']],config,file_hash(config_path))
        print('SQL features built; evaluating development intervals',flush=True)
        experiment_id,data,metrics_frame,summary=evaluate(conn,feature_id,config,file_hash(config_path),out)
        export_analyses(conn,feature_id,experiment_id,[audit['source_id']],out)
        figures(data,metrics_frame,out,synthetic)
        findings(out,audit,summary,metrics_frame,synthetic)
        # Plans are actual measured executions of the two initial investigation queries.
        plans={}
        for name in ['01_activity.sql','02_bursts.sql']:
            query=(ROOT/'sql/analytics'/name).read_text(encoding='utf-8')
            plans[name]=conn.execute('EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON) '+query,
                                    {'feature_run_id':feature_id}).fetchone()[0]
        (out/'query_plans.json').write_text(json.dumps(plans,indent=2),encoding='utf-8')
        summary.update({'schema':schema,'output_directory':str(out),'synthetic':synthetic,
                        'data_quality':{k:audit[k] for k in ['input_rows','accepted_rows','rejected_rows','clock_usable_rows']}})
        (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    integrity={p.relative_to(out).as_posix():file_hash(p) for p in sorted(out.rglob('*'))
               if p.is_file() and p.name!='output_manifest.json'}
    (out/'output_manifest.json').write_text(json.dumps(integrity,indent=2),encoding='utf-8')
    (ROOT/'reports'/f'latest_{args.mode}.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2),flush=True)


def verify_comparison(report, expected, check_producer=False):
    """Check saved evidence independently of the current producer checkout."""
    import pandas as pd
    from .study_benchmark import verify_scores

    if file_hash(report/'registration.json') != expected:
        raise ValueError('Registration hash differs from the supplied expected hash')
    registration=json.loads((report/'registration.json').read_text(encoding='utf-8'))
    manifest=json.loads((report/'result_manifest.json').read_text(encoding='utf-8'))
    if registration['kind']!='cybershield_neural_comparison_v1' or manifest['registration_sha256']!=expected:
        raise ValueError('Results do not match the registered comparison')
    required={'registration.json','registration.sha256','protocol.json','scores.csv','cutoffs.csv',
              'metrics.csv','quality_latency.csv','raw_latency.csv','latency_by_batch.csv',
              'raw_fit_times.csv','comparison.png','latency.png','environment.json','fit_warnings.json',
              'neural_fit_state.json','model_artifact_index.json','retained_model_reconciliation.json'}
    if set(manifest['files'])!=required:
        raise ValueError('Comparison manifest is incomplete or contains unexpected files')
    for name,digest in manifest['files'].items():
        path=(report/name).resolve()
        if not path.is_relative_to(report) or not path.is_file() or file_hash(path)!=digest:
            raise ValueError(f'Result artifact missing or altered: {name}')
    if file_hash(report/'protocol.json')!=registration['protocol_sha256']:
        raise ValueError('Protocol differs from its registration')
    protocol=json.loads((report/'protocol.json').read_text(encoding='utf-8'))
    if manifest['status']!=registration['status'] or protocol['status']!=registration['status']:
        raise ValueError('Result status differs from its registration')
    methods=set(protocol['models']+protocol['controls'])
    scores=pd.read_csv(report/'scores.csv',float_precision='round_trip')
    cuts=pd.read_csv(report/'cutoffs.csv',float_precision='round_trip')
    keys={'src_ip','window_start','role','is_attack'}
    support=scores.groupby('role').is_attack.agg(['size','sum']).to_dict()
    if set(scores.columns)!=keys|methods or len(scores)!=registration['windows'] or support!=registration['support']:
        raise ValueError('Saved scoring population or model roster differs from its registration')
    budgets={protocol['false_positive_target'],*protocol['sensitivity_targets']}
    if (set(cuts.method)!=methods or set(cuts.target)!=budgets or
            cuts.duplicated(['method','target']).any() or len(cuts)!=len(methods)*len(budgets)):
        raise ValueError('Saved cutoffs do not cover every registered model and budget')
    verify_scores(report)
    if check_producer:
        # Producer checks remain strict and separate from saved-data integrity.
        from .neural_comparison import verify_registration
        verify_registration(report,expected,check_parent=False)
    print(f'Verified {len(required)} registered result files and all matched confusion counts. '
          f'Producer checkout audit: {"passed" if check_producer else "not requested"}.')


def main():
    parser=argparse.ArgumentParser(description='CyberShield PostgreSQL prototype (development-only)')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('configure',help='Create a local .env with a random password if absent')
    verify=sub.add_parser('verify',help='Verify saved report files against their output hashes')
    verify.add_argument('report',type=Path)
    verify.add_argument('--registration-sha256',help='Expected registration hash for a saved revised comparison')
    verify.add_argument('--check-producer',action='store_true',help='Also require the original producer source and package versions')
    workspace=sub.add_parser('serve',help='Open the local, read-only browser SQL workspace')
    workspace.add_argument('--port',type=int,default=8765)
    init=sub.add_parser('init',help='Apply checksum-verified migrations')
    init.add_argument('--schema',default='cs_fixture')
    pipeline=sub.add_parser('run',help='Run ingestion through findings and figures')
    pipeline.add_argument('--mode',choices=['fixture','real'],default='fixture')
    pipeline.add_argument('--archive',type=Path)
    pipeline.add_argument('--config',type=Path)
    pipeline.add_argument('--schema')
    args=parser.parse_args()
    try:
        if args.command=='serve':
            if not 1024<=args.port<=65535:
                raise ValueError('Choose a local port between 1024 and 65535.')
            from .web import serve
            serve(args.port)
        elif args.command=='configure':
            env=ROOT/'.env'
            if not env.exists():
                env.write_text('POSTGRES_DB=cybershield\nPOSTGRES_USER=cybershield\n'
                    f'POSTGRES_PASSWORD={secrets.token_hex(24)}\nPOSTGRES_PORT=55432\n',encoding='utf-8')
            print('Local .env ready; existing configuration preserved.')
        elif args.command=='verify':
            report=args.report.resolve()
            if args.registration_sha256:
                verify_comparison(report,args.registration_sha256,args.check_producer)
                return
            if args.check_producer:
                raise ValueError('--check-producer requires --registration-sha256')
            manifest=json.loads((report/'output_manifest.json').read_text(encoding='utf-8'))
            for name,digest in manifest.items():
                path=(report/name.replace('\\','/')).resolve()
                if not path.is_relative_to(report) or not path.is_file() or file_hash(path)!=digest:
                    raise ValueError(f'Report file missing or altered: {name}')
            print(f'Verified {len(manifest)} report files. This is integrity verification, not a final-test seal.')
        elif args.command=='init':
            with connect(args.schema) as conn:
                migrate(conn,args.schema)
            print(f'Migrations ready: {args.schema}')
        else:
            run(args)
    except Exception as exc:
        # Do not print a DSN/password on connection failures.
        print(f'CyberShield failed ({type(exc).__name__}): {exc}',file=sys.stderr)
        raise SystemExit(1) from None


if __name__=='__main__':
    main()

