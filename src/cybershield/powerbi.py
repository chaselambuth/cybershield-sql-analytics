"""Validated, immutable reporting exports. Does not fit models or write to SQL."""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import math
import shutil
import uuid
from pathlib import Path

import numpy as np
import pandas as pd

from .db import ROOT, connect, file_hash
from .evaluate import FEATURES, frame, metrics

SCHEMA_VERSION = 1
PROTO = {'rule_volume':'volume', 'rule_ports':'ports', 'rule_services':'services',
         'sql_combined':'sql', 'logistic_regression':'lr', 'flow_count_baseline':'flow',
         'random_baseline':'random', 'always_benign':'benign'}
ML = {'Random forest':'rf','Linear SVM':'svm','Logistic regression':'lr','XGBoost':'xgb',
      'Histogram boosting':'hgb','LightGBM':'lgbm','CatBoost':'cat','Extra trees':'extra'}
NAMES = {'volume':'Volume rule (flow-count equivalent)','ports':'Port diversity rule',
         'services':'Service traffic rule','sql':'Combined SQL rules','lr':'Logistic regression',
         'flow':'Flow count control','random':'Random control','benign':'Always-benign control',
         **{v:k for k,v in ML.items()}}
INT_FIELDS = {'tp','fp','tn','fn','windows','positives','negatives','alerts'}
QUALITY_FIELDS = sorted(INT_FIELDS) + ['precision','recall','f1','false_positives_per_1000',
                                       'average_precision','roc_auc']


class ReportingError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReportingError(message)


def digest_object(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                    ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_csv(path):
    return pd.read_csv(path,float_precision='round_trip',keep_default_na=True)


def score_values(values, dtype):
    """Restore a documented native dtype, then always compare at float64 precision."""
    require(dtype in {'float32','float64'}, 'Unsupported native score dtype')
    result=np.asarray(values,dtype=dtype).astype(np.float64)
    require(np.isfinite(result).all(), 'Non-finite reporting score')
    return result


def tie_stats(values):
    _, counts=np.unique(np.asarray(values,dtype=np.float64),return_counts=True)
    return {'distinct_scores':len(counts),'largest_tie_count':int(counts.max()),
            'largest_tie_share':float(counts.max()/counts.sum())}


def window_keys(data, feature_id):
    # Length-prefixed structured hashing, independent of file ordering.
    return [digest_object([str(feature_id),str(ip),pd.Timestamp(t).isoformat()])
            for ip,t in zip(data.src_ip,data.window_start)]


def check_quality(actual, expected, label):
    for field in QUALITY_FIELDS:
        target=expected[field]
        if pd.isna(target):
            require(actual[field] is None, f'{label}: undefined {field} differs')
        elif field in INT_FIELDS:
            require(actual[field]==int(target),f'{label}: {field} mismatch')
        else:
            require(math.isclose(actual[field],float(target),rel_tol=1e-10,abs_tol=1e-12),
                    f'{label}: {field} mismatch')


def verified_inputs(root=ROOT):
    root=Path(root); research=root/'reports/research'
    recorded={k.replace('\\','/'):v for k,v in load_json(research/'research_manifest.json').items()}
    artifact=load_json(research/'snapshot/artifact_manifest.json')
    original_python={k.replace('\\','/'):v for k,v in artifact['python_files'].items()}
    for key,h in original_python.items():
        recorded.setdefault(key,h)
    snapshot=load_json(research/'snapshot/manifest.json')
    scientific=[research/'snapshot/manifest.json',*[research/'snapshot'/p for p in snapshot['files']],
                *sorted((research/'models').glob('*')),
                root/'src/cybershield/research.py',root/'src/cybershield/evaluate.py']
    audits=sorted(p for p in (research/'sources').glob('*') if p.is_file())
    digests={}
    for path in scientific+audits:
        require(path.is_file(),f'Missing input {path.name}')
        key=path.relative_to(root).as_posix()
        require(key in recorded and file_hash(path)==recorded[key],f'Input hash mismatch: {key}')
        digests[key]=recorded[key]
    for name,h in snapshot['files'].items():
        require(file_hash(research/'snapshot'/name)==h,f'Snapshot mismatch: {name}')
    for key,h in artifact['sql_files'].items():
        path=root/key
        require(file_hash(path)==h,f'Original SQL changed: {key}')
        digests[path.relative_to(root).as_posix()]=h
    benchmark_inputs={p.relative_to(root).as_posix():digests[p.relative_to(root).as_posix()]
                      for p in scientific}
    return snapshot,digests,'benchmark_'+digest_object(benchmark_inputs)


def scientific_tables(root=ROOT):
    root=Path(root); research=root/'reports/research'
    snapshot,input_hashes,benchmark_id=verified_inputs(root)
    feature_id=snapshot['feature_run_id']; experiment_id=snapshot['experiment_id']
    protocol=load_json(research/'snapshot/development_protocol.json')
    environment=load_json(research/'models/environment.json')
    xgb=importlib.metadata.distribution('xgboost')
    require(xgb.version==environment['versions']['xgboost'],'XGBoost dtype evidence version differs')
    core=Path(xgb.locate_file('xgboost/core.py'))
    producer=core.read_text(encoding='utf-8').split('def _prediction_output(',1)[1].split('\nclass ',1)[0]
    require('np.float32' in producer,'XGBoost native dtype evidence unavailable')
    data=read_csv(research/'snapshot/window_scores.csv')
    data['window_start']=pd.to_datetime(data.window_start)
    require(not data.duplicated(['src_ip','window_start']).any(),'Duplicate snapshot windows')
    data['window_key']=window_keys(data,feature_id)
    require(data.window_key.is_unique,'Window key collision')
    require(not data.unknown_flows.gt(0).any(),'Pinned snapshot gained unresolved targets')
    data['is_attack']=data.attack_flows.gt(0)
    dev=data.loc[data.split.eq('development')].sort_values(['src_ip','window_start']).reset_index(drop=True)
    require(len(dev)==3413 and dev.is_attack.sum()==6,'Pinned development population changed')
    require(data.split.value_counts().to_dict()=={'train':3493,'development':3413,
            'unscored':3247,'calibration':1245},'Role population changed')
    scores=read_csv(research/'models/development_scores.csv')
    scores['window_start']=pd.to_datetime(scores.window_start)
    require(not scores.duplicated(['src_ip','window_start']).any(),'Duplicate benchmark keys')
    scores=scores.sort_values(['src_ip','window_start']).reset_index(drop=True)
    require(scores[['src_ip','window_start']].equals(dev[['src_ip','window_start']]),'Benchmark keys differ')
    require(np.array_equal(scores.is_attack,dev.is_attack),'Benchmark targets differ')
    quality=read_csv(research/'models/quality_latency.csv').set_index('method')
    require(set(quality.index)==set(ML),'Benchmark candidate set changed')
    baselines=read_csv(research/'models/baseline_quality.csv').set_index('method')
    prototype_metrics={}; evaluations={}; detector_rows={}; decisions=[]; checks=[]
    for method,detector in PROTO.items():
        values=score_values(data[method],'float64'); cutoff=float(protocol['cutoffs'][method])
        selected=values>=np.float64(cutoff)
        dev_scores=score_values(dev[method],'float64')
        actual=metrics(dev.is_attack,dev_scores,cutoff)
        prototype_metrics[method]=actual
        if method in baselines.index:
            check_quality(actual,baselines.loc[method],method)
        evaluations[detector]={'detector_id':detector,'quality_provider':'prototype:'+method,
            'cohort':'development','cutoff_text':repr(cutoff),**actual}
        stats=tie_stats(dev_scores)
        detector_rows[detector]={'detector_id':detector,'display_name':NAMES[detector],
            'family':'SQL' if method.startswith('rule_') or method=='sql_combined' else 'Control',
            'default_comparison':method=='sql_combined','decision_provider':'snapshot:'+method,
            'quality_provider':'prototype:'+method,'latency_provider':'not measured',
            'native_score_dtype':'float64','score_semantics':'rule scale' if 'rule' in method or method=='sql_combined' else 'control score',
            'reproduced':False,**stats}
        part=pd.DataFrame({'window_key':data.window_key,'detector_id':detector,
                           'predicted_attack':selected,'score':values})
        part['within_detector_rank']=part.score.rank(method='min',ascending=False).astype(int)
        part['cutoff_text']=repr(cutoff)
        decisions.append(part)
    dtype_evidence={}
    for method,detector in ML.items():
        native='float32' if method=='XGBoost' else 'float64'
        values=score_values(scores[method],native); row=quality.loc[method];cutoff=float(row.cutoff)
        actual=metrics(dev.is_attack,values,cutoff)
        check_quality(actual,row,method)
        if detector=='lr':
            check_quality(actual,pd.Series(prototype_metrics['logistic_regression']),'Logistic provider agreement')
            require(np.array_equal(values>=cutoff,dev.logistic_regression.to_numpy()>=protocol['cutoffs']['logistic_regression']),
                    'Logistic providers disagree on decisions')
            require(np.allclose(values,dev.logistic_regression,rtol=1e-12,atol=1e-14),'Logistic score mismatch')
        evaluations[detector]={'detector_id':detector,'quality_provider':'benchmark:'+method,
            'cohort':'development','cutoff_text':repr(cutoff),**actual,
            **{k:float(row[k]) for k in ['fit_median_ms','fit_max_ms','serialized_bytes',
                'single_pipeline_median_ms','single_pipeline_p95_ms']},
            'pareto_observed':bool(row.pareto_observed)}
        detector_rows[detector]={'detector_id':detector,'display_name':NAMES[detector],
            'family':'ML','default_comparison':True,'decision_provider':'snapshot:logistic_regression' if detector=='lr' else 'not in prototype',
            'quality_provider':'benchmark:'+method,'latency_provider':'benchmark:'+method,
            'native_score_dtype':native,'score_semantics':'SVM margin' if detector=='svm' else 'positive-class model score',
            'reproduced':detector=='lr',**tie_stats(values)}
        dtype_evidence[method]={'native_dtype':native,'comparison_dtype':'float64',
            'evidence':'XGBoost core.py _prediction_output constructs np.float32; pinned xgboost '+environment['versions']['xgboost']
                       if native=='float32' else 'Float64 producer output; saved-score reconstruction verified against all quality metrics'}
        if native=='float32':dtype_evidence[method]['installed_core_sha256']=file_hash(core)
    for row in detector_rows.values():
        row['high_tie_concentration']=row['largest_tie_share']>.5
        row['caveat']=('Constant-score control. ' if row['distinct_scores']==1 else '')
        if row['high_tie_concentration']:
            row['caveat']+=f"Majority tied: {row['largest_tie_count']:,}/3,413 ({row['largest_tie_share']:.2%}); {row['distinct_scores']} distinct scores. "
        if row['detector_id']=='xgb':
            row['caveat']+='Legacy float32 CSV restored before float64 comparisons; calibration-alert field excluded.'
        if row['detector_id']=='volume':row['caveat']+='Same ranking as flow-count control.'
    columns=['window_key','src_ip','window_start','split',*FEATURES,'attack_flows','unknown_flows','categories','is_attack']
    windows=data[columns].copy()
    windows['categories']=windows.categories.map(lambda v:';'.join(sorted(ast.literal_eval(v))) if isinstance(v,str) else '')
    windows['role_context']=windows.split.map({'train':'Training / in-sample','calibration':'Threshold calibration',
                                             'development':'Development check; correlated campaign','unscored':'Unscored; not test'})
    evaluation=pd.DataFrame(evaluations.values()).drop(columns='cutoff',errors='ignore')
    latency=read_csv(research/'models/latency_by_batch.csv')
    latency['detector_id']=latency.method.map(ML)
    require(latency.detector_id.notna().all(),'Unknown latency model')
    raw=read_csv(research/'models/raw_latency.csv')
    derived=raw.groupby(['method','scope','batch_size']).call_ms.agg(median_ms='median',p95_ms=lambda s:s.quantile(.95),calls='size').reset_index()
    joined=latency.merge(derived,on=['method','scope','batch_size'],suffixes=('','_raw'),validate='one_to_one')
    require(len(joined)==64,'Missing latency groups')
    for col in ['median_ms','p95_ms','calls']:
        require(np.allclose(joined[col],joined[col+'_raw'],rtol=1e-12,atol=1e-12),f'Latency {col} changed')
    require((latency.calls==np.where(latency.batch_size.eq(1),60,25)).all(),'Timing call count mismatch')
    require(set(latency.scope)=={'pipeline','model_only'},'Timing scope changed')
    latency['scope_display']=latency.scope.map({'pipeline':'Pipeline (includes preprocessing)','model_only':'Estimator only'})
    latency['hardware_context']=environment['cpu']+'; 1 compute thread; '+environment['os']
    tables={'Window':windows,'DimDetector':pd.DataFrame(detector_rows.values()),
            'FactPrototypeDecision':pd.concat(decisions,ignore_index=True),
            'FactEvaluation':evaluation,'FactLatency':latency.drop(columns='method')}
    tables.update(audit_tables(research))
    checks.append({'check':'All benchmark quality, scores, labels and prototype control providers','status':'passed'})
    checks.append({'check':'64 timing groups reproduce raw-call median/P95/count','status':'passed'})
    return tables,{'snapshot':snapshot,'protocol':protocol,'environment':environment,'input_hashes':input_hashes,
                   'benchmark_id':benchmark_id,'dtype_evidence':dtype_evidence,'checks':checks}


def audit_tables(research):
    rows=[];datasets=[]
    metrics_fields={'input_rows':('Input records','rows'),'accepted_rows':('Accepted records','rows'),
        'rejected_rows':('Quarantined records','rows'),'temporal_eligible_rows':('Temporally eligible records','rows'),
        'negative_duration_rows':('Negative durations','rows'),'duplicate_content_rows_excluding_id':('Repeated content','rows'),
        'active_windows':('Active source windows','windows'),'positive_windows':('Positive windows across roles','windows'),
        'positive_sources':('Positive recorded sources','addresses'),'unknown_windows':('Unknown-label windows','windows'),
        'attempted_rows':('Attempted-label records','rows')}
    quality=load_json(research/'snapshot/data_quality.json')
    for key,label in [('original','Original CIC-IDS2017'),('corrected','Corrected CIC-IDS2017 (CNS2022)'),('unsw','UNSW-NB15')]:
        scope='Morning-eligible temporal population; complete Tuesday input audit' if key=='original' else 'Full-day Tuesday; explicit corrected clock'
        status='documentation_only' if key=='unsw' else 'measured'
        if key=='unsw':scope='Not inspected; official download HTTP 403'
        datasets.append({'dataset_id':key,'dataset_name':label,'evidence_status':status,'scope':scope})
        audit={} if key=='unsw' else load_json(research/f'sources/{key}_audit.json')
        if key=='original':audit.update({k:quality[k] for k in ['accepted_rows','rejected_rows']})
        for metric,(title,unit) in metrics_fields.items():
            value=audit.get(metric)
            if key=='corrected' and metric=='accepted_rows':title='Prototype accepted records';value=None
            rows.append({'dataset_id':key,'metric':metric,'metric_label':title,'value':value,'unit':unit,
                'time_scope':scope,'status':status if value is not None else ('documentation_only' if key=='unsw' else 'not_applicable'),
                'label_policy':'Unresolved attempted labels retained; not silently remapped' if key=='corrected' else 'Original retrospective labels',
                'clock_policy':audit.get('clock_policy','unverified')})
    sensitivity=read_csv(research/'sources/label_sensitivity.csv')
    for r in sensitivity.itertuples():
        for metric in ['eligible_windows','positive_windows']:
            rows.append({'dataset_id':r.source,'metric':metric+'_sensitivity','metric_label':metric.replace('_',' ').title(),
                'value':getattr(r,metric),'unit':'windows','time_scope':'Tuesday sensitivity population',
                'status':'measured','label_policy':r.policy,'clock_policy':'Release-specific clock; scopes differ'})
    return {'DimDataset':pd.DataFrame(datasets),'FactSourceAudit':pd.DataFrame(rows)}


def extract_sql(tables,context,root=ROOT):
    snapshot=context['snapshot']; feature=snapshot['feature_run_id']; experiment=snapshot['experiment_id']
    query_path=Path(root)/'sql/reporting/supporting_flows.sql'
    with connect(snapshot['schema']) as conn:
        conn.read_only=True
        conn.isolation_level=__import__('psycopg').IsolationLevel.REPEATABLE_READ
        conn.execute("SET LOCAL statement_timeout='120s'")
        require(conn.execute('SHOW transaction_read_only').fetchone()[0]=='on','SQL transaction not read-only')
        exists=conn.execute('SELECT feature_run_id::text FROM experiment_run WHERE experiment_id=%s',(experiment,)).fetchone()
        require(exists is not None and exists[0]==feature,'Pinned SQL experiment absent or different')
        db=frame(conn,'''SELECT host(src_ip) src_ip,window_start,method,score,predicted_attack,split
                         FROM prediction WHERE experiment_id=%s ORDER BY method,src_ip,window_start''',(experiment,))
        db['window_key']=window_keys(db,feature);db['detector_id']=db.method.map(PROTO)
        require(db.detector_id.notna().all(),'SQL detector set changed')
        expected=tables['FactPrototypeDecision']
        joined=expected.merge(db,on=['window_key','detector_id'],validate='one_to_one',suffixes=('','_db'))
        require(len(joined)==len(expected)==len(db),'SQL decision population mismatch')
        require(np.array_equal(joined.predicted_attack,joined.predicted_attack_db),'SQL decisions differ')
        require(np.allclose(joined.score,joined.score_db,rtol=1e-12,atol=1e-14),'SQL scores differ')
        roles=tables['Window'].set_index('window_key').split
        require(db.split.eq(db.window_key.map(roles)).all(),'SQL role assignment differs')
        flows=frame(conn,query_path.read_text(),{'feature_run_id':feature})
        require(flows.matched_feature_run_id.eq(feature).all(),'Eligible SQL flow lacks a pinned window')
    flows['window_key']=window_keys(flows,feature)
    flows['flow_id']=snapshot['schema']+':'+flows.flow_id.astype(str)
    require(flows.flow_id.is_unique,'Duplicate supporting flow key')
    actual=flows.groupby('window_key').size().sort_index()
    wanted=tables['Window'].set_index('window_key').flow_count.sort_index()
    require(actual.index.equals(wanted.index) and np.array_equal(actual.values,wanted.values),
            'Supporting flows do not reconcile for every window')
    require(len(flows)==int(wanted.sum())==207006,'Supporting flow total changed')
    tables['SupportingFlows']=flows.drop(columns=['matched_feature_run_id','window_start'])
    context['checks']+= [{'check':'91,184 prototype decisions equal pinned PostgreSQL records','status':'passed'},
                        {'check':'207,006 supporting flows reconcile individually to all 11,398 windows','status':'passed'}]


def column_type(series):
    if pd.api.types.is_bool_dtype(series):return 'boolean'
    if pd.api.types.is_integer_dtype(series):return 'int64'
    if pd.api.types.is_datetime64_any_dtype(series):return 'datetime'
    if pd.api.types.is_numeric_dtype(series):return 'double'
    return 'text'


def verify_bundle(folder):
    folder=Path(folder); manifest=load_json(folder/'manifest.json')
    require(manifest['schema_version']==SCHEMA_VERSION,'Unsupported bundle schema')
    identity={k:v for k,v in manifest.items() if k!='report_bundle_id'}
    require('bundle_'+digest_object(identity)==manifest['report_bundle_id'],'Bundle identity mismatch')
    for name,record in manifest['files'].items():
        require(Path(name).name==name,'Invalid bundle filename')
        require((folder/name).is_file() and file_hash(folder/name)==record['sha256'],f'Bundle file changed: {name}')
    schemas=load_json(folder/'schema.json')
    if 'payload_id' in manifest:
        payload=load_json(folder/'report_data.json')
        raw={k:v for k,v in payload.items() if k!='payload_id'}
        require(payload['payload_id']=='payload_'+digest_object(raw)==manifest['payload_id'],
                'Packed payload identity mismatch')
    for table,schema in schemas.items():
        data=read_csv(folder/schema['file'])
        require(list(data.columns)==[c['name'] for c in schema['columns']],f'{table}: columns changed')
        require(len(data)==schema['rows'],f'{table}: row count changed')
    return manifest


def prepare(root=ROOT):
    root=Path(root)
    tables,context=scientific_tables(root)
    extract_sql(tables,context,root)
    env=context['environment']; snap=context['snapshot']
    tables['RunContext']=pd.DataFrame([{'pipeline_experiment_id':snap['experiment_id'],
        'feature_run_id':snap['feature_run_id'],'benchmark_id':context['benchmark_id'],
        'dataset':'Original CIC-IDS2017 Tuesday','clock_policy':'naive_capture_clock; strict unrepaired morning',
        'cohort':'Development only: 6 positive / 3,407 benign; one correlated campaign',
        'hardware':env['cpu']+'; '+env['os'],'benchmark_created_utc':env['created_utc'],
        'report_note':'Retrospective offline evidence; not live detection or a model winner certificate.'}])
    tables['DetectorArtifactMap']=tables['DimDetector'][['detector_id','decision_provider','quality_provider','latency_provider']].melt(
        id_vars='detector_id',var_name='evidence_role',value_name='provider')
    base=root/'power_bi/data';base.mkdir(parents=True,exist_ok=True)
    stage=base/('.staging_'+uuid.uuid4().hex);stage.mkdir()
    try:
        schema={}
        for name,table in tables.items():
            table.to_csv(stage/f'{name}.csv',index=False,float_format='%.17g',date_format='%Y-%m-%d %H:%M:%S.%f')
            schema[name]={'file':f'{name}.csv','rows':len(table),'columns':[
                {'name':col,'type':column_type(table[col])} for col in table]}
        (stage/'schema.json').write_text(json.dumps(schema,indent=2))
        validation={'status':'passed','checks':context['checks'],
            'dtype_evidence':context['dtype_evidence'],'excluded_fields':['calibration_false_alerts'],
            'legacy_issues':['XGBoost calibration scalar-promotion bug; original artifact preserved',
                'XGBoost float32 score text restored before float64 validation'],
            'populations':{'windows':11398,'development_windows':3413,'positive_development':6,'supporting_flows':207006}}
        (stage/'validation.json').write_text(json.dumps(validation,indent=2))
        packed_tables={}
        for name,table in tables.items():
            packed=table.copy()
            for col in packed:
                if pd.api.types.is_datetime64_any_dtype(packed[col]):
                    packed[col]=packed[col].dt.strftime('%Y-%m-%d %H:%M:%S.%f')
            packed=packed.astype(object).where(pd.notna(packed),None)
            packed_tables[name]={'columns':list(packed.columns),'rows':packed.values.tolist()}
        payload={'schema_version':SCHEMA_VERSION,'benchmark_id':context['benchmark_id'],
                 'schema':schema,'validation':validation,'tables':packed_tables}
        payload['payload_id']='payload_'+digest_object(payload)
        # One physical data source avoids private-file combination in Power Query.
        (stage/'report_data.json').write_text(json.dumps(payload,separators=(',',':'),
            ensure_ascii=False,allow_nan=False),encoding='utf-8')
        producer_files=['src/cybershield/powerbi.py','sql/reporting/supporting_flows.sql']
        manifest={'schema_version':SCHEMA_VERSION,'payload_id':payload['payload_id'],'benchmark_id':context['benchmark_id'],
            'pipeline_experiment_id':snap['experiment_id'],'feature_run_id':snap['feature_run_id'],
            'input_hashes':context['input_hashes'],
            'reporting_code_hashes':{p:file_hash(root/p) for p in producer_files},
            'files':{p.name:{'sha256':file_hash(p),'bytes':p.stat().st_size} for p in sorted(stage.iterdir())}}
        manifest['report_bundle_id']='bundle_'+digest_object(manifest)
        (stage/'manifest.json').write_text(json.dumps(manifest,indent=2))
        verify_bundle(stage)
        target=base/manifest['report_bundle_id']
        if target.exists():
            require(verify_bundle(target)==manifest,'Existing bundle differs from identical identity')
            shutil.rmtree(stage)
        else:stage.rename(target)
        return target
    except Exception:
        # Failed staging evidence is retained for diagnosis; never expose it as a bundle.
        raise
