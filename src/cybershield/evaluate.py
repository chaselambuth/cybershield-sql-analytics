from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from psycopg.types.json import Jsonb
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from .db import ROOT, file_hash

FEATURES = ['flow_count','unique_ports','unique_destinations','service_flows',
            'packets','bytes','mean_duration_us']


def frame(conn, query, params=None):
    cursor=conn.execute(query,params)
    return pd.DataFrame(cursor.fetchall(),columns=[c.name for c in cursor.description])


def calibrate(scores, target=0.01):
    scores=np.asarray(scores,dtype=float)
    if not len(scores) or not np.isfinite(scores).all():
        raise ValueError('Calibration requires nonempty finite benign scores')
    if not 0 <= target < 1:
        raise ValueError('False-positive target must be in [0,1)')
    allowed=math.floor(target*len(scores))
    ordered=np.sort(scores)[::-1]
    return float(np.nextafter(ordered[allowed],np.inf))


def metrics(y,scores,cutoff):
    y=np.asarray(y,dtype=bool); scores=np.asarray(scores,dtype=float)
    pred=scores>=cutoff
    tp=int(np.sum(pred & y)); fp=int(np.sum(pred & ~y))
    tn=int(np.sum(~pred & ~y)); fn=int(np.sum(~pred & y))
    return {'windows':len(y),'positives':int(y.sum()),'negatives':int((~y).sum()),
            'tp':tp,'fp':fp,'tn':tn,'fn':fn,'alerts':tp+fp,
            'precision':tp/(tp+fp) if tp+fp else None,
            'recall':tp/(tp+fn) if tp+fn else None,
            'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
            'false_positives_per_1000':1000*fp/(fp+tn) if fp+tn else None,
            'average_precision':float(average_precision_score(y,scores)) if y.any() else None,
            'roc_auc':float(roc_auc_score(y,scores)) if y.any() and (~y).any() else None,
            'cutoff':float(cutoff)}


def build_features(conn, source_ids, config, config_hash):
    if config.get('status') != 'development_only' or config.get('window_minutes') != 5:
        raise ValueError('Prototype supports development-only five-minute configurations')
    feature_id=uuid.uuid4()
    feature_sql=ROOT/'sql/features/source_windows.sql'
    label_sql=ROOT/'sql/features/window_labels.sql'
    digest=hashlib.sha256(feature_sql.read_bytes()+label_sql.read_bytes()).hexdigest()
    conn.execute('INSERT INTO feature_run VALUES (%s,now(),%s,%s,%s,%s)',
                 (feature_id,config_hash,digest,Jsonb(config),source_ids))
    params={'feature_run_id':feature_id,'source_ids':source_ids}
    conn.execute(feature_sql.read_text(encoding='utf-8'),params)
    conn.execute(label_sql.read_text(encoding='utf-8'),params)
    conn.commit()
    return feature_id


def evaluate(conn, feature_id, config, config_hash, out: Path):
    data=frame(conn,'''SELECT host(f.src_ip) AS src_ip,f.window_start,f.flow_count,f.unique_ports,
        f.unique_destinations,f.service_flows,f.packets,f.bytes,f.mean_duration_us,
        f.historical_mean,f.historical_windows,f.volume_change,l.attack_flows,l.unknown_flows,l.categories
        FROM window_features f JOIN window_label l USING(feature_run_id,src_ip,window_start)
        WHERE f.feature_run_id=%s ORDER BY window_start,f.src_ip''',(feature_id,))
    if data.empty:
        raise ValueError('No usable morning-clock source windows')
    data['window_start']=pd.to_datetime(data.window_start)
    data['split']='unscored'
    for name,interval in config['splits'].items():
        if name not in {'train','calibration','development'}:
            raise ValueError('Final test scoring is not implemented in this prototype')
        mask=(data.window_start>=pd.Timestamp(interval[0])) & (data.window_start<pd.Timestamp(interval[1]))
        if (data.loc[mask,'split']!='unscored').any():
            raise ValueError('Overlapping development intervals')
        data.loc[mask,'split']=name
    known=data.unknown_flows==0
    train=(data.split=='train') & known
    calibration=(data.split=='calibration') & known & (data.attack_flows==0)
    if data.loc[train,'attack_flows'].gt(0).nunique()!=2:
        raise ValueError('Training interval needs both classes; inspect support before changing the protocol')
    if not calibration.any():
        raise ValueError('No benign calibration windows')
    reference=train & (data.attack_flows==0)
    if not reference.any():
        raise ValueError('No benign reference windows')
    scales={name:max(1.0,float(data.loc[reference,col].quantile(config['rule_reference_quantile'])))
            for name,col in [('rule_volume','flow_count'),('rule_ports','unique_ports'),('rule_services','service_flows')]}
    scored=frame(conn,(ROOT/'sql/detection/scores.sql').read_text(encoding='utf-8'),
        {'feature_run_id':feature_id,'volume_scale':scales['rule_volume'],
         'ports_scale':scales['rule_ports'],'services_scale':scales['rule_services']})
    data=data.merge(scored.drop(columns='feature_run_id'),on=['src_ip','window_start'],validate='one_to_one',sort=False)
    # Merge is explicitly checked and masks are recomputed rather than relying on order.
    known=data.unknown_flows==0
    train=(data.split=='train') & known
    calibration=(data.split=='calibration') & known & (data.attack_flows==0)
    X=data[FEATURES].to_numpy(dtype=float)
    model=make_pipeline(SimpleImputer(strategy='median'),FunctionTransformer(np.log1p),
                        StandardScaler(),LogisticRegression(C=config['model']['C'],
                        class_weight=config['model']['class_weight'],solver=config['model']['solver'],
                        max_iter=config['model']['max_iter'],random_state=config['seed']))
    model.fit(X[train],data.loc[train,'attack_flows'].gt(0).to_numpy())
    data['logistic_regression']=model.predict_proba(X)[:,1]
    data['flow_count_baseline']=data.flow_count.astype(float)
    data['random_baseline']=np.random.default_rng(config['seed']).random(len(data))
    data['always_benign']=0.0
    methods=['rule_volume','rule_ports','rule_services','sql_combined','logistic_regression',
             'flow_count_baseline','random_baseline','always_benign']
    cutoffs={method:calibrate(data.loc[calibration,method],config['false_positive_target']) for method in methods}
    cutoffs['always_benign']=1.0
    results=[]
    for split in ['train','calibration','development']:
        mask=(data.split==split)&known
        for method in methods:
            results.append({'split':split,'method':method,**metrics(data.loc[mask,'attack_flows'].gt(0),
                data.loc[mask,method],cutoffs[method])})
    result_frame=pd.DataFrame(results)
    result_frame.to_csv(out/'metrics.csv',index=False)
    data.to_csv(out/'window_scores.csv',index=False)
    joblib.dump(model,out/'model.joblib')
    protocol={'status':'development_only','config_sha256':config_hash,'cutoffs':cutoffs,
              'scales':scales,'features':FEATURES,'config':config}
    (out/'development_protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf-8')
    artifacts={p.name:file_hash(p) for p in [out/'model.joblib',out/'development_protocol.json']}
    artifacts['sql_files']={str(p.relative_to(ROOT)):file_hash(p) for p in sorted((ROOT/'sql').rglob('*.sql'))}
    artifacts['python_files']={str(p.relative_to(ROOT)):file_hash(p) for p in sorted((ROOT/'src').rglob('*.py'))}
    artifacts['versions']={name:importlib.metadata.version(name) for name in ['psycopg','numpy','pandas','scikit-learn','matplotlib']}
    experiment_id=uuid.uuid4()
    support={split:{'windows':int(((data.split==split)&known).sum()),
                   'positive_windows':int(((data.split==split)&known&(data.attack_flows>0)).sum())}
             for split in ['train','calibration','development','unscored']}
    summary={'status':'development_only','experiment_id':str(experiment_id),
             'feature_run_id':str(feature_id),'support':support,'total_windows':len(data),
             'unknown_windows':int((~known).sum()),'benign_calibration_windows':int(calibration.sum()),
             'calibration_target':config['false_positive_target'],
             'warning':'Adjacent Tuesday intervals may share an attack episode. Not a final holdout study.'}
    conn.execute('INSERT INTO experiment_run VALUES (%s,%s,now(),%s,%s,%s,%s)',
                 (experiment_id,feature_id,'development_only',file_hash(out/'development_protocol.json'),Jsonb(artifacts),Jsonb(summary)))
    for method,scale in scales.items():
        conn.execute('INSERT INTO rule_version VALUES (%s,%s,%s,%s)',(experiment_id,method,scale,cutoffs[method]))
    with conn.cursor().copy('COPY prediction FROM STDIN') as copy:
        for row in data.itertuples(index=False):
            for method in methods:
                score=float(getattr(row,method))
                copy.write_row((experiment_id,feature_id,row.src_ip,row.window_start.to_pydatetime(),
                                method,row.split,score,score>=cutoffs[method]))
    conn.commit()
    (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    (out/'artifact_manifest.json').write_text(json.dumps(artifacts,indent=2),encoding='utf-8')
    return experiment_id,data,result_frame,summary

