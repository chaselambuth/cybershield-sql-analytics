"""Matched development comparison reusing fixed candidates, cutoffs and metrics."""
from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
import platform
import time

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import psutil
from sklearn.base import clone
from threadpoolctl import threadpool_limits

from .evaluate import FEATURES, calibrate, metrics
from .protocol import ROLES, support, write_support
from .research import candidates, pareto_flags, response


def dump(path, value):
    def safe(item):
        if isinstance(item,dict):return {key:safe(value) for key,value in item.items()}
        if isinstance(item,(list,tuple)):return [safe(value) for value in item]
        if isinstance(item,(float,np.floating)) and not np.isfinite(item):return str(item)
        return item
    # NaN is a legitimate estimator missing_values parameter, not a measured metric.
    path.write_text(json.dumps(safe(value),indent=2,default=str,allow_nan=False),encoding='utf-8')


def as_scores(values, expected):
    # Explicit promotion BEFORE threshold comparisons avoids NumPy float32 scalar
    # coercion at a float64 nextafter cutoff. Native values themselves are preserved.
    values=np.asarray(values,dtype=np.float64)
    if values.shape!=(expected,) or not np.isfinite(values).all():
        raise ValueError('Every method must score the same complete finite population')
    return values


def rule_scales(data, config):
    benign=data.role.eq('train')&data.known&~data.is_attack
    if not benign.any():raise ValueError('No training-benign rule reference')
    return {name:max(1.,float(data.loc[benign,column].quantile(config['rule_reference_quantile'])))
            for name,column in [('volume_scale','flow_count'),('ports_scale','unique_ports'),('services_scale','service_flows')]}


def numpy_rule_reference(data, scales):
    """Synthetic-test oracle only; the real runner calls the registered PostgreSQL SQL."""
    return np.maximum.reduce([data.flow_count.to_numpy(float)/scales['volume_scale'],
        np.where(data.flow_count.to_numpy()>=10,data.unique_ports.to_numpy(float)/scales['ports_scale'],0.),
        data.service_flows.to_numpy(float)/scales['services_scale']])


def verify_scores(folder):
    folder=Path(folder)
    scores=pd.read_csv(folder/'scores.csv',float_precision='round_trip')
    cuts=pd.read_csv(folder/'cutoffs.csv',float_precision='round_trip')
    result=pd.read_csv(folder/'metrics.csv',float_precision='round_trip')
    if scores.duplicated(['src_ip','window_start']).any():raise ValueError('Duplicate scored population')
    for row in cuts.itertuples():
        calibration=scores.loc[scores.role.eq('calibration')&~scores.is_attack,row.method].to_numpy(float)
        if len(calibration)!=row.calibration_benign_windows:
            raise ValueError('Calibration denominator changed')
        actual=int((calibration>=row.cutoff).sum())
        if actual!=row.calibration_false_alerts or actual>row.calibration_allowed_false_alerts:
            raise ValueError('Round-trip score/cutoff calibration reconciliation failed')
        for role in ROLES:
            part=scores.loc[scores.role.eq(role)]
            found=result.loc[result.method.eq(row.method)&result.target.eq(row.target)&result.role.eq(role)]
            if len(found)!=1:raise ValueError('Missing/duplicate matched metric row')
            expected=metrics(part.is_attack,part[row.method],row.cutoff)
            for name in ['windows','positives','negatives','tp','fp','tn','fn','alerts']:
                if int(found.iloc[0][name])!=expected[name]:raise ValueError('Exact confusion-count mismatch')
            for name in ['precision','recall','f1','false_positives_per_1000','average_precision','roc_auc']:
                observed=found.iloc[0][name]
                if expected[name] is None:
                    if not pd.isna(observed):raise ValueError('Undefined metric was replaced')
                elif not np.isclose(float(observed),expected[name],rtol=1e-12,atol=1e-14):
                    raise ValueError(f'Recomputed metric differs: {name}')
    methods=set(cuts.method)
    if set(result.method)!=methods or any(result.groupby(['role','target']).windows.nunique()!=1):
        raise ValueError('Compared methods do not have identical denominators')
    return True


def subgroup_metrics(data, scores, cutoffs, config, output):
    primary={r['method']:r['cutoff'] for r in cutoffs if r['target']==config['false_positive_target']}
    known=data.loc[data.known&data.role.eq('validation')].copy()
    known['row_id']=known.index
    for grouping in ['day','src_ip','dependency_block','episode_groups']:
        grouped=known
        if grouping=='episode_groups':
            grouped=known.explode('episode_groups').dropna(subset=['episode_groups'])
        rows=[]
        for key,part in grouped.groupby(grouping):
            ids=part.row_id.to_numpy()
            for method,cutoff in primary.items():
                rows.append({'group':key,'method':method,**metrics(part.is_attack,scores[method][ids],cutoff),
                             'note':'overlapping episode memberships are not additive' if grouping=='episode_groups' else 'descriptive correlated windows'})
        pd.DataFrame(rows).to_csv(output/f'validation_by_{grouping}.csv',index=False,float_format='%.17g')
    # Family views explicitly include only windows carrying that family. They are
    # positive-support/recall views, not per-family false-positive-rate populations.
    family_rows=[]
    exploded=known.explode('episode_groups').dropna(subset=['episode_groups'])
    if not exploded.empty:
        exploded['family']=exploded.episode_groups.map(lambda x:json.loads(x)[2])
        for name,part in exploded.groupby('family'):
            part=part.drop_duplicates('row_id');ids=part.row_id.to_numpy()
            for method,cutoff in primary.items():
                family_rows.append({'family':name,'method':method,'windows_with_family':len(part),
                    'known_positive_windows':int(part.is_attack.sum()),
                    'caught_positive_windows':int((part.is_attack.to_numpy()&(scores[method][ids]>=cutoff)).sum()),
                    'note':'unknown-contaminated windows excluded; multi-family windows may appear in multiple rows'})
    pd.DataFrame(family_rows).to_csv(output/'validation_family_support.csv',index=False)
    validation=data.known&data.role.eq('validation');y=data.loc[validation,'is_attack'].to_numpy()
    decisions={name:values[validation]>=primary[name] for name,values in scores.items()}
    paired=[];names=list(decisions)
    for i,left in enumerate(names):
        for right in names[i+1:]:
            a,b=decisions[left],decisions[right]
            paired.append({'left':left,'right':right,'positive_windows':int(y.sum()),'benign_windows':int((~y).sum()),
                'both_catch':int((a&b&y).sum()),'left_only_catch':int((a&~b&y).sum()),
                'right_only_catch':int((~a&b&y).sum()),'both_miss':int((~a&~b&y).sum()),
                'both_false_alert':int((a&b&~y).sum()),'left_only_false_alert':int((a&~b&~y).sum()),
                'right_only_false_alert':int((~a&b&~y).sum())})
    pd.DataFrame(paired).to_csv(output/'paired_primary_overlap.csv',index=False)
    table=data.loc[validation,['src_ip','window_start','is_attack']].copy()
    for name,values in decisions.items():table[name]=values
    table.to_csv(output/'validation_primary_decisions.csv',index=False)


def run_benchmark(data, config, output, sql_scorer, run_id, *, model_factory=None, synthetic=False):
    """Model-factory override is for labeled synthetic tests, never the real CLI."""
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    data=data.copy().reset_index(drop=True)
    gate=write_support(data,config,output)
    if not gate['passed']:
        result={'status':'blocked_support','run_id':run_id,'reasons':gate['reasons'],
                'performance_claim':'none; no model was fitted','mlp':'deferred'}
        dump(output/'status.json',result)
        return result
    X=data[FEATURES].to_numpy(dtype=float)
    if np.isinf(X).any() or np.any(X<0):raise ValueError('Features must be nonnegative finite or missing')
    train=data.known&data.role.eq('train')
    calibration=data.known&data.role.eq('calibration')&~data.is_attack
    validation=data.known&data.role.eq('validation')
    y=data.is_attack.to_numpy(bool);Xtrain=X[train];ytrain=y[train]
    if np.isnan(Xtrain).all(axis=0).any():raise ValueError('A training feature is entirely missing')
    seed=config['seed'];rng=np.random.default_rng(seed)
    factory=model_factory or candidates
    models=factory(seed,float((~ytrain).sum()/ytrain.sum()))
    if model_factory is None and list(models)!=config['models']:
        raise ValueError('Candidate registry differs from registered design')
    dump(output/'model_parameters.json',{name:m.get_params(deep=True) for name,m in models.items()})
    scales=rule_scales(data,config);dump(output/'training_rule_scales.json',scales)
    fits=[];timings=[];fitted={};scores={};native={}
    with threadpool_limits(limits=1):
        for repeat in range(config['timing']['fit_repeats']):
            for name in rng.permutation(list(models)):
                model=clone(models[name]);started=time.perf_counter_ns();model.fit(Xtrain,ytrain)
                fits.append({'method':name,'repeat':repeat,'fit_ms':(time.perf_counter_ns()-started)/1e6})
                fitted[name]=model
        for name in models:
            raw=response(fitted[name],X)
            native[name]=str(np.asarray(raw).dtype)
            scores[name]=as_scores(raw,len(data))
        sizes=list(dict.fromkeys([*config['timing']['batch_sizes'],int(validation.sum())]))
        Xval=X[validation]
        for size in sizes:
            # Sampling with replacement supports small synthetic fixtures while keeping
            # the same requested batch size for every candidate; full population is exact.
            reps=config['timing']['single_repeats'] if size==1 else config['timing']['batch_repeats']
            batches=[np.ascontiguousarray(Xval if size==len(Xval) else Xval[rng.choice(len(Xval),size,replace=size>len(Xval))]) for _ in range(reps)]
            for scope in ['pipeline','model_only']:
                transformed={name:[model[:-1].transform(b) for b in batches] for name,model in fitted.items()} if scope=='model_only' else None
                for name,model in fitted.items():
                    for _ in range(config['timing']['warmup_calls']):
                        response(model if scope=='pipeline' else model[-1],batches[0] if scope=='pipeline' else transformed[name][0])
                for repeat,batch in enumerate(batches):
                    for name in rng.permutation(list(models)):
                        model=fitted[name] if scope=='pipeline' else fitted[name][-1]
                        values=batch if scope=='pipeline' else transformed[name][repeat]
                        started=time.perf_counter_ns();response(model,values);elapsed=(time.perf_counter_ns()-started)/1e6
                        timings.append({'method':name,'scope':scope,'batch_size':size,'repeat':repeat,'milliseconds':elapsed})
    started=time.perf_counter_ns()
    scores['sql_combined']=as_scores(sql_scorer(scales),len(data))
    sql_ms=(time.perf_counter_ns()-started)/1e6
    scores['always_benign']=np.zeros(len(data),dtype=float)
    native.update(sql_combined='float64',always_benign='float64')
    # Derive all cutoffs exclusively from known-benign calibration scores.
    cuts=[];results=[]
    for target in [config['false_positive_target'],*config['sensitivity_targets']]:
        for name,values in scores.items():
            cutoff=1. if name=='always_benign' else calibrate(values[calibration],target)
            count=int(calibration.sum());actual=int((values[calibration]>=cutoff).sum());allowed=int(np.floor(target*count))
            if actual>allowed:raise ValueError('Empirical calibration allowance violated')
            cuts.append({'method':name,'target':target,'cutoff':cutoff,'native_response_dtype':native[name],
                         'comparison_dtype':'float64','calibration_benign_windows':count,
                         'calibration_false_alerts':actual,'calibration_allowed_false_alerts':allowed,
                         'calibration_distinct_scores':int(np.unique(values[calibration]).size)})
            for role in ROLES:
                mask=data.known&data.role.eq(role)
                results.append({'role':role,'target':target,'method':name,**metrics(y[mask],values[mask],cutoff)})
    selected=data.known&data.role.isin(ROLES)
    score_table=data.loc[selected,['src_ip','window_start','role','is_attack']].copy()
    for name,values in scores.items():score_table[name]=values[selected]
    score_table.to_csv(output/'scores.csv',index=False,float_format='%.17g')
    pd.DataFrame(cuts).to_csv(output/'cutoffs.csv',index=False,float_format='%.17g')
    metric_table=pd.DataFrame(results);metric_table.to_csv(output/'metrics.csv',index=False,float_format='%.17g')
    pd.DataFrame(fits).to_csv(output/'raw_fit_times.csv',index=False,float_format='%.17g')
    timing=pd.DataFrame(timings);timing.to_csv(output/'raw_latency.csv',index=False,float_format='%.17g')
    latency=timing.groupby(['method','scope','batch_size']).milliseconds.agg(
        repetitions='size',median_ms='median',p95_ms=lambda x:float(np.quantile(x,.95))).reset_index()
    latency.to_csv(output/'latency_by_batch.csv',index=False,float_format='%.17g')
    quality=metric_table.loc[metric_table.role.eq('validation')&metric_table.target.eq(.01)].copy()
    single=latency.loc[latency.scope.eq('pipeline')&latency.batch_size.eq(1),['method','median_ms','p95_ms']]
    quality=quality.merge(single.rename(columns={'p95_ms':'single_pipeline_p95_ms','median_ms':'single_pipeline_median_ms'}),on='method',how='left',validate='one_to_one')
    quality=quality.merge(pd.DataFrame(fits).groupby('method').fit_ms.median().rename('median_fit_ms'),on='method',how='left')
    quality['pareto_observed']=pd.NA
    timed=quality.single_pipeline_p95_ms.notna()
    quality.loc[timed,'pareto_observed']=pareto_flags(quality.loc[timed])
    quality.to_csv(output/'quality_latency.csv',index=False,float_format='%.17g')
    subgroup_metrics(data,scores,cuts,config,output)
    (output/'models').mkdir()
    for i,(name,model) in enumerate(fitted.items()):joblib.dump(model,output/'models'/f'{i:02d}.joblib')
    fitted_parameters={name:{'imputer_medians':model[0].statistics_.tolist(),
        'scaler_mean':next((step.mean_.tolist() for step in model if hasattr(step,'mean_')),None)} for name,model in fitted.items()}
    dump(output/'fitted_preprocessing.json',fitted_parameters)
    versions={p:importlib.metadata.version(p) for p in ['numpy','pandas','scikit-learn','xgboost','lightgbm','catboost','threadpoolctl']}
    dump(output/'environment.json',{'python':platform.python_version(),'os':platform.platform(),'cpu':platform.processor(),
         'physical_cpus':psutil.cpu_count(logical=False),'logical_cpus':psutil.cpu_count(),
         'ram_bytes':psutil.virtual_memory().total,'versions':versions,'seed':seed,'threads':1,
         'timing':'Warm CPU calls; excludes SQL feature construction/retrieval, loading, network, HTTP, serialization, cold starts, flow export and window wait.',
         'sql_score_query_wall_ms':sql_ms,'sql_timing_note':'One full-population rule query including adapter overhead; not comparable to single-window warm estimator P95.',
         'synthetic_test':synthetic or model_factory is not None,'native_score_dtypes':native,
         'uncertainty':'No independent-episode confidence interval; source/day proxies do not prove independence.'})
    fig,axes=plt.subplots(1,2,figsize=(12,5))
    axes[0].scatter(quality.fp,quality.tp)
    for row in quality.itertuples():axes[0].annotate(row.method,(row.fp,row.tp),fontsize=7,xytext=(3,3),textcoords='offset points')
    axes[0].set(xlabel='False alerts among known benign validation windows',ylabel='Caught positive validation windows',title='Matched 1% benign calibration budget')
    axes[1].barh(single.method,single.p95_ms);axes[1].set(xlabel='Warm CPU pipeline P95 milliseconds',title='Scoring only; no end-to-end latency claim')
    fig.suptitle('Development/validation only - correlated campaign proxies');fig.tight_layout()
    fig.savefig(output/'comparison.png',dpi=160);plt.close(fig)
    verify_scores(output)
    result={'status':'completed_synthetic_validation' if synthetic or model_factory is not None else 'completed_development_validation','run_id':run_id,'methods':list(scores),
            'validation_windows':int(validation.sum()),'validation_positive_windows':int(y[validation].sum()),
            'budgets':[config['false_positive_target'],*config['sensitivity_targets']],
            'no_final_test':True,'mlp':'deferred','support_warning':gate['independence']}
    dump(output/'status.json',result)
    (output/'findings.md').write_text('# Corrected development/validation comparison\n\n'
        +f"Run `{run_id}`. This is a new study, separate from historical Tuesday identities.\n\n"
        +quality[['method','positives','negatives','tp','fp','tn','fn','alerts']].to_csv(index=False)
        +'\nAll rows use the same known-label validation windows and prespecified benign calibration budgets. '
        +'The support gate permits descriptive comparison; it does not verify independence. '
        +'Families can share an actor, capture environment and window. No confidence intervals, pristine final holdout, '
        +'production detection, measured analyst hours saved or autonomous remediation are claimed. '
        +'Optional neural training remains deferred. SQL and ML are separate methods.\n',encoding='utf-8')
    return result
