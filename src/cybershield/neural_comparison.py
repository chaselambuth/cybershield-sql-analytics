"""Revised matched comparison: replace two classical models with neural models."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import time
import warnings

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import psutil
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.exceptions import ConvergenceWarning
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from .db import ROOT, file_hash
from .evaluate import FEATURES, calibrate, metrics
from .research import candidates, response
from .study import code_files, safe_new_output
from .study_benchmark import verify_scores


def save(path, value):
    path.write_text(json.dumps(value, indent=2, default=str, allow_nan=False)+'\n', encoding='utf-8', newline='\n')


class NeuralMLP(ClassifierMixin, BaseEstimator):
    def __init__(self, random_state=1729, hidden_layer_sizes=(32, 16), max_iter=200):
        self.random_state = random_state
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter

    def fit(self, X, y):
        self.network_ = MLPClassifier(hidden_layer_sizes=self.hidden_layer_sizes, activation='relu',
            solver='adam', alpha=.001, batch_size=64, learning_rate_init=.001,
            max_iter=self.max_iter, early_stopping=False, n_iter_no_change=20, tol=1e-4,
            random_state=self.random_state)
        self.network_.fit(X, y, sample_weight=compute_sample_weight('balanced', y))
        self.classes_ = self.network_.classes_
        self.training_rows_ = len(X)
        return self

    def predict_proba(self, X):
        return self.network_.predict_proba(X)


class NeuralAutoencoder(BaseEstimator):
    def __init__(self, random_state=1729, hidden_layer_sizes=(16, 4, 16), max_iter=200):
        self.random_state = random_state
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter

    def fit(self, X, y):
        benign = np.asarray(X)[~np.asarray(y, dtype=bool)]
        self.network_ = MLPRegressor(hidden_layer_sizes=self.hidden_layer_sizes, activation='relu',
            solver='adam', alpha=.001, batch_size=64, learning_rate_init=.001,
            max_iter=self.max_iter, early_stopping=False, n_iter_no_change=20, tol=1e-4,
            random_state=self.random_state)
        self.network_.fit(benign, benign)
        self.training_rows_ = len(benign)
        return self

    def decision_function(self, X):
        return np.mean((np.asarray(X)-self.network_.predict(X))**2, axis=1)


def revised_candidates(config, positive_weight):
    models = candidates(config['seed'], positive_weight)
    for name in config['replaced_models']:
        models.pop(name)
    def neural(estimator):
        return make_pipeline(SimpleImputer(strategy='median'), FunctionTransformer(np.log1p),
                             StandardScaler(), estimator)
    models['Neural MLP'] = neural(NeuralMLP(config['seed'], tuple(config['neural']['classifier_hidden_layers']), config['neural']['max_iter']))
    models['Neural autoencoder'] = neural(NeuralAutoencoder(config['seed'], tuple(config['neural']['autoencoder_hidden_layers']), config['neural']['max_iter']))
    if list(models) != config['models']:
        raise ValueError('Model roster differs from the revised protocol')
    return models


def load_parent(parent, config):
    if file_hash(parent/'registration.json') != config['parent_design_sha256'] or file_hash(parent/'prepared.json') != config['parent_prepared_sha256']:
        raise ValueError('Parent design or prepared input receipt changed')
    design = json.loads((parent/'registration.json').read_text())
    prepared = json.loads((parent/'prepared.json').read_text())
    if prepared['design_sha256'] != config['parent_design_sha256'] or prepared['run_id'] != design['run_id']:
        raise ValueError('Parent input identity does not match its design')
    if file_hash(parent/'protocol.json') != design['protocol_sha256']:
        raise ValueError('Parent protocol changed')
    # Consume the frozen prepared table, not a re-execution of the old adapter.
    # Verify its archived source bytes even if current project code has evolved.
    for name, digest in design['code_files'].items():
        if file_hash(parent/'source_code'/name) != digest:
            raise ValueError(f'Parent archived source changed: {name}')
    for name, digest in prepared['files'].items():
        if file_hash(parent/'prepared'/name) != digest:
            raise ValueError(f'Parent prepared input changed: {name}')
    data = pd.read_csv(parent/'prepared/windows.csv', float_precision='round_trip')
    receipt = json.loads((parent/'benchmark_registration.json').read_text())
    if receipt['design_sha256'] != config['parent_design_sha256'] or receipt['prepared_sha256'] != config['parent_prepared_sha256']:
        raise ValueError('Parent benchmark does not match its prepared population')
    for name, digest in receipt['files'].items():
        if file_hash(parent/'benchmark'/name) != digest:
            raise ValueError(f'Parent benchmark changed: {name}')
    selected = data.loc[data.known & data.role.isin(['train','calibration','validation'])].copy()
    old = pd.read_csv(parent/'benchmark/scores.csv', float_precision='round_trip')
    keys = ['src_ip','window_start','role','is_attack']
    selected = selected.merge(old[keys+['sql_combined']], on=keys, how='left', validate='one_to_one')
    if len(selected) != len(old) or selected.sql_combined.isna().any():
        raise ValueError('Revised comparison does not match parent scoring windows')
    return selected.reset_index(drop=True), old


def register(parent, config_path, output):
    config = json.loads(config_path.read_text())
    data, _ = load_parent(parent, config)
    revised_candidates(config, 1.)  # Validate the complete roster before fitting.
    output = safe_new_output(output)
    (output/'protocol.json').write_bytes(config_path.read_bytes())
    files = [*code_files(), Path(__file__), ROOT/'requirements.lock']
    code = {p.relative_to(ROOT).as_posix(): file_hash(p) for p in files}
    versions = {p:importlib.metadata.version(p) for p in ['numpy','pandas','scikit-learn','xgboost','lightgbm','catboost','threadpoolctl']}
    value = {'kind':'cybershield_neural_comparison_v1', 'created_utc':datetime.now(timezone.utc).isoformat(),
             'status':config['status'], 'parent_study':parent.relative_to(ROOT).as_posix(),
             'parent_prepared_sha256':file_hash(parent/'prepared.json'),
             'parent_benchmark_registration_sha256':file_hash(parent/'benchmark_registration.json'),
             'protocol_sha256':file_hash(output/'protocol.json'), 'code_files':code, 'versions':versions,
             'windows':len(data), 'support':data.groupby('role').is_attack.agg(['size','sum']).to_dict(),
             'prior_access':config['replacement_reason'],
             'input_reuse':'Byte-verified parent prepared windows and role assignments; original archived source verified. No re-ingestion or split reassignment.',
             'registration_note':'Local hash receipt before new fits; not an external seal or a new independent holdout.'}
    save(output/'registration.json', value)
    expected = file_hash(output/'registration.json')
    (output/'registration.sha256').write_text(expected+'\n', encoding='ascii')
    print(json.dumps({'registration_sha256':expected,'output':str(output)}), flush=True)


def verify_registration(output, expected, *, check_parent=True):
    if file_hash(output/'registration.json') != expected:
        raise ValueError('Registration hash differs from the supplied expected hash')
    registration = json.loads((output/'registration.json').read_text())
    config = json.loads((output/'protocol.json').read_text())
    if file_hash(output/'protocol.json') != registration['protocol_sha256']:
        raise ValueError('Revised protocol changed after registration')
    for name, digest in registration['code_files'].items():
        if file_hash(ROOT/name) != digest:
            raise ValueError(f'Registered source changed: {name}')
    for package, version in registration['versions'].items():
        if importlib.metadata.version(package) != version:
            raise ValueError(f'Registered dependency changed: {package}')
    parent = ROOT/registration['parent_study']
    if check_parent and file_hash(parent/'benchmark_registration.json') != registration['parent_benchmark_registration_sha256']:
        raise ValueError('Parent benchmark registration changed')
    return config, parent, registration


def draw_figures(quality, output):
    names = quality.method.replace({'sql_combined':'Combined SQL rule','always_benign':'Always benign'})
    colors = ['#b09aff' if name.startswith('Neural') else '#147e88' for name in quality.method]
    fig, axes = plt.subplots(1, 2, figsize=(13, 6), sharey=True)
    for ax, column, title in zip(axes, ['tp','fp'], ['Caught positive windows / 21','False alerts / 2,464 benign windows']):
        ax.barh(names, quality[column], color=colors)
        ax.bar_label(ax.containers[0], padding=4, fontsize=9)
        ax.set_title(title, fontsize=11); ax.set_xlim(0, max(quality[column].max()*1.15, 1))
        ax.grid(axis='x', alpha=.15); ax.set_axisbelow(True); ax.spines[['top','right']].set_visible(False)
    axes[0].invert_yaxis()
    fig.suptitle('Corrected four-day study: revised model comparison', fontsize=15)
    fig.text(.02,.025,'Same validation windows and 1% benign-calibration budget. Correlated windows; no independent final holdout.',fontsize=9)
    fig.tight_layout(rect=(0,.065,1,.94)); fig.savefig(output/'comparison.png',dpi=170); plt.close(fig)
    timed = quality.dropna(subset=['single_pipeline_p95_ms'])
    fig, ax = plt.subplots(figsize=(11, 5))
    ypos = np.arange(len(timed)); height = .36
    ax.barh(ypos-height/2, timed.single_pipeline_median_ms, height, label='Median', color='#147e88')
    ax.barh(ypos+height/2, timed.single_pipeline_p95_ms, height, label='P95', color='#9a7cda')
    ax.set_yticks(ypos, timed.method); ax.invert_yaxis(); ax.set_xscale('log')
    ax.set_xlabel('Milliseconds per warm CPU call, including preprocessing (log scale)')
    ax.set_title('Revised comparison: single-window inference latency'); ax.legend(); ax.grid(axis='x',alpha=.15)
    ax.spines[['top','right']].set_visible(False)
    fig.text(.02,.015,'One requested CPU thread; 5 warm-ups and 60 calls per model. SQL/network/window waiting excluded.',fontsize=9)
    fig.tight_layout(rect=(0,.045,1,1)); fig.savefig(output/'latency.png',dpi=170); plt.close(fig)


def run(output, expected):
    config, parent, registration = verify_registration(output, expected)
    if (output/'metrics.csv').exists():
        raise ValueError('Results already exist; create a new registration for another run')
    data, old = load_parent(parent, config)
    train = data.role.eq('train').to_numpy(); calibration = data.role.eq('calibration').to_numpy()
    validation = data.role.eq('validation').to_numpy(); y = data.is_attack.to_numpy(bool)
    X = data[FEATURES].to_numpy(float)
    models = revised_candidates(config, float((~y[train]).sum()/y[train].sum()))
    fits, timings, fitted, convergence = [], [], {}, []
    rng = np.random.default_rng(config['seed']); timing = config['timing']
    with threadpool_limits(limits=timing['threads']):
        for repeat in range(timing['fit_repeats']):
            for name in rng.permutation(list(models)):
                model = clone(models[name]); started = time.perf_counter_ns()
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always', ConvergenceWarning)
                    model.fit(X[train], y[train])
                elapsed = (time.perf_counter_ns()-started)/1e6
                fits.append({'method':name,'repeat':repeat,'fit_ms':elapsed})
                convergence.extend({'method':name,'repeat':repeat,'category':type(w.message).__name__,'message':str(w.message)} for w in caught)
                fitted[name] = model
                print(f'Fit {repeat+1}/{timing["fit_repeats"]}: {name} ({elapsed:.1f} ms; {len(caught)} warnings)',flush=True)
        scores = {name:np.asarray(response(fitted[name],X),dtype=np.float64) for name in models}
        scores.update(sql_combined=data.sql_combined.to_numpy(float), always_benign=np.zeros(len(data)))
        if any(values.shape != (len(data),) or not np.isfinite(values).all() for values in scores.values()):
            raise ValueError('A method did not return complete finite matched scores')
        Xval = X[validation]
        for size in [*timing['batch_sizes'],len(Xval)]:
            repetitions = timing['single_repeats'] if size == 1 else timing['batch_repeats']
            batches = [np.ascontiguousarray(Xval if size == len(Xval) else Xval[rng.choice(len(Xval),size,replace=False)]) for _ in range(repetitions)]
            for scope in ['pipeline','model_only']:
                transformed = {name:[model[:-1].transform(b) for b in batches] for name,model in fitted.items()} if scope == 'model_only' else None
                for name,model in fitted.items():
                    for _ in range(timing['warmup_calls']):
                        response(model if scope == 'pipeline' else model[-1], batches[0] if scope == 'pipeline' else transformed[name][0])
                for repeat,batch in enumerate(batches):
                    for name in rng.permutation(list(models)):
                        model = fitted[name] if scope == 'pipeline' else fitted[name][-1]
                        values = batch if scope == 'pipeline' else transformed[name][repeat]
                        started = time.perf_counter_ns(); prediction = response(model,values)
                        elapsed = (time.perf_counter_ns()-started)/1e6
                        if not np.isfinite(prediction).all() or len(prediction) != size:
                            raise ValueError('Invalid timed predictions')
                        timings.append({'method':name,'scope':scope,'batch_size':size,'repeat':repeat,'milliseconds':elapsed})
    score_table = data[['src_ip','window_start','role','is_attack']].copy()
    for name, values in scores.items():
        score_table[name] = values
    score_table.to_csv(output/'scores.csv', index=False, float_format='%.17g')
    cuts, results = [], []
    for target in [config['false_positive_target'],*config['sensitivity_targets']]:
        for name, values in scores.items():
            benign_calibration = calibration & ~y
            cutoff = 1. if name == 'always_benign' else calibrate(values[benign_calibration],target)
            actual = int((values[benign_calibration]>=cutoff).sum()); allowed = int(np.floor(target*benign_calibration.sum()))
            if actual > allowed:
                raise ValueError('Calibration allowance exceeded')
            cuts.append({'method':name,'target':target,'cutoff':cutoff,'calibration_benign_windows':int(benign_calibration.sum()),
                         'calibration_false_alerts':actual,'calibration_allowed_false_alerts':allowed})
            for role in ['train','calibration','validation']:
                mask = data.role.eq(role).to_numpy()
                results.append({'role':role,'target':target,'method':name,**metrics(y[mask],values[mask],cutoff)})
    pd.DataFrame(cuts).to_csv(output/'cutoffs.csv',index=False,float_format='%.17g')
    result_table = pd.DataFrame(results)
    result_table.to_csv(output/'metrics.csv',index=False,float_format='%.17g')
    fit_table, raw = pd.DataFrame(fits), pd.DataFrame(timings)
    fit_table.to_csv(output/'raw_fit_times.csv',index=False,float_format='%.17g')
    raw.to_csv(output/'raw_latency.csv',index=False,float_format='%.17g')
    latency = raw.groupby(['method','scope','batch_size']).milliseconds.agg(repetitions='size',median_ms='median',p95_ms=lambda values:float(np.quantile(values,.95))).reset_index()
    latency.to_csv(output/'latency_by_batch.csv',index=False,float_format='%.17g')
    single = latency.loc[latency.scope.eq('pipeline') & latency.batch_size.eq(1)].rename(columns={'median_ms':'single_pipeline_median_ms','p95_ms':'single_pipeline_p95_ms'})
    quality = result_table.loc[result_table.role.eq('validation') & result_table.target.eq(config['false_positive_target'])]
    quality = quality.merge(single[['method','single_pipeline_median_ms','single_pipeline_p95_ms']],on='method',how='left')
    quality = quality.merge(fit_table.groupby('method').fit_ms.median().rename('median_fit_ms'),on='method',how='left')
    quality.to_csv(output/'quality_latency.csv',index=False,float_format='%.17g')
    save(output/'fit_warnings.json', convergence)
    neural_state = {}
    model_index = {}
    (output/'models').mkdir()
    for i,(name,model) in enumerate(fitted.items()):
        model_path = output/f'models/{i:02d}.joblib'
        joblib.dump(model, model_path)
        restored = joblib.load(model_path)
        with threadpool_limits(limits=timing['threads']):
            reproduced = response(restored, X)
        if not np.array_equal(reproduced, scores[name]):
            raise ValueError(f'Serialized model does not reproduce saved scores: {name}')
        model_index[name] = {'file':f'models/{i:02d}.joblib','sha256':file_hash(model_path),
                             'bytes':model_path.stat().st_size,'saved_scores_reproduced':True}
        if name.startswith('Neural'):
            network = model[-1].network_
            neural_state[name] = {'hidden_layers':list(network.hidden_layer_sizes),'iterations':int(network.n_iter_),
                'loss':float(network.loss_),'training_rows':model[-1].training_rows_,
                'parameters':network.get_params(),'loss_curve':[float(v) for v in network.loss_curve_]}
    save(output/'neural_fit_state.json',neural_state)
    save(output/'model_artifact_index.json',model_index)
    reference = score_table.merge(old,on=['src_ip','window_start','role','is_attack'],suffixes=('_revised','_parent'),validate='one_to_one')
    reconciliation = {name:{'exact_scores':bool(np.array_equal(reference[name+'_revised'],reference[name+'_parent'])),
        'maximum_absolute_difference':float(np.max(np.abs(reference[name+'_revised']-reference[name+'_parent'])))}
        for name in models if not name.startswith('Neural')}
    save(output/'retained_model_reconciliation.json',reconciliation)
    save(output/'environment.json',{'created_utc':datetime.now(timezone.utc).isoformat(), 'os':platform.platform(),
        'python':platform.python_version(),'cpu':platform.processor(),'logical_cpus':psutil.cpu_count(),
        'physical_cpus':psutil.cpu_count(logical=False),'ram_bytes':psutil.virtual_memory().total,
        'threads':timing['threads'],'versions':registration['versions'],
        'scope':'Warm CPU pipeline/model-only response calls; excludes SQL, HTTP, loading, serialization and window waiting.'})
    verify_scores(output)
    draw_figures(quality,output)
    manifest = {p.relative_to(output).as_posix():file_hash(p) for p in output.rglob('*') if p.is_file() and p.suffix != '.joblib' and p.name != 'result_manifest.json'}
    save(output/'result_manifest.json',{'registration_sha256':expected,'status':config['status'],
                                      'local_models':'Weights are ignored; their hashes and verified score reproduction are recorded in model_artifact_index.json.',
                                      'files':manifest})
    print(quality[['method','tp','fp','single_pipeline_median_ms','single_pipeline_p95_ms']].to_string(index=False),flush=True)


def verify(output, expected):
    verify_registration(output, expected, check_parent=False)
    manifest = json.loads((output/'result_manifest.json').read_text())
    if manifest['registration_sha256'] != expected:
        raise ValueError('Results belong to a different registration')
    for name,digest in manifest['files'].items():
        path = (output/name).resolve()
        if not path.is_relative_to(output.resolve()) or file_hash(path) != digest:
            raise ValueError(f'Result artifact changed: {name}')
    verify_scores(output)
    print(f'Verified {len(manifest["files"])} registered result files and all matched confusion counts.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command',required=True)
    registration = subs.add_parser('register')
    registration.add_argument('--parent',type=Path,required=True)
    registration.add_argument('--config',type=Path,default=ROOT/'configs/neural_comparison_v1.json')
    registration.add_argument('--output',type=Path,default=ROOT/'reports/neural_comparison_v1')
    for name in ['run','verify']:
        sub = subs.add_parser(name); sub.add_argument('--output',type=Path,default=ROOT/'reports/neural_comparison_v1')
        sub.add_argument('--registration-sha256',required=True)
    args = parser.parse_args()
    if args.command == 'register':
        register(args.parent.resolve(),args.config.resolve(),args.output.resolve())
    else:
        (run if args.command == 'run' else verify)(args.output.resolve(),args.registration_sha256)


if __name__ == '__main__':
    main()
