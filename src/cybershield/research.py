"""Offline, development-only model comparisons; never writes to PostgreSQL."""
from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import platform
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psutil
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits

from .db import ROOT, file_hash
from .evaluate import FEATURES, calibrate, metrics

RESEARCH = ROOT / 'reports' / 'research'


def load_snapshot():
    folder = RESEARCH / 'snapshot'
    manifest = json.loads((folder / 'manifest.json').read_text())
    for name, digest in manifest['files'].items():
        if file_hash(folder / name) != digest:
            raise ValueError(f'Frozen research input changed: {name}')
    data = pd.read_csv(folder / 'window_scores.csv', parse_dates=['window_start'])
    protocol = json.loads((folder / 'development_protocol.json').read_text())
    if data.duplicated(['src_ip', 'window_start']).any():
        raise ValueError('Duplicate scoring entities in frozen snapshot')
    return data, protocol, manifest


def split_masks(data, config):
    """Validate frozen role assignments against the original chronological protocol."""
    known = data.unknown_flows.eq(0)
    masks = {}
    for role in ['train', 'calibration', 'development']:
        start, end = map(pd.Timestamp, config['splits'][role])
        expected = data.window_start.ge(start) & data.window_start.lt(end)
        if not expected.equals(data.split.eq(role)):
            raise ValueError(f'Split assignment mismatch: {role}')
        masks[role] = expected & known
    if pd.DataFrame(masks).sum(axis=1).gt(1).any():
        raise ValueError('Overlapping experiment populations')
    if data.loc[masks['train'], 'attack_flows'].gt(0).nunique() != 2:
        raise ValueError('Training requires both classes')
    masks['benign_calibration'] = masks['calibration'] & data.attack_flows.eq(0)
    if not masks['benign_calibration'].any():
        raise ValueError('No benign calibration windows')
    return masks


def candidates(seed, positive_weight):
    from catboost import CatBoostClassifier
    from lightgbm import LGBMClassifier
    from xgboost import XGBClassifier

    def linear(estimator):
        return make_pipeline(SimpleImputer(strategy='median'), FunctionTransformer(np.log1p),
                             StandardScaler(), estimator)
    def tree(estimator):
        return make_pipeline(SimpleImputer(strategy='median'), estimator)
    return {
        'Logistic regression': linear(LogisticRegression(C=1, class_weight='balanced',
            max_iter=2000, solver='lbfgs', random_state=seed)),
        'Linear SVM': linear(LinearSVC(C=1, class_weight='balanced', dual='auto',
            max_iter=10000, random_state=seed)),
        'Random forest': tree(RandomForestClassifier(n_estimators=200, max_depth=8,
            min_samples_leaf=5, class_weight='balanced', n_jobs=1, random_state=seed)),
        'Extra trees': tree(ExtraTreesClassifier(n_estimators=200, max_depth=8,
            min_samples_leaf=5, class_weight='balanced', n_jobs=1, random_state=seed)),
        'Histogram boosting': tree(HistGradientBoostingClassifier(max_iter=200, max_leaf_nodes=15,
            learning_rate=.05, min_samples_leaf=10, class_weight='balanced',
            early_stopping=False, random_state=seed)),
        'XGBoost': tree(XGBClassifier(n_estimators=200, max_depth=4, learning_rate=.05,
            min_child_weight=5, reg_lambda=1, tree_method='hist', device='cpu',
            scale_pos_weight=positive_weight, n_jobs=1, random_state=seed, eval_metric='logloss')),
        'LightGBM': tree(LGBMClassifier(n_estimators=200, num_leaves=15, max_depth=6,
            learning_rate=.05, min_child_samples=10, class_weight='balanced', n_jobs=1,
            random_state=seed, verbosity=-1, deterministic=True, force_col_wise=True)),
        'CatBoost': tree(CatBoostClassifier(iterations=200, depth=6, learning_rate=.05,
            auto_class_weights='Balanced', thread_count=1, random_seed=seed,
            task_type='CPU', verbose=False, allow_writing_files=False)),
    }


def response(model, X):
    if hasattr(model, 'predict_proba'):
        classes = list(model.classes_)
        return model.predict_proba(X)[:, classes.index(True)]
    return model.decision_function(X)


def pareto_flags(table):
    """Non-dominated in caught positives, false alerts and warm single-row P95."""
    values = table[['fn', 'fp', 'single_pipeline_p95_ms']].to_numpy(float)
    return np.array([not np.any(np.all(values <= row, axis=1) & np.any(values < row, axis=1))
                     for row in values])


def benchmark(data, protocol, output=None):
    output = Path(output or RESEARCH / 'models')
    output.mkdir(parents=True, exist_ok=True)
    cfg = protocol['config']; seed = cfg['seed']; masks = split_masks(data, cfg)
    X = data[FEATURES].to_numpy(dtype=float)
    if np.any(X < 0) or np.isinf(X).any():
        raise ValueError('Features must be nonnegative and finite or missing')
    y = data.attack_flows.gt(0).to_numpy()
    Xtrain, ytrain = X[masks['train']], y[masks['train']]
    Xdev, ydev = X[masks['development']], y[masks['development']]
    models = candidates(seed, (~ytrain).sum() / ytrain.sum())
    quality, fits, timings, fitted = [], [], [], {}
    params = {name: model.get_params(deep=True) for name, model in models.items()}
    (output / 'model_parameters.json').write_text(json.dumps(params, indent=2, default=str))
    rng = np.random.default_rng(seed)
    predictions = pd.DataFrame({'src_ip': data.loc[masks['development'], 'src_ip'].to_numpy(),
                                'window_start': data.loc[masks['development'], 'window_start'].to_numpy(),
                                'is_attack': ydev})
    # Three complete, independent fits per method, interleaved in seeded random order.
    with threadpool_limits(limits=1):
        for repeat in range(3):
            for name in rng.permutation(list(models)):
                model = clone(models[name]); started = time.perf_counter_ns()
                model.fit(Xtrain, ytrain)
                fits.append({'method': name, 'repeat': repeat,
                             'fit_ms': (time.perf_counter_ns() - started) / 1e6})
                fitted[name] = model
        for name, model in fitted.items():
            cut = calibrate(response(model, X[masks['benign_calibration']]), cfg['false_positive_target'])
            scores = response(model, Xdev)
            predictions[name] = scores
            buffer = io.BytesIO(); joblib.dump(model, buffer, compress=0)
            quality.append({'method': name, **metrics(ydev, scores, cut),
                'calibration_false_alerts': int((response(model, X[masks['benign_calibration']]) >= cut).sum()),
                'serialized_bytes': buffer.tell()})
        # Identical sampled rows and batch order for every model in a repeat.
        for batch_size in [1, 32, 256, len(Xdev)]:
            repeats = 60 if batch_size == 1 else 25
            indices = [rng.choice(len(Xdev), batch_size, replace=False) for _ in range(repeats)]
            batches = [np.ascontiguousarray(Xdev[idx]) for idx in indices]
            for scope in ['pipeline', 'model_only']:
                transformed = {name: [model[:-1].transform(batch) for batch in batches]
                               for name, model in fitted.items()} if scope == 'model_only' else None
                for name, model in fitted.items():
                    for _ in range(5):
                        response(model if scope == 'pipeline' else model[-1],
                                 batches[0] if scope == 'pipeline' else transformed[name][0])
                for repeat, batch in enumerate(batches):
                    for name in rng.permutation(list(fitted)):
                        model = fitted[name] if scope == 'pipeline' else fitted[name][-1]
                        inputs = batch if scope == 'pipeline' else transformed[name][repeat]
                        started = time.perf_counter_ns(); scores = response(model, inputs)
                        elapsed = (time.perf_counter_ns() - started) / 1e6
                        if len(scores) != batch_size or not np.isfinite(scores).all():
                            raise ValueError('Invalid timed prediction')
                        timings.append({'method': name, 'scope': scope, 'batch_size': batch_size,
                                        'repeat': repeat, 'call_ms': elapsed})
    raw = pd.DataFrame(timings)
    latency = raw.groupby(['method', 'scope', 'batch_size']).call_ms.agg(
        median_ms='median', p95_ms=lambda a: a.quantile(.95), calls='size').reset_index()
    latency['amortized_us_per_row'] = latency.median_ms * 1000 / latency.batch_size
    latency['rows_per_second'] = latency.batch_size * 1000 / latency.median_ms
    fit_frame = pd.DataFrame(fits)
    fit_summary = fit_frame.groupby('method').fit_ms.agg(fit_median_ms='median',
        fit_max_ms='max').reset_index()  # Three fits do not support a meaningful tail percentile.
    single = latency.query("scope == 'pipeline' and batch_size == 1").rename(
        columns={'median_ms': 'single_pipeline_median_ms', 'p95_ms': 'single_pipeline_p95_ms'})
    comparison = pd.DataFrame(quality).merge(fit_summary, on='method').merge(
        single[['method', 'single_pipeline_median_ms', 'single_pipeline_p95_ms']], on='method')
    comparison['pareto_observed'] = pareto_flags(comparison)
    baselines = []
    for method in ['sql_combined', 'flow_count_baseline', 'always_benign', 'random_baseline']:
        baselines.append({'method': method, **metrics(ydev, data.loc[masks['development'], method],
                                                    protocol['cutoffs'][method])})
    for name, table in [('quality_latency', comparison), ('raw_latency', raw), ('latency_by_batch', latency),
                        ('raw_fit_times', fit_frame), ('baseline_quality', pd.DataFrame(baselines)),
                        ('development_scores', predictions)]:
        table.to_csv(output / f'{name}.csv', index=False)
    packages = ['numpy', 'pandas', 'scikit-learn', 'lightgbm', 'xgboost', 'catboost',
                'psutil', 'threadpoolctl', 'nbclient']
    metadata = {'status': 'development_only', 'seed': seed, 'threads': 1,
        'feature_columns': FEATURES, 'created_utc': pd.Timestamp.now(tz='UTC').isoformat(),
        'cpu': platform.processor(), 'logical_cpus': psutil.cpu_count(),
        'physical_cpus': psutil.cpu_count(logical=False), 'ram_bytes': psutil.virtual_memory().total,
        'os': platform.platform(), 'python': platform.python_version(),
        'versions': {p: importlib.metadata.version(p) for p in packages},
        'masks': {k: int(v.sum()) for k, v in masks.items()},
        'training_positive_windows': int(ytrain.sum()), 'development_positive_windows': int(ydev.sum()),
        'timing_scope': 'Warm CPU calls; no SQL, network, Flask, loading, serialization or window wait.',
        'warning': 'Six correlated development positives; no independent-episode generalization claim.'}
    (output / 'environment.json').write_text(json.dumps(metadata, indent=2))
    return comparison, latency, pd.DataFrame(baselines), predictions, metadata
