"""Controlled feature ablation and alert-budget sensitivity on frozen SQL windows."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from threadpoolctl import threadpool_limits

from .db import ROOT, file_hash
from .evaluate import FEATURES, calibrate, metrics
from .research import RESEARCH, split_masks


# These groups follow SQL feature meaning, independently of development scores.
FEATURE_GROUPS = {
    'volume': ['flow_count'],
    'diversity': ['unique_ports', 'unique_destinations'],
    'services': ['service_flows'],
    'size_duration': ['packets', 'bytes', 'mean_duration_us'],
}
ALERT_TARGETS = (0.001, 0.005, 0.01, 0.02)
SQL_CONTROLS = ('sql_combined', 'rule_volume', 'rule_ports', 'rule_services')


def feature_variants():
    """Hold the estimator fixed; remove a semantic group and refit from scratch."""
    return {
        'LR: all features': list(FEATURES),
        **{f'LR: without {name}': [f for f in FEATURES if f not in group]
           for name, group in FEATURE_GROUPS.items()},
        'LR: flow count only': ['flow_count'],
    }


def run_robustness(data, protocol, output=None):
    """Fit on training only, calibrate on benign calibration, describe development.

    All variants and budgets are reported. No development-driven feature or cutoff
    is selected, and saved SQL scores keep their original training-fitted scales.
    """
    output = Path(output or RESEARCH / 'robustness')
    cfg = protocol['config']
    if protocol.get('status') != 'development_only':
        raise ValueError('Robustness experiment requires a development-only protocol')
    masks = split_masks(data, cfg)
    if not masks['development'].any():
        raise ValueError('No known-label development windows')
    X = data[FEATURES].to_numpy(dtype=float)
    if np.any(X < 0) or np.isinf(X).any():
        raise ValueError('Features must be nonnegative and finite or missing')
    if not np.isfinite(data[list(SQL_CONTROLS)].to_numpy(dtype=float)).all():
        raise ValueError('SQL control scores must be finite')
    if data.loc[masks['train'], FEATURES].isna().all().any():
        raise ValueError('Each feature requires at least one observed training value')

    y = data.attack_flows.gt(0)
    variants = feature_variants()
    scores = data[['src_ip', 'window_start', 'split']].copy()
    scores['is_attack'] = y
    scores['known_label'] = data.unknown_flows.eq(0)
    fitted_parameters = {}
    with threadpool_limits(limits=1):
        for name, features in variants.items():
            model = make_pipeline(
                SimpleImputer(strategy='median'), FunctionTransformer(np.log1p),
                StandardScaler(), LogisticRegression(**cfg['model'], random_state=cfg['seed']))
            model.fit(data.loc[masks['train'], features].to_numpy(float), y[masks['train']])
            scores[name] = model.predict_proba(data[features].to_numpy(float))[:, list(model.classes_).index(True)]
            fitted_parameters[name] = {
                'features': features,
                'imputer_medians': model[0].statistics_.tolist(),
                'scaler_means': model[2].mean_.tolist(),
                'scaler_scales': model[2].scale_.tolist(),
                'coefficients': model[-1].coef_[0].tolist(),
                'intercept': float(model[-1].intercept_[0]),
            }
    for name in SQL_CONTROLS:
        scores[name] = data[name].to_numpy(float)

    records = []
    for name in [*variants, *SQL_CONTROLS]:
        calibration_scores = scores.loc[masks['benign_calibration'], name].to_numpy(float)
        development_scores = scores.loc[masks['development'], name].to_numpy(float)
        for target in ALERT_TARGETS:
            cutoff = calibrate(calibration_scores, target)
            records.append({
                'method': name, 'target': target,
                'feature_count': len(variants[name]) if name in variants else None,
                'calibration_benign_windows': len(calibration_scores),
                'calibration_allowed_false_alerts': math.floor(target * len(calibration_scores)),
                'calibration_false_alerts': int((calibration_scores >= cutoff).sum()),
                **metrics(y[masks['development']], development_scores, cutoff),
            })
    results = pd.DataFrame(records)

    # Matched entities expose what each removal changed, without treating changes as causal.
    reference = results.loc[(results.method == 'LR: all features') & results.target.eq(.01)].iloc[0]
    reference_pred = scores.loc[masks['development'], reference.method].ge(reference.cutoff)
    ablations = results.loc[results.method.isin(variants) & results.target.eq(.01)].copy()
    for index, row in ablations.iterrows():
        prediction = scores.loc[masks['development'], row.method].ge(row.cutoff)
        ablations.loc[index, 'changed_decisions'] = int(prediction.ne(reference_pred).sum())
        for metric in ['tp', 'fp', 'average_precision']:
            ablations.loc[index, f'delta_{metric}_vs_full'] = row[metric] - reference[metric]

    support = pd.DataFrame([
        {'role': role, 'windows': int(mask.sum()), 'positive_windows': int(y[mask].sum()),
         'benign_windows': int((~y[mask]).sum()),
         'positive_sources': int(data.loc[mask & y, 'src_ip'].nunique()),
         'observed_time_bins': int(data.loc[mask, 'window_start'].nunique())}
        for role, mask in masks.items()
    ])
    errors = []
    dev = masks['development']
    for name in ['LR: all features', 'sql_combined']:
        row = results.loc[results.method.eq(name) & results.target.eq(.01)].iloc[0]
        table = scores.loc[dev, ['src_ip', 'window_start', 'is_attack']].copy()
        table['method'] = name
        table['score'] = scores.loc[dev, name]
        table['cutoff'] = row.cutoff
        table['alert'] = table.score.ge(row.cutoff)
        table['outcome'] = np.select(
            [table.alert & table.is_attack, table.alert & ~table.is_attack, ~table.alert & table.is_attack],
            ['TP', 'FP', 'FN'], default='TN')
        errors.append(table)
    errors = pd.concat(errors, ignore_index=True)

    output.mkdir(parents=True, exist_ok=True)
    for name, table in [('budget_sensitivity', results), ('feature_ablation', ablations),
                        ('support', support), ('reference_decisions', errors)]:
        table.to_csv(output / f'{name}.csv', index=False)
    scores.loc[masks['calibration'] | dev].to_csv(output / 'window_scores.csv', index=False)
    metadata = {
        'status': 'development_only', 'seed': cfg['seed'],
        'estimator': cfg['model'], 'feature_groups': FEATURE_GROUPS,
        'variants': variants, 'false_alert_targets': ALERT_TARGETS,
        'sql_controls': SQL_CONTROLS, 'primary_comparison_target': .01,
        'training_parameters': fitted_parameters,
        'versions': {p: importlib.metadata.version(p) for p in ['numpy', 'pandas', 'scikit-learn']},
        'input_data_sha256': hashlib.sha256(data.to_csv(index=False).encode()).hexdigest(),
        'protocol_sha256': hashlib.sha256(
            json.dumps(protocol, sort_keys=True).encode()).hexdigest(),
        'code_sha256': {str(p.relative_to(ROOT)): file_hash(p) for p in [
            Path(__file__), ROOT / 'src/cybershield/evaluate.py', ROOT / 'src/cybershield/research.py',
            ROOT / 'sql/features/source_windows.sql', ROOT / 'sql/detection/scores.sql']},
        'interpretation': 'Matched feature removals and budget scenarios on correlated development windows; '
                          'no causal attribution, general model selection, or independent test estimate.',
    }
    (output / 'protocol.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return results, ablations, support, errors
