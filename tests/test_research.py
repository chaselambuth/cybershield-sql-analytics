"""Research safeguards: role integrity, ambiguous targets, and source scope."""
import csv
import io
import json
import zipfile

import numpy as np
import pandas as pd
import pytest

from cybershield.research import pareto_flags, split_masks
from cybershield.source_audit import CORRECTED_MEMBER, audit_tuesday
from cybershield.robustness import ALERT_TARGETS, SQL_CONTROLS, feature_variants, run_robustness
from cybershield.evaluate import FEATURES


def population():
    data = pd.DataFrame({'window_start': pd.to_datetime(['2020-01-01 00:00','2020-01-01 00:05',
        '2020-01-01 00:10','2020-01-01 00:15','2020-01-01 00:20']),
        'split':['train','train','calibration','calibration','development'],
        'attack_flows':[0,1,0,0,1], 'unknown_flows':[0,0,0,1,0]})
    cfg = {'splits': {'train':['2020-01-01 00:00','2020-01-01 00:10'],
        'calibration':['2020-01-01 00:10','2020-01-01 00:20'],
        'development':['2020-01-01 00:20','2020-01-01 00:25']}}
    return data, cfg


def test_unknown_calibration_windows_are_excluded():
    data, cfg = population()
    masks = split_masks(data,cfg)
    assert masks['benign_calibration'].tolist() == [False,False,True,False,False]
    assert not masks['development'].iloc[:4].any()


def test_changed_role_labels_are_rejected():
    data, cfg = population(); data.loc[0,'split']='development'
    with pytest.raises(ValueError,match='Split assignment mismatch'):
        split_masks(data,cfg)


def test_source_audit_refuses_friday_before_opening_archive(tmp_path):
    with pytest.raises(ValueError,match='Tuesday'):
        audit_tuesday(tmp_path/'does_not_exist.zip','friday.csv',corrected=True)


def test_audit_preserves_ambiguous_labels_and_invalid_times(tmp_path):
    header = ['id','Src IP','Dst IP','Dst Port','Timestamp','Flow Duration','Total Fwd Packet',
        'Total Bwd packets','Total Length of Fwd Packet','Total Length of Bwd Packet',
        'Flow Bytes/s','Flow Packets/s','Label']
    rows = [[1,'10.0.0.1','10.0.0.2',22,'2020-01-01 12:00:00.000001',100,1,1,10,10,1,1,'SSH-Patator - Attempted'],
            [2,'10.0.0.1','10.0.0.2',22,'bad-clock',100,1,1,10,10,1,1,'BENIGN'],
            [3,'bad-address','10.0.0.2',22,'2020-01-01 12:00:00.000001',100,1,1,10,10,1,1,'BENIGN']]
    stream=io.StringIO(); writer=csv.writer(stream); writer.writerow(header); writer.writerows(rows)
    archive=tmp_path/'test.zip'
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr(CORRECTED_MEMBER,stream.getvalue())
    audit, flows, windows=audit_tuesday(archive,CORRECTED_MEMBER,corrected=True)
    assert audit['input_rows']==3 and audit['temporal_eligible_rows']==1
    assert audit['timestamp_parse_failures']==1 and audit['invalid_address_rows']==1
    assert windows.unknown_flows.tolist()==[1] and not windows.attack_flows.any()
    assert audit['positive_windows_attempted_as_attack']==1
    assert audit['positive_windows_attempted_as_benign']==0


def test_frontier_keeps_quality_latency_tradeoffs_and_ties():
    table=pd.DataFrame({'fn':[0,0,1,0,0], 'fp':[5,6,0,5,5],
                        'single_pipeline_p95_ms':[1,2,.1,1,3]})
    assert pareto_flags(table).tolist()==[True,False,True,True,False]


def robustness_population():
    """Synthetic roles include an unknown calibration row with an extreme score."""
    time = pd.date_range('2020-01-01', periods=14, freq='5min')
    data = pd.DataFrame({
        'window_start': time, 'src_ip': [f'10.0.0.{i+1}' for i in range(14)],
        'split': ['train'] * 6 + ['calibration'] * 4 + ['development'] * 4,
        'attack_flows': [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1],
        'unknown_flows': [0] * 9 + [1] + [0] * 4,
    })
    for index, feature in enumerate(FEATURES):
        data[feature] = np.arange(1, 15, dtype=float) * (index + 1)
    for name in SQL_CONTROLS:
        data[name] = [1, 9, 2, 8, 3, 7, 1, 2, 2, 999, 1, 5, 3, 6]
    protocol = {'status': 'development_only', 'config': {
        'seed': 1729,
        'model': {'C': 1., 'class_weight': 'balanced', 'solver': 'lbfgs', 'max_iter': 2000},
        'splits': {'train': [str(time[0]), str(time[6])],
                   'calibration': [str(time[6]), str(time[10])],
                   'development': [str(time[10]), '2020-01-01 01:10:00']},
    }}
    return data, protocol


def test_budget_grid_uses_known_benign_calibration_and_preserves_ties(tmp_path):
    data, protocol = robustness_population()
    results, ablations, support, decisions = run_robustness(data, protocol, tmp_path)
    assert len(results) == (len(feature_variants()) + len(SQL_CONTROLS)) * len(ALERT_TARGETS)
    assert results.calibration_benign_windows.eq(3).all()
    assert results.calibration_false_alerts.le(results.calibration_allowed_false_alerts).all()
    sql = results.loc[results.method.eq('sql_combined') & results.target.eq(.01)].iloc[0]
    assert sql.cutoff == np.nextafter(2., np.inf)  # Tied benign maxima are excluded together.
    assert (sql.tp, sql.fp, sql.tn, sql.fn) == (2, 1, 1, 0)
    assert support.set_index('role').loc['calibration', 'windows'] == 3
    assert len(decisions) == 8
    assert len(ablations) == 6


def test_development_changes_cannot_change_fitted_preprocessing_or_cutoffs(tmp_path):
    data, protocol = robustness_population()
    original, *_ = run_robustness(data, protocol, tmp_path / 'original')
    first = json.loads((tmp_path / 'original/protocol.json').read_text())
    dev = data.split.eq('development')
    data.loc[dev, FEATURES] = 1e12
    data.loc[dev, 'attack_flows'] = [1, 0, 1, 0]
    changed, *_ = run_robustness(data, protocol, tmp_path / 'changed')
    second = json.loads((tmp_path / 'changed/protocol.json').read_text())
    assert first['training_parameters'] == second['training_parameters']
    np.testing.assert_array_equal(original.cutoff, changed.cutoff)
    assert first['input_data_sha256'] != second['input_data_sha256']
    full = first['training_parameters']['LR: all features']
    assert full['imputer_medians'] == data.loc[data.split.eq('train'), FEATURES].median().tolist()


def test_larger_budgets_never_raise_cutoffs_or_remove_existing_alerts(tmp_path):
    data, protocol = robustness_population()
    # Enough benign scores to exercise all four distinct integer alert allowances.
    calibration = pd.concat([data.loc[data.split.eq('calibration') & data.unknown_flows.eq(0)]] * 100,
                            ignore_index=True)
    calibration['src_ip'] = [f'192.0.2.{i}' for i in range(len(calibration))]
    for name in SQL_CONTROLS:
        calibration[name] = np.arange(len(calibration), dtype=float) / 100
    data = pd.concat([data.loc[~data.split.eq('calibration')], calibration], ignore_index=True)
    results, *_ = run_robustness(data, protocol, tmp_path)
    for _, rows in results.groupby('method'):
        ordered = rows.sort_values('target')
        assert ordered.cutoff.diff().dropna().le(0).all()
        assert ordered.tp.diff().dropna().ge(0).all()
        assert ordered.fp.diff().dropna().ge(0).all()


@pytest.mark.parametrize('feature_value', [-1., np.inf])
def test_robustness_rejects_invalid_features(tmp_path, feature_value):
    data, protocol = robustness_population()
    data.loc[0, 'bytes'] = feature_value
    with pytest.raises(ValueError, match='nonnegative'):
        run_robustness(data, protocol, tmp_path)
