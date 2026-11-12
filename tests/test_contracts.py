import csv
from datetime import datetime

import numpy as np
import pytest

from cybershield.evaluate import calibrate, metrics
from cybershield.fixture import make_fixture
from cybershield.ingest import normalize_headers, parse_row, optional_rate, label_info


def first_row(tmp_path):
    path=make_fixture(tmp_path/'fixture.csv')
    with path.open(encoding='cp1252',newline='') as stream:
        reader=csv.reader(stream); header=normalize_headers(next(reader))
        return dict(zip(header,next(reader)))


def test_duplicate_header_is_not_overwritten(tmp_path):
    row=first_row(tmp_path)
    assert row['Fwd Header Length']=='40'
    assert row['Fwd Header Length__2']=='40'


@pytest.mark.parametrize('value',['NaN','Infinity','-1','bad',''])
def test_nonfinite_rates_become_missing(value):
    assert optional_rate(value) is None


def test_invalid_ip_and_fractional_counts_rejected(tmp_path):
    row=first_row(tmp_path);row['Source IP']='not-an-ip'
    with pytest.raises(ValueError):parse_row(row)
    row=first_row(tmp_path);row['Total Fwd Packets']='2.5'
    with pytest.raises(ValueError,match='invalid_packets'):parse_row(row)


def test_reported_afternoon_clock_is_preserved_but_not_scored(tmp_path):
    row=first_row(tmp_path);row['Timestamp']='4/7/2017 1:00'
    parsed=parse_row(row)
    assert parsed[7]==datetime(2017,7,4,1)
    assert parsed[9] is False


def test_noon_completion_excluded(tmp_path):
    row=first_row(tmp_path);row['Timestamp']='4/7/2017 11:59';row['Flow Duration']='120000000'
    assert parse_row(row)[9] is False


def test_unknown_labels_are_not_benign():
    assert label_info('unrecognized')[1] is None
    assert label_info('BENIGN')[1] is False
    assert label_info('Web Attack \u2013 XSS')[1] is True


def test_cutoff_excludes_tie_group_and_controls_budget():
    scores=np.array([10,9,9,8,1])
    cutoff=calibrate(scores,.2)
    assert (scores>=cutoff).sum()==1
    assert (np.array([1,1,1])>=calibrate([1,1,1],.01)).sum()==0


def test_metrics_hand_calculation_and_undefined_cases():
    result=metrics([1,1,0,0],[.9,.1,.8,.2],.5)
    assert (result['tp'],result['fp'],result['tn'],result['fn'])==(1,1,1,1)
    assert result['recall']==result['precision']==.5
    assert metrics([0,0],[0,0],1)['recall'] is None
    assert metrics([0,0],[0,0],1)['precision'] is None
    assert metrics([],[],1)['roc_auc'] is None

