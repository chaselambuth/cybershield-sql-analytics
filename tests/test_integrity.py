import hashlib
import json
import shutil
import sys

import pytest

from cybershield.cli import main, verify_comparison
from cybershield.db import ROOT


def test_report_verifier_rejects_tampering(tmp_path,monkeypatch,capsys):
    report=tmp_path/'report'; report.mkdir()
    target=report/'metrics.csv'; target.write_text('tp,fp\n5,21\n')
    (report/'output_manifest.json').write_text(json.dumps({'metrics.csv':hashlib.sha256(target.read_bytes()).hexdigest()}))
    monkeypatch.setattr(sys,'argv',['cybershield','verify',str(report)])
    main()
    assert 'Verified 1 report files' in capsys.readouterr().out
    target.write_text('tp,fp\n6,0\n')
    with pytest.raises(SystemExit) as exc:main()
    assert exc.value.code==1
    assert 'altered' in capsys.readouterr().err


@pytest.mark.parametrize('relative',['../outside.csv','..\\outside.csv'])
def test_report_verifier_rejects_outside_paths(tmp_path,monkeypatch,relative):
    report=tmp_path/'report'; report.mkdir()
    (report/'output_manifest.json').write_text(json.dumps({relative:'anything'}))
    monkeypatch.setattr(sys,'argv',['cybershield','verify',str(report)])
    with pytest.raises(SystemExit) as exc:main()
    assert exc.value.code==1


def test_report_verifier_reads_windows_manifest_paths(tmp_path,monkeypatch,capsys):
    report=tmp_path/'report';(report/'analytics').mkdir(parents=True)
    target=report/'analytics/metrics.csv';target.write_text('tp,fp\n5,21\n')
    (report/'output_manifest.json').write_text(json.dumps({
        'analytics\\metrics.csv':hashlib.sha256(target.read_bytes()).hexdigest()}))
    monkeypatch.setattr(sys,'argv',['cybershield','verify',str(report)])
    main()
    assert 'Verified 1 report files' in capsys.readouterr().out


@pytest.fixture
def saved_comparison(tmp_path):
    source=ROOT/'reports/neural_comparison_v1'
    report=tmp_path/'comparison';report.mkdir()
    manifest=json.loads((source/'result_manifest.json').read_text())
    for name in [*manifest['files'],'result_manifest.json']:
        shutil.copyfile(source/name,report/name)
    return report,manifest['registration_sha256']


def test_saved_comparison_survives_producer_edit_but_strict_audit_rejects_it(saved_comparison,tmp_path,monkeypatch,capsys):
    import cybershield.neural_comparison as producer

    report,expected=saved_comparison
    registration=json.loads((report/'registration.json').read_text())
    checkout=tmp_path/'producer'
    for name in registration['code_files']:
        target=checkout/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,target)
    db=checkout/'src/cybershield/db.py'
    db.write_bytes(db.read_bytes()+b'\n# A later documentation-only edit.\n')
    monkeypatch.setattr(producer,'ROOT',checkout)
    monkeypatch.setattr(sys,'argv',['cybershield','verify',str(report),'--registration-sha256',expected])
    main()
    assert 'Verified 17 registered result files' in capsys.readouterr().out
    with pytest.raises(ValueError,match='Registered source changed: src/cybershield/db.py'):
        verify_comparison(report,expected,check_producer=True)


@pytest.mark.parametrize('name',['registration.json','protocol.json','scores.csv','metrics.csv'])
def test_saved_comparison_rejects_changed_evidence(saved_comparison,name):
    report,expected=saved_comparison
    path=report/name;path.write_bytes(path.read_bytes()+b'\n')
    with pytest.raises(ValueError,match='hash|altered'):
        verify_comparison(report,expected)


def test_saved_comparison_recomputes_calibration_after_hash_checks(saved_comparison):
    import pandas as pd

    report,expected=saved_comparison
    path=report/'cutoffs.csv'
    cuts=pd.read_csv(path,float_precision='round_trip')
    cuts.loc[0,'cutoff']=-1.
    cuts.to_csv(path,index=False,float_format='%.17g')
    manifest_path=report/'result_manifest.json'
    manifest=json.loads(manifest_path.read_text())
    manifest['files']['cutoffs.csv']=hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='calibration'):
        verify_comparison(report,expected)


def test_saved_comparison_rejects_incomplete_manifest(saved_comparison):
    report,expected=saved_comparison
    path=report/'result_manifest.json'
    manifest=json.loads(path.read_text());del manifest['files']['metrics.csv']
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='manifest is incomplete'):
        verify_comparison(report,expected)

