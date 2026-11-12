import hashlib
import json
import sys

import pytest

from cybershield.cli import main


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


def test_report_verifier_rejects_outside_paths(tmp_path,monkeypatch):
    report=tmp_path/'report'; report.mkdir()
    (report/'output_manifest.json').write_text(json.dumps({'../outside.csv':'anything'}))
    monkeypatch.setattr(sys,'argv',['cybershield','verify',str(report)])
    with pytest.raises(SystemExit) as exc:main()
    assert exc.value.code==1

