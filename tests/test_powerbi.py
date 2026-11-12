"""Reporting correctness checks, including the legacy XGBoost precision trap."""
import json
import re
import shutil

import numpy as np
import pandas as pd
import pytest

from cybershield.db import ROOT,file_hash
from cybershield.powerbi import (ReportingError,digest_object,score_values,tie_stats,
                                scientific_tables,verify_bundle,verified_inputs)


def test_float32_restoration_does_not_round_cutoff_down():
    cutoff=0.0014141943538561466
    saved=np.array([0.0014141944])
    assert (saved>=cutoff).item()  # Naive CSV parsing changes the original decision.
    assert not (score_values(saved,'float32')>=cutoff).item()
    with pytest.raises(ReportingError,match='Non-finite'):
        score_values([float('inf')],'float64')


def test_tie_diagnostics_apply_to_controls_and_non_xgboost_models():
    assert tie_stats([0,0,0,1])=={'distinct_scores':2,'largest_tie_count':3,'largest_tie_share':.75}
    assert tie_stats([0,0])['largest_tie_share']==1


@pytest.fixture(scope='module')
def reporting_tables():
    return scientific_tables()


def test_all_models_match_pinned_quality_and_provider_deduplication(reporting_tables):
    tables,context=reporting_tables
    assert len(tables['Window'])==11398
    assert len(tables['FactPrototypeDecision'])==11398*8
    detectors=tables['DimDetector'].set_index('detector_id')
    assert len(detectors)==15 and detectors.index.is_unique
    assert detectors.loc['lr','reproduced']
    assert detectors.loc['xgb','distinct_scores']==2
    assert detectors.loc['rf','high_tie_concentration']
    evaluation=tables['FactEvaluation'].set_index('detector_id')
    assert evaluation.loc['xgb',['tp','fp','tn','fn']].tolist()==[4,0,3407,2]
    assert evaluation.loc['lr',['tp','fp','tn','fn']].tolist()==[5,64,3343,1]
    assert evaluation[['tp','fp','tn','fn']].sum(axis=1).eq(3413).all()
    assert not any('calibration' in c for c in evaluation)
    assert evaluation.cohort.eq('development').all()


def test_audit_unknowns_and_release_scopes_remain_explicit(reporting_tables):
    tables,_=reporting_tables
    audit=tables['FactSourceAudit'];unknown=audit.loc[audit.dataset_id.eq('unsw')]
    assert unknown.value.isna().all()
    assert unknown.status.eq('documentation_only').all()
    assert audit.loc[audit.dataset_id.eq('original')].time_scope.str.contains('Morning|sensitivity').all()


def mini_bundle(folder):
    (folder/'Example.csv').write_text('id,value\n1,2\n')
    schema={'Example':{'file':'Example.csv','rows':1,'columns':[{'name':'id','type':'int64'},{'name':'value','type':'int64'}]}}
    (folder/'schema.json').write_text(json.dumps(schema))
    manifest={'schema_version':1,'files':{p.name:{'sha256':file_hash(p),'bytes':p.stat().st_size}
                                         for p in folder.iterdir()}}
    manifest['report_bundle_id']='bundle_'+digest_object(manifest)
    (folder/'manifest.json').write_text(json.dumps(manifest))


def test_bundle_validation_detects_same_size_data_changes(tmp_path):
    mini_bundle(tmp_path);verify_bundle(tmp_path)
    (tmp_path/'Example.csv').write_text('id,value\n1,3\n')
    with pytest.raises(ReportingError,match='Bundle file changed'):
        verify_bundle(tmp_path)


def test_bundle_manifest_cannot_silently_change_identity(tmp_path):
    mini_bundle(tmp_path)
    path=tmp_path/'manifest.json';manifest=json.loads(path.read_text())
    manifest['report_bundle_id']='different';path.write_text(json.dumps(manifest))
    with pytest.raises(ReportingError,match='identity mismatch'):
        verify_bundle(tmp_path)


def test_tmdl_measures_and_columns_do_not_share_case_insensitive_names():
    paths=list((ROOT/'power_bi/CyberShield.SemanticModel/definition/tables').glob('*.tmdl'))
    assert len(paths)==10
    for path in paths:
        text=path.read_text(encoding='utf-8')
        columns={s.casefold() for s in re.findall(r"^\tcolumn '([^']+)'",text,re.M)}
        measures={s.casefold() for s in re.findall(r"^\tmeasure '([^']+)'",text,re.M)}
        assert not columns & measures, f'Power BI name collision in {path.name}'


def test_benchmark_identity_ignores_notebook_edits_but_rejects_changed_results(tmp_path):
    _,inputs,identity=verified_inputs()
    for relative in inputs:
        path=tmp_path/relative;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/relative,path)
    manifest=tmp_path/'reports/research/research_manifest.json'
    shutil.copyfile(ROOT/'reports/research/research_manifest.json',manifest)
    notebook=tmp_path/'notebooks/01_data_audit_and_source_selection.ipynb'
    notebook.parent.mkdir();notebook.write_text('Presentation changed')
    assert verified_inputs(tmp_path)[2]==identity
    scores=tmp_path/'reports/research/models/development_scores.csv'
    with scores.open('a') as stream:stream.write('\n')
    with pytest.raises(ReportingError,match='Input hash mismatch'):
        verified_inputs(tmp_path)


def test_power_query_does_not_combine_private_file_sources():
    expressions=(ROOT/'power_bi/CyberShield.SemanticModel/definition/expressions.tmdl').read_text(encoding='utf-8')
    assert expressions.count('File.Contents(')==1
    assert '/report_data.json' in expressions
    assert 'PostgreSQL.Database' not in expressions
    assert 'PrivacyLevel' not in expressions  # No code that disables privacy checking.
