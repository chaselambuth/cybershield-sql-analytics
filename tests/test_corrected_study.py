"""New scientific controls: synthetic contracts and optional isolated PostgreSQL checks."""
import copy
import csv
from datetime import datetime
import io
import json
import uuid
import zipfile

import numpy as np
import pandas as pd
import pytest
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from cybershield.corrected import CorrectedAdapter, REQUIRED, audit_archive, corrected_label
from cybershield.db import ROOT, connect, file_hash, migrate
from cybershield.evaluate import FEATURES, build_features
from cybershield.ingest import ingest
from cybershield.protocol import allocate, episode_overlap, support, validate_protocol
from cybershield.study import (artifact_hashes, audit_support, load_prepared, register,
                               save_json, verify_design)
from cybershield.study_benchmark import (as_scores, numpy_rule_reference, rule_scales,
                                        run_benchmark, verify_scores)


def config():
    return json.loads((ROOT/'configs/corrected_development_v1.json').read_text())


def corrected_row(**changes):
    row=dict(zip(REQUIRED,['1','synthetic-flow','192.0.2.1','1234','198.51.100.2','22','6',
        '2017-07-04 13:00:00.000001','1000000','1','2','10','20','BENIGN','-1']))
    row.update(changes)
    return row


def fixture_zip(path, rows):
    stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=REQUIRED)
    writer.writeheader();writer.writerows(rows)
    with zipfile.ZipFile(path,'w') as z:z.writestr('tuesday.csv',stream.getvalue())
    return path


def test_corrected_clock_duration_and_raw_fields():
    adapter=CorrectedAdapter('tuesday.csv',['tuesday.csv'],synthetic=True)
    row=corrected_row();parsed=adapter.parse_row(row)
    assert parsed[7]==datetime(2017,7,4,13,0,0,1)
    assert parsed[8]==datetime(2017,7,4,13,0,1,1) and parsed[9]
    assert parsed[10:13]==(1000000,3,30)
    assert adapter.provenance(row)['Flow Duration']=='1000000'
    assert adapter.provenance(row)['id']=='1'
    next_id=dict(row,id='2')
    assert adapter.record_hash(row)==adapter.record_hash(next_id)


@pytest.mark.parametrize('label,category,target,status',[
    ('BENIGN','-1',False,'known_benign'),('FTP-Patator','-1',True,'known_attack'),
    ('FTP-Patator - Attempted','0',None,'attempted_unresolved'),
    ('BENIGN','3',None,'attempted_unresolved'),('novel_label','-1',None,'unknown_label'),
    ('BENIGN','bad',None,'invalid_attempted_category')])
def test_uncertain_labels_never_become_known_benign(label,category,target,status):
    _,actual,_,state=corrected_label(label,category)
    assert actual is target and state==status


@pytest.mark.parametrize('changes,reason',[
    ({'Timestamp':'2017-07-05 13:00:00.000001'},'member_date'),
    ({'Timestamp':'4/7/2017 1:00'},'timestamp'),
    ({'Flow Duration':'-1'},'duration'),({'Total Fwd Packet':'1.5'},'packets'),
    ({'Src Port':'65536'},'src_port'),({'Src IP':'bad'},None)])
def test_corrected_rejects_ambiguous_and_invalid_required_fields(changes,reason):
    adapter=CorrectedAdapter('tuesday.csv',['tuesday.csv'],synthetic=True)
    with pytest.raises(ValueError,match=reason):adapter.parse_row(corrected_row(**changes))


def test_corrected_requires_explicit_member_and_unique_schema():
    with pytest.raises(ValueError,match='registered'):
        CorrectedAdapter('friday.csv',['tuesday.csv'])
    adapter=CorrectedAdapter('tuesday.csv',['tuesday.csv'])
    with pytest.raises(ValueError,match='missing'):adapter.normalize_headers(REQUIRED[:-1])
    with pytest.raises(ValueError,match='duplicate'):adapter.normalize_headers(REQUIRED+['Label'])


def test_streaming_audit_reconciles_unknown_windows_and_content_duplicates(tmp_path):
    rows=[corrected_row(),corrected_row(id='2'),
          corrected_row(id='3',Label='FTP-Patator'),
          corrected_row(id='4',Label='FTP-Patator - Attempted',**{'Attempted Category':'0'}),
          corrected_row(id='5',**{'Flow Duration':'-1'})]
    archive=fixture_zip(tmp_path/'synthetic.zip',rows)
    result=audit_archive(archive,['tuesday.csv'],tmp_path/'audit')
    audit=result['members'][0]
    assert (audit['input_rows'],audit['accepted_rows'],audit['rejected_rows'])==(5,4,1)
    assert audit['duplicate_content_rows_excluding_id']==1
    assert audit['unknown_excluded_windows']==1 and audit['known_positive_windows']==0
    raw=json.loads((tmp_path/'audit/tuesday_quarantine.jsonl').read_text())
    assert raw['csv_record_number']==6 and raw['raw_row'][8]=='-1'


def test_source_support_is_bound_to_protocol_and_has_no_model_claim(tmp_path):
    cfg=config();cfg['members']=['tuesday.csv']
    protocol=tmp_path/'protocol.json';protocol.write_text(json.dumps(cfg))
    archive=fixture_zip(tmp_path/'synthetic.zip',[corrected_row()])
    audit_archive(archive,cfg['members'],tmp_path/'audit',protocol_sha256=file_hash(protocol))
    gate=audit_support(tmp_path/'audit',protocol,tmp_path/'support')
    assert not gate['passed'] and not (tmp_path/'support/metrics.csv').exists()
    cfg['protocol_version']='synthetic-support-only-revision'
    protocol.write_text(json.dumps(cfg))
    with pytest.raises(ValueError,match='bound to this protocol'):
        audit_support(tmp_path/'audit',protocol,tmp_path/'unregistered_revision')
    audit_support(tmp_path/'audit',protocol,tmp_path/'revised',revision_note='Synthetic pre-model support revision')
    context=json.loads((tmp_path/'revised/audit_support_context.json').read_text())
    assert context['source_audit_protocol_sha256']!=context['protocol_sha256']
    (tmp_path/'audit/window_support.csv').write_text('tampered')
    with pytest.raises(ValueError,match='audit file changed'):
        audit_support(tmp_path/'audit',protocol,tmp_path/'tampered',revision_note='Synthetic pre-model support revision')


def population():
    rows=[]
    # Entirely synthetic units. Enough calibration negatives to exercise a 1% allowance.
    definitions=[('2017-07-04 13:00',12),('2017-07-05 10:00',140),
                 ('2017-07-05 14:00',8),('2017-07-06 14:00',8)]
    for block,(stamp,count) in enumerate(definitions):
        for i in range(count):
            time=pd.Timestamp(stamp)+pd.Timedelta(minutes=5*(i%8))
            positive=block!=1 and i%3==0
            labels=(['FTP-Patator' if i%2 else 'SSH-Patator'] if block==0 else ['DoS Hulk' if block==2 else 'Web Attack - XSS']) if positive else []
            row={'src_ip':f'192.0.{block}.{i+1}','window_start':time,
                 'min_flow_start':time,'max_flow_end':time+pd.Timedelta(seconds=1),
                 'flow_count':20+i,'attack_flows':int(positive),'unknown_flows':0,'episode_labels':labels}
            row.update({name:float((i+1)*(j+1)+10*positive) for j,name in enumerate(FEATURES) if name!='flow_count'})
            rows.append(row)
    return pd.DataFrame(rows)


def test_roles_are_reproducible_time_aware_and_support_is_not_independence():
    cfg=config();data=allocate(population(),cfg)
    pd.testing.assert_series_equal(data.role,allocate(population().sample(frac=1,random_state=5),cfg).set_index(['src_ip','window_start']).reindex(data.set_index(['src_ip','window_start']).index).role.reset_index(drop=True),check_names=False)
    assert episode_overlap(data).empty
    table,gate=support(data,cfg)
    assert gate['passed'] and gate['observed']['benign_calibration_windows']==140
    assert 'not established' in gate['independence'] and gate['mlp'].startswith('deferred')


def test_episode_crossing_roles_blocks_comparison_even_if_windows_do_not_overlap():
    raw=population();cfg=config()
    cfg['roles']['train']=['2017-07-04T12:00:00Z','2017-07-04T13:05:00Z']
    cfg['roles']['calibration']=['2017-07-04T14:10:00Z','2017-07-04T14:15:00Z']
    cfg['roles']['validation']=['2017-07-04T15:20:00Z','2017-07-05T00:00:00Z']
    extra=raw.iloc[0].copy();extra['window_start']=pd.Timestamp('2017-07-04 15:20')
    extra['min_flow_start']=extra.window_start;extra['max_flow_end']=extra.window_start+pd.Timedelta(seconds=1)
    raw=pd.concat([raw,pd.DataFrame([extra])],ignore_index=True)
    data=allocate(raw,cfg)
    assert len(episode_overlap(data))==1
    assert any('cross prohibited' in r for r in support(data,cfg)[1]['reasons'])


def test_flow_start_boundary_and_unknown_calibration_exclusions():
    raw=population();raw.loc[0,'min_flow_start']=pd.Timestamp('2017-07-02 23:59')
    cal=raw.index[raw.window_start.eq(pd.Timestamp('2017-07-05 10:00'))][0]
    raw.loc[cal,'unknown_flows']=1
    data=allocate(raw,config())
    assert data.loc[0,'role']=='unscored'
    table,gate=support(data,config())
    assert gate['observed']['benign_calibration_windows']==139
    assert table.set_index('role').loc['calibration','unknown_excluded_windows']==1


def test_invalid_roles_final_test_and_friday_are_rejected():
    for mutate in [lambda c:c.update(final_test_enabled=True),
                   lambda c:c['members'].append('friday.csv'),
                   lambda c:c['roles'].update(calibration=['2017-07-05T00:00:00Z','2017-07-05T12:00:00Z'])]:
        cfg=config();mutate(cfg)
        with pytest.raises(ValueError):validate_protocol(cfg)


def test_mixed_fractional_source_times_keep_exact_boundary_membership():
    raw=population()
    raw['min_flow_start']=raw.min_flow_start.astype(str)
    raw.loc[0,'min_flow_start']='2017-07-04T13:00:00.000001'
    raw.loc[1,'min_flow_start']='2017-07-04T13:05:00'
    data=allocate(raw,config())
    assert data.loc[0,'min_flow_start'].microsecond==1
    assert data.loc[:1,'role'].eq('train').all()


def test_support_gate_stops_before_fitting_or_sql(tmp_path):
    data=allocate(population(),config());data.loc[data.role.eq('train'),'is_attack']=False
    def forbidden(*args):raise AssertionError('Should not fit/score insufficient support')
    result=run_benchmark(data,config(),tmp_path/'blocked',forbidden,'synthetic',model_factory=forbidden)
    assert result['status']=='blocked_support'
    assert not (tmp_path/'blocked/metrics.csv').exists()


def small_models(seed,positive_weight):
    return {'Logistic regression':make_pipeline(SimpleImputer(strategy='median'),FunctionTransformer(np.log1p),
        StandardScaler(),LogisticRegression(C=1,class_weight='balanced',max_iter=2000,random_state=seed))}


def test_matched_comparison_roundtrip_and_no_validation_fitting(tmp_path):
    cfg=config();data=allocate(population(),cfg)
    # Extreme unknown calibration rows cannot affect the learned preprocessing/cutoff.
    first=tmp_path/'first'
    run_benchmark(data,cfg,first,lambda s:numpy_rule_reference(data,s),'synthetic',model_factory=small_models)
    assert verify_scores(first)
    changed=data.copy();changed.loc[changed.role.eq('validation'),FEATURES]=1e9
    second=tmp_path/'second'
    run_benchmark(changed,cfg,second,lambda s:numpy_rule_reference(changed,s),'synthetic',model_factory=small_models)
    assert json.loads((first/'fitted_preprocessing.json').read_text())==json.loads((second/'fitted_preprocessing.json').read_text())
    assert json.loads((first/'training_rule_scales.json').read_text())==json.loads((second/'training_rule_scales.json').read_text())
    a=pd.read_csv(first/'cutoffs.csv',float_precision='round_trip');b=pd.read_csv(second/'cutoffs.csv',float_precision='round_trip')
    np.testing.assert_array_equal(a.cutoff,b.cutoff)
    quality=pd.read_csv(first/'metrics.csv')
    assert quality.groupby(['role','target']).windows.nunique().eq(1).all()
    quality.loc[0,'tp']+=1;quality.to_csv(first/'metrics.csv',index=False)
    with pytest.raises(ValueError,match='confusion'):verify_scores(first)


def test_float32_boundary_is_promoted_before_decision():
    from cybershield.evaluate import calibrate
    native=np.array([.5,.5,.1],dtype=np.float32)
    values=as_scores(native,3);cutoff=calibrate(values,.01)
    assert not (values>=cutoff).any() and values.dtype==np.float64


def test_all_eight_fixed_candidates_and_controls_on_synthetic_fixture(tmp_path):
    cfg=config();data=allocate(population(),cfg)
    result=run_benchmark(data,cfg,tmp_path/'eight',lambda s:numpy_rule_reference(data,s),
                         'synthetic-eight-candidate-contract',synthetic=True)
    assert result['status']=='completed_synthetic_validation'
    assert set(result['methods'])==set(cfg['models']+cfg['controls'])
    assert verify_scores(tmp_path/'eight')
    environment=json.loads((tmp_path/'eight/environment.json').read_text())
    assert environment['synthetic_test'] and environment['native_score_dtypes']['XGBoost']=='float32'


def test_design_registration_rejects_changed_protocol_and_wrong_expected_hash(tmp_path):
    archive=fixture_zip(tmp_path/'synthetic.zip',[corrected_row()])
    folder,digest=register(ROOT/'configs/corrected_development_v1.json',archive,tmp_path/'design')
    verify_design(folder,digest)
    with pytest.raises(ValueError,match='expected hash'):verify_design(folder,'0'*64)
    (folder/'protocol.json').write_text('{}')
    with pytest.raises(ValueError,match='protocol changed'):verify_design(folder,digest)


def test_design_registration_preserves_and_checks_source_bytes(tmp_path):
    archive=fixture_zip(tmp_path/'synthetic.zip',[corrected_row()])
    folder,digest=register(ROOT/'configs/corrected_development_v1.json',archive,tmp_path/'design')
    snapshot=folder/'source_code/src/cybershield/corrected.py'
    assert snapshot.read_bytes()==(ROOT/'src/cybershield/corrected.py').read_bytes()
    snapshot.write_text('changed source snapshot')
    with pytest.raises(ValueError,match='source snapshot changed'):verify_design(folder,digest)


def test_prepared_input_roundtrip_and_tamper_rejection(tmp_path):
    archive=fixture_zip(tmp_path/'synthetic.zip',[corrected_row()])
    folder,design=register(ROOT/'configs/corrected_development_v1.json',archive,tmp_path/'design')
    registration=json.loads((folder/'registration.json').read_text())
    data=allocate(population(),config())
    data['attack_categories']=data.episode_labels.map(list)
    data['source_members']=[['synthetic_fixture'] for _ in range(len(data))]
    for name in ['attack_categories','episode_labels','episode_groups','source_members']:
        data[name]=data[name].map(json.dumps)
    prepared=folder/'prepared';prepared.mkdir()
    data.to_csv(prepared/'windows.csv',index=False,float_format='%.17g')
    save_json(folder/'prepared.json',{'kind':'cybershield_corrected_prepared_v1',
        'run_id':registration['run_id'],'design_sha256':design,'files':artifact_hashes(prepared)})
    expected=file_hash(folder/'prepared.json')
    *_,loaded=load_prepared(folder,design,expected)
    assert loaded.role.tolist()==data.role.tolist()
    assert loaded.episode_groups.iloc[0]==json.loads(data.episode_groups.iloc[0])
    (prepared/'windows.csv').write_text('changed input')
    with pytest.raises(ValueError,match='Prepared input changed'):
        load_prepared(folder,design,expected)


def test_support_blocked_verification_does_not_claim_model_results(tmp_path,monkeypatch,capsys):
    import sys
    import cybershield.study as study
    folder=tmp_path/'run';bench=folder/'benchmark';bench.mkdir(parents=True)
    save_json(bench/'support_gate.json',{'passed':False})
    save_json(folder/'benchmark_registration.json',{'design_sha256':'design','prepared_sha256':'prepared',
        'status':'blocked_support','files':artifact_hashes(bench)})
    monkeypatch.setattr(study,'load_prepared',lambda *args:(folder,None,None,None,None))
    monkeypatch.setattr(sys,'argv',['study','verify','--run',str(folder),
                                  '--design-sha256','design','--prepared-sha256','prepared'])
    study.main()
    assert 'no model metrics or scoring are claimed' in capsys.readouterr().out


@pytest.mark.integration
def test_corrected_postgres_idempotency_provenance_and_label_free_features(tmp_path):
    schema='cs_test_'+uuid.uuid4().hex[:10]
    from psycopg import sql
    with connect(schema) as conn:
        migrate(conn,schema)
        try:
            rows=[corrected_row(),corrected_row(id='2'),corrected_row(id='3',Label='FTP-Patator'),
                  corrected_row(id='4',Label='FTP-Patator - Attempted',**{'Attempted Category':'0'}),
                  corrected_row(id='5',**{'Flow Duration':'-1'})]
            archive=fixture_zip(tmp_path/'synthetic.zip',rows)
            adapter=CorrectedAdapter('tuesday.csv',['tuesday.csv'],synthetic=True)
            audit=ingest(conn,archive,'tuesday.csv',synthetic=True,adapter=adapter)
            assert audit['accepted_rows']==4 and audit['rejected_rows']==1 and audit['content_duplicate_rows']==1
            repeated=ingest(conn,archive,'tuesday.csv',synthetic=True,adapter=adapter)
            assert repeated['skipped'] and conn.execute('SELECT count(*) FROM flow').fetchone()[0]==4
            raw=conn.execute("SELECT raw_fields FROM flow_provenance JOIN flow USING(flow_id) WHERE row_number=2").fetchone()[0]
            assert raw['Timestamp']==rows[0]['Timestamp'] and raw['Flow Duration']=='1000000'
            cfg={'status':'development_only','window_minutes':5}
            first=build_features(conn,[audit['source_id']],cfg,'synthetic')
            assert conn.execute('SELECT sum(flow_count) FROM window_features WHERE feature_run_id=%s',(first,)).fetchone()[0]==4
            assert conn.execute('SELECT attack_flows,unknown_flows FROM window_label WHERE feature_run_id=%s',(first,)).fetchone()==(1,1)
            before=conn.execute('SELECT '+','.join(FEATURES)+' FROM window_features WHERE feature_run_id=%s',(first,)).fetchall()
            conn.execute('UPDATE flow_label SET is_attack=NOT is_attack');conn.commit()
            second=build_features(conn,[audit['source_id']],cfg,'synthetic')
            after=conn.execute('SELECT '+','.join(FEATURES)+' FROM window_features WHERE feature_run_id=%s',(second,)).fetchall()
            assert before==after
        finally:
            conn.rollback();conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)));conn.commit()
