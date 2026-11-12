import uuid
from pathlib import Path

import pytest
import yaml

from cybershield.db import ROOT, connect, file_hash, migrate
from cybershield.evaluate import build_features
from cybershield.fixture import make_fixture
from cybershield.ingest import ingest


@pytest.fixture
def database():
    schema='cs_test_'+uuid.uuid4().hex[:10]
    try:
        conn=connect(schema)
    except Exception as exc:
        pytest.fail(f'PostgreSQL integration requires docker compose up -d --wait: {type(exc).__name__}')
    migrate(conn,schema)
    yield conn
    conn.rollback()
    # Generated test schemas are the only objects removed; no project data touched.
    from psycopg import sql
    conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
    conn.commit();conn.close()


@pytest.mark.integration
def test_reconciliation_idempotency_and_label_separation(database,tmp_path):
    conn=database; path=make_fixture(tmp_path/'synthetic.csv')
    audit=ingest(conn,path,synthetic=True)
    assert audit['input_rows']==audit['accepted_rows']+audit['rejected_rows']
    assert audit['rejected_rows']==2
    assert audit['content_duplicate_rows']>=1
    count=conn.execute('SELECT count(*) FROM flow').fetchone()[0]
    repeated=ingest(conn,path,synthetic=True)
    assert repeated['skipped'] is True
    assert conn.execute('SELECT count(*) FROM flow').fetchone()[0]==count
    config=yaml.safe_load((ROOT/'configs/prototype.yaml').read_text(encoding='utf-8'))
    feature_id=build_features(conn,[audit['source_id']],config,file_hash(ROOT/'configs/prototype.yaml'))
    # Independently count source-window membership from normalized flows.
    mismatch=conn.execute('''SELECT count(*) FROM window_features w WHERE feature_run_id=%s AND flow_count != (
        SELECT count(*) FROM flow f WHERE f.src_ip=w.src_ip AND f.clock_usable
        AND f.reported_end>=w.window_start AND f.reported_end<w.window_start+interval '5 minutes')''',(feature_id,)).fetchone()[0]
    assert mismatch==0
    before=conn.execute('SELECT src_ip,window_start,flow_count FROM window_features WHERE feature_run_id=%s ORDER BY 1,2',(feature_id,)).fetchall()
    conn.execute("UPDATE flow_label SET is_attack=NOT is_attack")
    altered=build_features(conn,[audit['source_id']],config,file_hash(ROOT/'configs/prototype.yaml'))
    after=conn.execute('SELECT src_ip,window_start,flow_count FROM window_features WHERE feature_run_id=%s ORDER BY 1,2',(altered,)).fetchall()
    assert before==after


@pytest.mark.integration
def test_window_boundaries_and_no_future_history(database,tmp_path):
    conn=database;path=make_fixture(tmp_path/'synthetic.csv')
    source=ingest(conn,path,synthetic=True)['source_id']
    config=yaml.safe_load((ROOT/'configs/prototype.yaml').read_text())
    feature=build_features(conn,[source],config,'test')
    # date_bin assigns the exact boundary to the following half-open bin.
    start=conn.execute("SELECT date_bin('5 minutes',timestamp '2017-07-04 09:05:00',timestamp '2000-01-01')").fetchone()[0]
    assert start.minute==5
    rows=conn.execute('''SELECT w.historical_mean,(
        SELECT avg(p.flow_count) FROM window_features p WHERE p.feature_run_id=w.feature_run_id
        AND p.src_ip=w.src_ip AND p.window_start BETWEEN w.window_start-interval '60 minutes'
            AND w.window_start-interval '5 minutes')
        FROM window_features w WHERE feature_run_id=%s''',(feature,)).fetchall()
    for actual,reference in rows:
        assert actual==pytest.approx(float(reference)) if reference is not None else actual is None


@pytest.mark.integration
def test_real_loader_rejects_reserved_friday(database,tmp_path):
    with pytest.raises(ValueError,match='Tuesday only'):
        ingest(database,tmp_path/'Friday.csv',synthetic=False)


@pytest.mark.integration
def test_failed_batch_rolls_back_and_can_retry(database,tmp_path,monkeypatch):
    import cybershield.ingest as module
    conn=database;path=make_fixture(tmp_path/'synthetic.csv')
    original=module.parse_row
    calls=0

    def interrupted(row):
        nonlocal calls
        calls+=1
        if calls==5100:
            raise RuntimeError('simulated interruption after a flushed batch')
        return original(row)

    monkeypatch.setattr(module,'parse_row',interrupted)
    with pytest.raises(RuntimeError,match='simulated interruption'):
        ingest(conn,path,synthetic=True)
    assert conn.execute('SELECT count(*) FROM flow').fetchone()[0]==0
    assert conn.execute("SELECT count(*) FROM ingestion_run WHERE status='failed'").fetchone()[0]==1
    conn.commit()
    monkeypatch.setattr(module,'parse_row',original)
    result=ingest(conn,path,synthetic=True)
    assert result['accepted_rows']==8802
    assert conn.execute('SELECT count(*) FROM flow').fetchone()[0]==8802

