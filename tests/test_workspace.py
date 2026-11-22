import re
import secrets
import uuid

import psycopg
import pytest
from psycopg import sql

from cybershield.web import EXAMPLES,create_app
from cybershield.workspace import (QueryRejected,prepare_workspace,reader_connection,
                                  run_query,validate_query)


@pytest.fixture(scope='module')
def workspace_database(tmp_path_factory):
    """Exercise real reader grants on synthetic rows in a disposable namespace."""
    import cybershield.workspace as workspace
    from cybershield.db import connect,migrate
    from cybershield.fixture import make_fixture
    from cybershield.ingest import ingest

    suffix=uuid.uuid4().hex[:10]
    schema,role='cs_test_'+suffix,'cs_test_reader_'+suffix
    with connect(schema) as conn,pytest.MonkeyPatch.context() as patch:
        patch.setattr(workspace,'DATASETS',{'fixture':schema})
        patch.setattr(workspace,'ROLE',role)
        patch.setenv('CYBERSHIELD_READER_PASSWORD',secrets.token_hex(24))
        try:
            migrate(conn,schema)
            ingest(conn,make_fixture(tmp_path_factory.mktemp('workspace')/'synthetic.csv'),synthetic=True)
            prepare_workspace()
            yield role,schema
        finally:
            conn.rollback()
            conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
            if conn.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(role,)).fetchone():
                conn.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
                conn.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
            conn.commit()


@pytest.mark.parametrize('query',[
    'DELETE FROM flow',
    'SELECT 1; DELETE FROM flow',
    'WITH changed AS (DELETE FROM flow RETURNING *) SELECT * FROM changed',
    'SELECT * INTO copied FROM flow',
    'SELECT * FROM flow FOR UPDATE',
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT set_config('role','cybershield',true)",
    'SELECT pg_sleep(20)',
    'SELECT * FROM pg_catalog.pg_authid',
    'SELECT * FROM cs_fixture.flow',
    'COPY flow TO STDOUT',
    'SELECT * FROM generate_series(1,1000000)',
])
def test_disallowed_queries_are_rejected_before_execution(query):
    with pytest.raises(QueryRejected):validate_query(query,'cs_tuesday')


@pytest.mark.parametrize('query',[
    'SELECT COUNT(*) FROM FLOW;',
    "SELECT '; DROP TABLE flow' AS text;",
    'WITH counts AS (SELECT src_ip, COUNT(*) AS n FROM flow GROUP BY src_ip) SELECT * FROM counts',
    'SELECT * FROM flow WHERE dst_port IN (21,22) AND clock_usable LIMIT 2',
    'SELECT CASE WHEN bytes > 0 THEN 1 ELSE 0 END FROM flow LIMIT 1',
])
def test_supported_selects_and_ctes(query):
    assert validate_query(query,'cs_tuesday')


def test_builtin_examples_are_supported():
    for example in EXAMPLES:
        assert validate_query(example['sql'],'cs_tuesday')


def test_browser_post_requires_same_page_token():
    client=create_app().test_client()
    assert client.post('/api/query',json={'sql':'SELECT 1'}).status_code==403
    assert client.get('/',headers={'Host':'untrusted.example'}).status_code==403
    page=client.get('/')
    assert b'Query editor' in page.data
    assert "frame-ancestors 'none'" in page.headers['Content-Security-Policy']
    token=re.search(rb'name="workspace-token" content="([^"]+)"',page.data).group(1).decode()
    result=client.post('/api/query',json={'sql':'DELETE FROM flow'},headers={'X-Workspace-Token':token})
    assert result.status_code==400
    assert 'read-only' in result.json['error']


@pytest.mark.integration
def test_reader_is_not_owner_and_cannot_write_or_read_files(workspace_database):
    role,schema=workspace_database
    with reader_connection('fixture') as conn:
        user,readonly=conn.execute("SELECT current_user,current_setting('transaction_read_only')").fetchone()
        assert user==role and readonly=='on'
        assert conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname=current_user").fetchone()==(False,)
    with reader_connection('fixture') as conn:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("DELETE FROM flow WHERE false")
        conn.rollback()
    # Read-only can be toggled by a DB session; SELECT-only grants independently
    # protect the data even when testing direct SQL outside the web validator.
    with reader_connection('fixture') as conn:
        conn.rollback();conn.read_only=False
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql.SQL('DELETE FROM {}.flow WHERE false').format(sql.Identifier(schema)))
        conn.rollback()
    with reader_connection('fixture') as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT pg_read_file('/etc/passwd')")
        conn.rollback()


@pytest.mark.integration
def test_fetch_limit_and_duplicate_column_names(workspace_database):
    result=run_query('SELECT n AS same,n AS same FROM (VALUES (1),(2),(3)) AS v(n)','fixture',2)
    assert result['columns']==['same','same']
    assert result['rows']==[[1,1],[2,2]] and result['truncated']


@pytest.mark.integration
def test_queries_run_through_http_response_and_report_sql_errors(workspace_database):
    client=create_app().test_client()
    page=client.get('/')
    token=re.search(rb'name="workspace-token" content="([^"]+)"',page.data).group(1).decode()
    headers={'X-Workspace-Token':token}
    good=client.post('/api/query',headers=headers,json={'sql':'SELECT COUNT(*) AS flows FROM flow','dataset':'fixture','limit':100})
    assert good.status_code==200 and good.json['columns']==['flows']
    assert good.json['rows'][0][0]>0
    bad=client.post('/api/query',headers=headers,json={'sql':'SELECT nonexistent_column FROM flow','dataset':'fixture','limit':100})
    assert bad.status_code==400 and bad.json['sqlstate']=='42703'

