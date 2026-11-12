"""Bounded SQL exploration using a separate, read-only PostgreSQL login."""
from __future__ import annotations

import math
import secrets
import time
import uuid
from datetime import date, datetime
from decimal import Decimal

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
import sqlglot
from sqlglot import exp

from .db import ROOT, connect, environment, migrate

ROLE = 'cybershield_workspace_reader'
DATASETS = {'real': 'cs_tuesday', 'fixture': 'cs_fixture'}
TABLES = {
    'flow': 'Accepted flows. One row per original source record.',
    'flow_label': 'Retrospective benchmark labels, joined by flow_id.',
    'source_file': 'Source filenames, hashes, and provenance.',
    'ingestion_run': 'Load reconciliation and quality summaries.',
    'latest_experiment': 'The most recently completed development experiment.',
    'latest_features': 'Latest SQL features: one source per five-minute window.',
    'latest_window_labels': 'Latest retrospective window targets.',
    'latest_predictions': 'Latest scores and decisions by detection method.',
    'latest_triage': 'Latest ranked SQL queue with explanations.',
    'window_features': 'All feature runs. Filter feature_run_id to avoid duplicates.',
    'window_label': 'All window targets. Join on run, source, and time.',
    'prediction': 'All experiment predictions. Filter experiment_id.',
    'rule_version': 'Per-experiment rule scales and calibrated cutoffs.',
    'experiment_run': 'Experiment metadata and recorded development summaries.',
    'feature_run': 'Feature configurations and source membership.',
    'v_triage_queue': 'All ranked queues. Filter experiment_id.',
}
FUNCTIONS = {
    'COUNT','SUM','AVG','MIN','MAX','ROUND','ABS','CEIL','CEILING','FLOOR',
    'COALESCE','NULLIF','GREATEST','LEAST','LOWER','UPPER','LENGTH','SUBSTRING',
    'LEFT','RIGHT','TRIM','CONCAT','CONCAT_WS','REPLACE','HOST','FAMILY',
    'DATE_BIN','DATE_TRUNC','TIMESTAMP_TRUNC','EXTRACT','TIME_TO_STR','TO_CHAR',
    'ROW_NUMBER','RANK','DENSE_RANK','LAG','LEAD','FIRST_VALUE','LAST_VALUE','NTILE',
    'ARRAY_AGG','STRING_AGG','GROUP_CONCAT','PERCENTILE_CONT','PERCENTILE_DISC',
    'BOOL_AND','BOOL_OR','LOGICAL_AND','LOGICAL_OR','CAST','TRY_CAST',
    'CURRENT_DATE','CURRENT_TIMESTAMP','CURRENT_USER','SESSION_USER',
    'ARRAY','JSON_EXTRACT','JSON_EXTRACT_SCALAR','CASE','IF',
    'AND','OR','NOT','IN','BETWEEN','LIKE','ILIKE','IS','EXISTS',
}


class QueryRejected(ValueError):
    pass


def validate_query(query: str, schema: str):
    if not isinstance(query,str) or not query.strip():
        raise QueryRejected('Write a SELECT query, or choose an example to start.')
    if len(query)>20_000:
        raise QueryRejected('Keep the query under 20,000 characters.')
    try:
        statements=[node for node in sqlglot.parse(query,read='postgres') if node is not None]
    except sqlglot.errors.ParseError as exc:
        raise QueryRejected('The SQL could not be parsed. Check the syntax and try again.') from exc
    if len(statements)!=1 or not isinstance(statements[0],(exp.Select,exp.Union,exp.Intersect,exp.Except)):
        raise QueryRejected('Run one read-only SELECT or WITH … SELECT statement at a time.')
    tree=statements[0]
    denied=tuple(getattr(exp,name) for name in
                 ['Insert','Update','Delete','Merge','Create','Drop','Alter','Command','Copy','Into','Lock','Set','Transaction']
                 if hasattr(exp,name))
    for node in tree.walk():
        if isinstance(node,denied):
            raise QueryRejected('This workspace supports read-only queries. Data changes and locking are disabled.')
        if isinstance(node,exp.Func):
            name=node.name.upper() if isinstance(node,exp.Anonymous) else node.sql_name().upper()
            if name not in FUNCTIONS:
                raise QueryRejected(f'Function {name} is not enabled in this query workspace.')
        if isinstance(node,exp.Dot) and isinstance(node.expression,exp.Func):
            raise QueryRejected('Use unqualified built-in function names.')
    ctes={cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    for table in tree.find_all(exp.Table):
        if not isinstance(table.this,exp.Identifier):
            raise QueryRejected('Query the listed dataset tables or a named CTE.')
        if table.catalog or (table.db and table.db.lower()!=schema):
            raise QueryRejected('Use tables from the selected dataset. Switch datasets in the sidebar.')
        name=table.name if table.this.quoted else table.name.lower()
        if name not in TABLES and not (not table.db and name.lower() in ctes):
            raise QueryRejected(f'Table “{table.name}” is not available. See the schema reference.')
    return query.strip().rstrip(';')


def prepare_workspace():
    """Run as the existing owner once at launch, never for user-supplied SQL."""
    env=environment()
    password=env.get('CYBERSHIELD_READER_PASSWORD')
    if not password:
        password=secrets.token_hex(24)
        with (ROOT/'.env').open('a',encoding='utf-8') as stream:
            stream.write(f'\nCYBERSHIELD_READER_PASSWORD={password}\n')
    with connect('cs_tuesday') as owner:
        exists=owner.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(ROLE,)).fetchone()
        verb='ALTER' if exists else 'CREATE'
        owner.execute(sql.SQL(verb+' ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8 PASSWORD {}').format(
                sql.Identifier(ROLE),sql.Literal(password)))
        owner.execute(sql.SQL('ALTER ROLE {} SET default_transaction_read_only=on').format(sql.Identifier(ROLE)))
        owner.execute(sql.SQL('ALTER ROLE {} SET statement_timeout=\'5s\'').format(sql.Identifier(ROLE)))
        owner.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(
            sql.Identifier(env.get('POSTGRES_DB','cybershield')),sql.Identifier(ROLE)))
        owner.commit()
    for schema in DATASETS.values():
        with connect(schema) as owner:
            present=owner.execute('SELECT to_regnamespace(%s)',(schema,)).fetchone()[0]
            owner.commit()
            if not present:
                continue
            migrate(owner,schema)
            owner.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(ROLE)))
            for table in TABLES:
                owner.execute(sql.SQL('GRANT SELECT ON {}.{} TO {}').format(
                    sql.Identifier(schema),sql.Identifier(table),sql.Identifier(ROLE)))
            owner.commit()


def reader_connection(dataset):
    if dataset not in DATASETS:
        raise QueryRejected('Choose either Tuesday real data or the synthetic fixture.')
    env=environment()
    password=env.get('CYBERSHIELD_READER_PASSWORD')
    if not password:
        raise RuntimeError('Start the workspace with the serve command to initialize its reader.')
    conn=psycopg.connect(make_conninfo(host=env.get('POSTGRES_HOST','127.0.0.1'),
        port=env.get('POSTGRES_PORT','55432'),dbname=env.get('POSTGRES_DB','cybershield'),
        user=ROLE,password=password,connect_timeout=3,application_name='cybershield_query_workspace'))
    conn.read_only=True
    conn.execute(sql.SQL('SET LOCAL search_path TO pg_catalog, {}').format(sql.Identifier(DATASETS[dataset])))
    conn.execute("SET LOCAL statement_timeout='5s'")
    conn.execute("SET LOCAL lock_timeout='500ms'")
    conn.execute("SET LOCAL idle_in_transaction_session_timeout='8s'")
    conn.execute("SET LOCAL work_mem='8MB'")
    return conn


def json_value(value):
    if value is None or isinstance(value,(bool,int)):
        return value
    if isinstance(value,float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value,(datetime,date)):
        return value.isoformat(sep=' ') if isinstance(value,datetime) else value.isoformat()
    if isinstance(value,Decimal):
        return str(value)
    if isinstance(value,(list,tuple)):
        return [json_value(item) for item in value[:100]]
    if isinstance(value,dict):
        return {str(key):json_value(item) for key,item in list(value.items())[:100]}
    return str(value)[:8000]


def run_query(query: str,dataset='real',row_limit=250):
    if dataset not in DATASETS:
        raise QueryRejected('Choose a valid dataset.')
    if isinstance(row_limit,bool) or not isinstance(row_limit,int) or not 1<=row_limit<=500:
        raise QueryRejected('Choose a result limit from 1 to 500 rows.')
    checked=validate_query(query,DATASETS[dataset])
    start=time.perf_counter()
    with reader_connection(dataset) as conn:
        # A server-side cursor bounds fetched rows without rewriting the query.
        with conn.cursor(name='workspace_'+uuid.uuid4().hex) as cursor:
            cursor.execute(checked)
            fetched=cursor.fetchmany(row_limit+1)
            columns=[column.name for column in cursor.description]
            if len(columns)>80:
                raise QueryRejected('Choose at most 80 columns for a readable result.')
            rows=[[json_value(value) for value in row] for row in fetched[:row_limit]]
    return {'columns':columns,'rows':rows,'row_count':len(rows),'truncated':len(fetched)>row_limit,
            'row_limit':row_limit,'elapsed_ms':round((time.perf_counter()-start)*1000),
            'dataset':dataset}


def dataset_metadata(dataset):
    with reader_connection(dataset) as conn:
        cursor=conn.execute('''SELECT (SELECT count(*) FROM flow),
            (SELECT count(*) FROM latest_features),
            (SELECT count(*) FROM latest_window_labels WHERE attack_flows>0),
            (SELECT count(DISTINCT label) FROM flow_label)''')
        flows,windows,positive,categories=cursor.fetchone()
        schema=DATASETS[dataset]
        rows=conn.execute('''SELECT table_name,column_name,data_type FROM information_schema.columns
            WHERE table_schema=%s ORDER BY table_name,ordinal_position''',(schema,)).fetchall()
        tables=[{'name':name,'description':description,
                 'columns':[{'name':column,'type':datatype} for table,column,datatype in rows if table==name]}
                for name,description in TABLES.items()]
        experiment=conn.execute('SELECT experiment_id,feature_run_id FROM latest_experiment').fetchone()
    return {'flows':flows,'windows':windows,'positive_windows':positive,'categories':categories,
            'schema':schema,'dataset':dataset,'tables':tables,
            'experiment_id':str(experiment[0]) if experiment else None,
            'feature_run_id':str(experiment[1]) if experiment else None}

