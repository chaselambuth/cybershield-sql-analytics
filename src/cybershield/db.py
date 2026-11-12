from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

ROOT = Path(__file__).resolve().parents[2]


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def environment() -> dict[str, str]:
    values = {}
    envfile = ROOT / '.env'
    if envfile.exists():
        for line in envfile.read_text(encoding='utf-8').splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
    values.update(os.environ)
    return values


def connect(schema: str = 'cs_fixture'):
    if not re.fullmatch(r'cs_[a-z0-9_]+', schema):
        raise ValueError('Schema must match cs_[a-z0-9_]+')
    env = environment()
    conn = psycopg.connect(make_conninfo(
        host=env.get('POSTGRES_HOST', '127.0.0.1'),
        port=env.get('POSTGRES_PORT', '55432'),
        dbname=env.get('POSTGRES_DB', 'cybershield'),
        user=env.get('POSTGRES_USER', 'cybershield'),
        password=env.get('POSTGRES_PASSWORD', ''),
        connect_timeout=10,
    ))
    conn.execute(sql.SQL('SET search_path TO {}, public').format(sql.Identifier(schema)))
    conn.commit()
    return conn


def migrate(conn, schema: str):
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', (f'cybershield:{schema}',))
        conn.execute(sql.SQL('CREATE SCHEMA IF NOT EXISTS {}').format(sql.Identifier(schema)))
        conn.execute('''CREATE TABLE IF NOT EXISTS schema_migrations (
            filename text PRIMARY KEY, sha256 text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now())''')
        for path in sorted((ROOT / 'sql' / 'migrations').glob('*.sql')):
            digest = file_hash(path)
            row = conn.execute('SELECT sha256 FROM schema_migrations WHERE filename=%s', (path.name,)).fetchone()
            if row:
                if row[0] != digest:
                    raise RuntimeError(f'Previously applied migration changed: {path.name}')
                continue
            conn.execute(path.read_text(encoding='utf-8'))
            conn.execute('INSERT INTO schema_migrations(filename,sha256) VALUES (%s,%s)', (path.name, digest))
    conn.commit()

