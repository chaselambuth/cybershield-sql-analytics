from __future__ import annotations

import collections
import csv
import hashlib
import io
import ipaddress
import math
import re
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

from psycopg.types.json import Jsonb

from .db import file_hash

REQUIRED = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
            'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 'Label']
KNOWN_ATTACKS = {'FTP-Patator', 'SSH-Patator', 'PortScan', 'DDoS', 'DoS Hulk',
                 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'Heartbleed',
                 'Bot', 'Infiltration', 'Web Attack - Brute Force',
                 'Web Attack - XSS', 'Web Attack - Sql Injection'}


def normalize_headers(header):
    counts = collections.Counter()
    normalized = []
    for raw in header:
        clean = raw.strip()
        counts[clean] += 1
        normalized.append(clean if counts[clean] == 1 else f'{clean}__{counts[clean]}')
    missing = set(REQUIRED) - set(normalized)
    if missing:
        raise ValueError(f'Missing required columns: {sorted(missing)}')
    return normalized


def integer(value: str, name: str, maximum: int = 2**63 - 1) -> int:
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f'invalid_{name}') from exc
    if not number.is_finite() or number != number.to_integral_value() or not 0 <= number <= maximum:
        raise ValueError(f'invalid_{name}')
    return int(number)


def optional_rate(value: str | None):
    try:
        result = float(value) if value else None
    except ValueError:
        result = None
    return result if result is not None and math.isfinite(result) and result >= 0 else None


def label_info(raw: str):
    label = re.sub(r'\s+', ' ', raw.strip().replace('\u2013', '-').replace('\u2014', '-'))
    return label, False if label == 'BENIGN' else True if label in KNOWN_ATTACKS else None


def parse_row(row: dict[str, str]):
    start = datetime.strptime(row['Timestamp'].strip(), '%d/%m/%Y %H:%M')
    duration = integer(row['Flow Duration'], 'duration')
    end = start + timedelta(microseconds=duration)
    # No AM/PM repair: retain ALL accepted records, but temporal features use only
    # 08:00–11:59 reported-clock records finishing before noon on the same date.
    # This is a limited retrospective morning-clock assumption, not a UTC claim.
    clock_usable = 8 <= start.hour < 12 and end.date() == start.date() and end.hour < 12
    src = str(ipaddress.ip_address(row['Source IP'].strip()))
    dst = str(ipaddress.ip_address(row['Destination IP'].strip()))
    packets = integer(row['Total Fwd Packets'], 'packets') + integer(row['Total Backward Packets'], 'packets')
    size = integer(row['Total Length of Fwd Packets'], 'bytes') + integer(row['Total Length of Bwd Packets'], 'bytes')
    if packets > 2**63-1 or size > 2**63-1:
        raise ValueError('aggregate_overflow')
    label, target = label_info(row['Label'])
    return (
        row['Flow ID'],src,dst,integer(row['Source Port'],'src_port',65535),
        integer(row['Destination Port'],'dst_port',65535),integer(row['Protocol'],'protocol',255),
        row['Timestamp'],start,end,clock_usable,duration,packets,size,
        optional_rate(row.get('Flow Bytes/s')),optional_rate(row.get('Flow Packets/s')),
        row['Label'],label,target,
    )


@contextmanager
def open_source(path: Path, member: str | None):
    if member:
        with zipfile.ZipFile(path) as archive, archive.open(member) as stream:
            yield stream
    else:
        with path.open('rb') as stream:
            yield stream


def stream_hash(path, member):
    digest = hashlib.sha256()
    size = 0
    with open_source(path, member) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def ingest(conn, path: Path, member: str | None = None, synthetic=False, adapter=None):
    filename = member or path.name
    if adapter is not None:
        adapter.validate_source(filename)
        schema = conn.execute('SELECT current_schema()').fetchone()[0]
        if not schema.startswith(('cs_study_', 'cs_test_')):
            raise ValueError('Corrected adapter requires an isolated cs_study_* schema')
    if adapter is None and not synthetic and ('Friday' in filename or 'Tuesday' not in filename):
        raise ValueError('Prototype real-data ingestion permits Tuesday only; Friday is reserved.')
    digest, size = stream_hash(path, member)
    existing = conn.execute('''SELECT s.source_id,r.audit FROM source_file s
        JOIN ingestion_run r USING(source_id) WHERE s.sha256=%s AND s.filename=%s
        AND r.status='complete' ORDER BY r.completed_at DESC LIMIT 1''', (digest, filename)).fetchone()
    conn.commit()
    if existing:
        if adapter is not None and existing[1].get('adapter_identity') != adapter.identity:
            raise ValueError('Existing source was ingested with a different adapter policy; use a new study schema')
        return {'source_id':existing[0], 'skipped':True, **existing[1]}

    with open_source(path, member) as stream:
        reader = csv.reader(io.TextIOWrapper(stream, encoding=adapter.encoding if adapter else 'cp1252', newline=''))
        original_header = next(reader)
    header = adapter.normalize_headers(original_header) if adapter else normalize_headers(original_header)
    run_id = uuid.uuid4()
    archive_digest = file_hash(path) if member else None
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', (f'ingest:{filename}:{digest}',))
        # Check again under the ingestion lock for concurrent/retried commands.
        previous = conn.execute('''SELECT s.source_id,r.audit FROM source_file s
            JOIN ingestion_run r USING(source_id) WHERE s.sha256=%s AND s.filename=%s
            AND r.status='complete' LIMIT 1''',(digest,filename)).fetchone()
        if previous:
            if adapter is not None and previous[1].get('adapter_identity') != adapter.identity:
                raise ValueError('Existing source has a different adapter policy')
            return {'source_id':previous[0],'skipped':True,**previous[1]}
        source_id = conn.execute('''INSERT INTO source_file(filename,sha256,archive_sha256,release,
            synthetic,bytes,header) VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (sha256,filename) DO UPDATE SET sha256=EXCLUDED.sha256 RETURNING source_id''',
            (filename,digest,archive_digest,adapter.release if adapter else 'synthetic_fixture' if synthetic else 'CIC-IDS2017-original',
             synthetic,size,Jsonb({'raw':original_header,'normalized':header}))).fetchone()[0]
        conn.execute('INSERT INTO ingestion_run(run_id,source_id,status) VALUES (%s,%s,\'running\')',(run_id,source_id))
    conn.commit()

    audit = {'filename':filename,'sha256':digest,'bytes':size,'synthetic':synthetic,
             'raw_hour_counts':collections.Counter(),'label_counts':collections.Counter(),
             'warnings':collections.Counter(),'rejection_reasons':collections.Counter(),
             'input_rows':0,'accepted_rows':0,'rejected_rows':0,'clock_usable_rows':0,
             'duplicate_headers':[n for n,c in collections.Counter(x.strip() for x in original_header).items() if c>1],
             'timestamp_policy':'reported_clock_morning_only_no_repair'}
    if adapter:
        audit.update(adapter_identity=adapter.identity,
                     timestamp_policy='corrected_explicit_utc_microseconds_no_repair',
                     raw_label_counts=collections.Counter())
    try:
        with conn.transaction():
            conn.execute('''CREATE TEMP TABLE stage_flow (
                source_id bigint,run_id uuid,row_number bigint,record_hash text,
                source_flow_id text,src_ip inet,dst_ip inet,src_port integer,dst_port integer,protocol smallint,
                raw_timestamp text,reported_start timestamp,reported_end timestamp,clock_usable boolean,
                duration_us bigint,packets bigint,bytes bigint,bytes_per_second float8,packets_per_second float8,
                label_raw text,label text,is_attack boolean,provenance jsonb) ON COMMIT DROP''')
            good, bad = [], []

            def flush():
                if good:
                    with conn.cursor().copy('COPY stage_flow FROM STDIN') as cp:
                        for item in good:
                            cp.write_row(item)
                    good.clear()
                if bad:
                    with conn.cursor().copy('COPY quarantine_record(run_id,row_number,reason,raw_row) FROM STDIN') as cp:
                        for item in bad:
                            cp.write_row(item)
                    bad.clear()

            with open_source(path, member) as stream:
                reader = csv.reader(io.TextIOWrapper(stream, encoding=adapter.encoding if adapter else 'cp1252', newline=''))
                next(reader)
                for row_number, values in enumerate(reader,2):
                    audit['input_rows'] += 1
                    try:
                        if len(values) != len(header) or not any(v.strip() for v in values):
                            raise ValueError('empty_or_wrong_column_count')
                        row = dict(zip(header,values))
                        if adapter:
                            audit['raw_label_counts'][row['Label']] += 1
                        parsed = adapter.parse_row(row) if adapter else parse_row(row)
                        record_hash = adapter.record_hash(row) if adapter else hashlib.sha256('\x1f'.join(values).encode('utf-8')).hexdigest()
                        provenance = Jsonb(adapter.provenance(row)) if adapter else None
                        good.append((source_id,run_id,row_number,record_hash,*parsed,provenance))
                        audit['accepted_rows'] += 1
                        audit['clock_usable_rows'] += int(parsed[9])
                        audit['raw_hour_counts'][str(parsed[7].hour)] += 1
                        audit['label_counts'][parsed[-2]] += 1
                        if parsed[-1] is None:
                            audit['warnings']['unknown_label'] += 1
                        for name,index in [('missing_or_invalid_bytes_rate',13),('missing_or_invalid_packets_rate',14)]:
                            if parsed[index] is None:
                                audit['warnings'][name] += 1
                        if parsed[10] > 120_000_000:
                            audit['warnings']['duration_over_120_seconds'] += 1
                    except (ValueError, OverflowError) as exc:
                        reason = str(exc)[:180]
                        audit['rejected_rows'] += 1
                        audit['rejection_reasons'][reason] += 1
                        bad.append((run_id,row_number,reason,Jsonb(values)))
                    if len(good) + len(bad) >= 5000:
                        flush()
                flush()
            conn.execute('''INSERT INTO flow(source_id,run_id,row_number,record_hash,source_flow_id,
                src_ip,dst_ip,src_port,dst_port,protocol,raw_timestamp,reported_start,reported_end,
                clock_usable,duration_us,packets,bytes,bytes_per_second,packets_per_second)
                SELECT source_id,run_id,row_number,record_hash,source_flow_id,
                src_ip,dst_ip,src_port,dst_port,protocol,raw_timestamp,reported_start,reported_end,
                clock_usable,duration_us,packets,bytes,bytes_per_second,packets_per_second FROM stage_flow''')
            conn.execute('''INSERT INTO flow_label SELECT f.flow_id,s.label_raw,s.label,s.is_attack
                FROM stage_flow s JOIN flow f USING(source_id,row_number)''')
            if adapter:
                conn.execute('''INSERT INTO flow_provenance SELECT f.flow_id,s.provenance
                    FROM stage_flow s JOIN flow f USING(source_id,row_number)''')
            accepted = conn.execute('SELECT count(*) FROM flow WHERE run_id=%s',(run_id,)).fetchone()[0]
            rejected = conn.execute('SELECT count(*) FROM quarantine_record WHERE run_id=%s',(run_id,)).fetchone()[0]
            assert accepted == audit['accepted_rows'] and rejected == audit['rejected_rows']
            assert accepted + rejected == audit['input_rows']
            audit['content_duplicate_rows'] = conn.execute('''SELECT coalesce(sum(n-1),0) FROM
                (SELECT count(*) n FROM flow WHERE source_id=%s GROUP BY record_hash HAVING count(*)>1) d''',(source_id,)).fetchone()[0]
            audit['content_duplicate_rows'] = int(audit['content_duplicate_rows'])
            conn.execute('''UPDATE ingestion_run SET status='complete',completed_at=now(),input_rows=%s,
                accepted_rows=%s,rejected_rows=%s,audit=%s WHERE run_id=%s''',
                (audit['input_rows'],accepted,rejected,Jsonb(audit),run_id))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        conn.execute("UPDATE ingestion_run SET status='failed',completed_at=now(),audit=%s WHERE run_id=%s",
                     (Jsonb({'error':type(exc).__name__}),run_id))
        conn.commit()
        raise
    return {'source_id':source_id,'skipped':False,**audit}

