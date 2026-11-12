"""Explicit CNS2022 adapter and streaming, non-model source audit."""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import zipfile

from .db import file_hash
from .ingest import integer, optional_rate, stream_hash

RELEASE = 'CIC-IDS2017-CNS2022-corrected'
DATES = {'monday.csv': '2017-07-03', 'tuesday.csv': '2017-07-04',
         'wednesday.csv': '2017-07-05', 'thursday.csv': '2017-07-06', 'friday.csv': '2017-07-07'}
REQUIRED = ['id', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
            'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
            'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Label', 'Attempted Category']
ATTACKS = {'FTP-Patator', 'SSH-Patator', 'DoS Hulk', 'DoS GoldenEye', 'DoS Slowloris',
           'DoS Slowhttptest', 'Heartbleed', 'Web Attack - Brute Force', 'Web Attack - XSS',
           'Web Attack - SQL Injection', 'Infiltration', 'Infiltration - Portscan', 'Botnet', 'DDoS', 'PortScan'}
ALIASES = {'DoS slowloris': 'DoS Slowloris', 'Web Attack - Sql Injection': 'Web Attack - SQL Injection',
           'Bot': 'Botnet', 'Infiltration - PortScan': 'Infiltration - Portscan'}


def corrected_label(raw, attempted_category):
    label = re.sub(r'\s+', ' ', raw.strip().replace('\u2013', '-').replace('\u2014', '-'))
    label = ALIASES.get(label, label)
    try:
        category = int(attempted_category.strip())
        if str(category) != attempted_category.strip() or category < -1:
            raise ValueError
    except (ValueError, AttributeError):
        return label, None, label.split(' - Attempted')[0], 'invalid_attempted_category'
    family = ALIASES.get(label.split(' - Attempted')[0], label.split(' - Attempted')[0])
    if category != -1 or 'attempted' in label.casefold():
        return label, None, family, 'attempted_unresolved'
    if label == 'BENIGN':
        return label, False, None, 'known_benign'
    if label in ATTACKS:
        return label, True, family, 'known_attack'
    return label, None, family, 'unknown_label'


class CorrectedAdapter:
    encoding = 'utf-8-sig'
    release = RELEASE

    def __init__(self, member, allowed_members, synthetic=False):
        self.member = member
        self.allowed_members = tuple(allowed_members)
        self.synthetic = synthetic
        self.validate_source(member)

    @property
    def identity(self):
        return {'adapter': 'cns2022-v1', 'release': RELEASE, 'encoding': self.encoding,
                'timestamp': 'UTC_explicit_microsecond_clock_no_repair', 'duration': 'microseconds',
                'attempted': 'unknown_exclude_entire_window', 'duplicates': 'retain_and_flag',
                'member': self.member, 'synthetic': self.synthetic}

    def validate_source(self, member):
        if member != self.member or member not in DATES or member not in self.allowed_members:
            raise ValueError('Member is not explicitly registered/approved for this corrected study')

    def normalize_headers(self, header):
        names = [name.strip() for name in header]
        if len(set(names)) != len(names):
            raise ValueError('Corrected schema has duplicate header names')
        missing = set(REQUIRED) - set(names)
        if missing:
            raise ValueError(f'Corrected schema missing required columns: {sorted(missing)}')
        return names

    def parse_row(self, row):
        raw_time = row['Timestamp'].strip()
        try:
            start = datetime.strptime(raw_time, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            try:
                start = datetime.strptime(raw_time, '%Y-%m-%d %H:%M:%S')
            except ValueError as exc:
                raise ValueError('invalid_corrected_timestamp') from exc
        # CSV has no zone marker; release documentation defines UTC. Store a UTC-normalized
        # naive value to match existing SQL timestamp columns, with policy on source metadata.
        start = start.replace(tzinfo=timezone.utc).astimezone(timezone.utc).replace(tzinfo=None)
        if start.date().isoformat() != DATES[self.member]:
            raise ValueError('timestamp_member_date_mismatch')
        duration = integer(row['Flow Duration'], 'duration')
        try:
            end = start + timedelta(microseconds=duration)
        except OverflowError as exc:
            raise ValueError('duration_timestamp_overflow') from exc
        packets = integer(row['Total Fwd Packet'], 'packets') + integer(row['Total Bwd packets'], 'packets')
        size = integer(row['Total Length of Fwd Packet'], 'bytes') + integer(row['Total Length of Bwd Packet'], 'bytes')
        if max(packets, size) > 2**63-1:
            raise ValueError('aggregate_overflow')
        label, target, _, _ = corrected_label(row['Label'], row['Attempted Category'])
        return (row['Flow ID'], str(ipaddress.ip_address(row['Src IP'].strip())),
                str(ipaddress.ip_address(row['Dst IP'].strip())),
                integer(row['Src Port'], 'src_port', 65535), integer(row['Dst Port'], 'dst_port', 65535),
                integer(row['Protocol'], 'protocol', 255), row['Timestamp'], start, end,
                end.date() == start.date(), duration, packets, size,
                optional_rate(row.get('Flow Bytes/s')), optional_rate(row.get('Flow Packets/s')),
                row['Label'], label, target)

    def provenance(self, row):
        return {name: row[name] for name in REQUIRED}

    def record_hash(self, row):
        # The generated id identifies a record; exclude it from content-duplication flags.
        return hashlib.sha256(json.dumps({k:v for k,v in row.items() if k != 'id'},
                                        sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def audit_archive(archive, members, output, *, protocol_sha256=None):
    """Audit only explicitly selected members. No fitting, no database, no source changes."""
    archive, output = Path(archive), Path(output)
    output.mkdir(parents=True, exist_ok=False)
    archive_hash = file_hash(archive)
    adapter_hash = file_hash(Path(__file__))
    audits, families, support = [], [], []
    with zipfile.ZipFile(archive) as z:
        inventory = [{'member':i.filename, 'bytes':i.file_size, 'selected':i.filename in members}
                     for i in z.infolist()]
        (output/'archive_inventory.json').write_text(json.dumps(inventory, indent=2))
        for member in members:
            adapter = CorrectedAdapter(member, members)
            digest, size = stream_hash(archive, member)
            counts, raw_labels, accepted_labels, statuses, rejections = [Counter() for _ in range(5)]
            windows, family_support, seen = {}, defaultdict(Counter), set()
            with z.open(member) as stream, (output/f'{Path(member).stem}_quarantine.jsonl').open('w', encoding='utf-8') as quarantine:
                reader = csv.reader(io.TextIOWrapper(stream, encoding=adapter.encoding, newline=''))
                raw_header = next(reader)
                header = adapter.normalize_headers(raw_header)
                for number, values in enumerate(reader, 2):
                    counts['input_rows'] += 1
                    try:
                        if len(values) != len(header) or not any(v.strip() for v in values):
                            raise ValueError('empty_or_wrong_column_count')
                        row = dict(zip(header, values))
                        raw_labels[row['Label']] += 1
                        parsed = adapter.parse_row(row)
                        label, target, family, status = corrected_label(row['Label'], row['Attempted Category'])
                        statuses[status] += 1
                        accepted_labels[label] += 1
                        counts['accepted_rows'] += 1
                        content_hash = adapter.record_hash(row)
                        counts['duplicate_content_rows_excluding_id'] += int(content_hash in seen)
                        seen.add(content_hash)
                        counts['timestamp_fractional_rows'] += int(parsed[7].microsecond != 0)
                        counts['missing_or_invalid_bytes_rate'] += int(parsed[13] is None)
                        counts['missing_or_invalid_packets_rate'] += int(parsed[14] is None)
                        for name in REQUIRED:
                            counts['missing_required_cells'] += int(not row[name].strip())
                        group = family_support[label]
                        group['accepted_rows'] += 1
                        group['temporally_eligible_rows'] += int(parsed[9])
                        if not parsed[9]:
                            counts['cross_day_completion_excluded'] += 1
                            continue
                        counts['temporally_eligible_rows'] += 1
                        bucket = parsed[8].replace(minute=parsed[8].minute//5*5, second=0, microsecond=0)
                        key = (parsed[1], bucket)
                        w = windows.setdefault(key, {'flows':0, 'attack':0, 'unknown':0, 'families':set(),
                            'min_flow_start':parsed[7],'max_flow_end':parsed[8]})
                        w['flows'] += 1; w['attack'] += int(target is True); w['unknown'] += int(target is None)
                        w['min_flow_start']=min(w['min_flow_start'],parsed[7])
                        w['max_flow_end']=max(w['max_flow_end'],parsed[8])
                        if family and family != 'BENIGN':
                            w['families'].add(family)
                    except (ValueError, OverflowError) as exc:
                        counts['rejected_rows'] += 1
                        reason = str(exc)[:180]
                        rejections[reason] += 1
                        quarantine.write(json.dumps({'csv_record_number':number, 'reason':reason, 'raw_row':values}, ensure_ascii=False)+'\n')
            assert counts['input_rows'] == counts['accepted_rows'] + counts['rejected_rows']
            assert sum(w['flows'] for w in windows.values()) == counts['temporally_eligible_rows']
            for name in ['input_rows','accepted_rows','rejected_rows','temporally_eligible_rows',
                         'duplicate_content_rows_excluding_id','cross_day_completion_excluded',
                         'timestamp_fractional_rows','missing_required_cells',
                         'missing_or_invalid_bytes_rate','missing_or_invalid_packets_rate']:
                counts.setdefault(name,0)
            unknown = sum(w['unknown'] > 0 for w in windows.values())
            known_positive = sum(w['attack'] > 0 and not w['unknown'] for w in windows.values())
            proxy_groups = {(src, family) for (src, _), w in windows.items() for family in w['families']}
            audit = {'member':member, 'release':RELEASE, 'archive_sha256':archive_hash,
                     'member_sha256':digest, 'member_bytes':size, 'raw_header':raw_header,
                     'normalized_header':header, 'adapter_identity':adapter.identity,
                     **dict(counts), 'rejection_reasons':dict(rejections), 'raw_label_counts':dict(raw_labels),
                     'accepted_label_counts':dict(accepted_labels), 'label_status_counts':dict(statuses),
                     'active_windows':len(windows), 'known_label_windows':len(windows)-unknown,
                     'unknown_excluded_windows':unknown, 'known_positive_windows':known_positive,
                     'annotated_episode_proxy_groups':len(proxy_groups),
                     'episode_warning':'day/source/family proxy; not a count of verified independent attacks'}
            audits.append(audit)
            for label, c in family_support.items(): families.append({'member':member,'label':label, **dict(c)})
            for (src, bucket), w in sorted(windows.items()):
                support.append({'member':member,'src_ip':src,'window_start':bucket.isoformat(),
                                'flows':w['flows'],'attack_flows':w['attack'],'unknown_flows':w['unknown'],
                                'families':json.dumps(sorted(w['families'])),
                                'min_flow_start':w['min_flow_start'].isoformat(),
                                'max_flow_end':w['max_flow_end'].isoformat()})
            (output/f'{Path(member).stem}_audit.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
            print(f"Audited {member}: {counts['input_rows']:,} rows; {len(windows):,} windows", flush=True)
    for filename, rows in [('attack_support.csv',families),('window_support.csv',support)]:
        if rows:
            with (output/filename).open('w', newline='', encoding='utf-8') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    if file_hash(Path(__file__))!=adapter_hash:
        raise ValueError('Adapter changed during audit; preserve partial output and start a new audit')
    result={'release':RELEASE,'archive_path':str(archive.resolve()),'archive_sha256':archive_hash,'members':audits,
            'adapter_code_sha256':adapter_hash,'protocol_sha256':protocol_sha256,
            'files':{p.relative_to(output).as_posix():file_hash(p) for p in sorted(output.rglob('*')) if p.is_file()},
            'scope':'source audit only; no new model performance; selected members only',
            'utc_policy':'release documentation; CSV itself has no explicit zone marker',
            'raw_access':'CSV records referenced by member/hash and record number; input archive remains unchanged'}
    (output/'audit_manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result
