"""Tuesday-only archive audit. Source selection never depends on model scores."""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from .db import ROOT, file_hash
from .research import RESEARCH

ORIGINAL_MEMBER = 'TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv'
CORRECTED_MEMBER = 'tuesday.csv'


def audit_tuesday(archive, member, corrected=False):
    if (member, corrected) not in [(ORIGINAL_MEMBER, False), (CORRECTED_MEMBER, True)]:
        raise ValueError('This audit is restricted to Tuesday, never Friday')
    archive = Path(archive)
    with zipfile.ZipFile(archive) as z:
        with z.open(member) as stream:
            header = next(csv.reader(io.TextIOWrapper(stream, encoding='utf-8-sig')))
        with z.open(member) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        with z.open(member) as stream:
            raw = pd.read_csv(stream, low_memory=False)
    raw.columns = raw.columns.str.strip()
    names = {
        'src': 'Src IP' if corrected else 'Source IP',
        'dst': 'Dst IP' if corrected else 'Destination IP',
        'port': 'Dst Port' if corrected else 'Destination Port',
        'fwd_packets': 'Total Fwd Packet' if corrected else 'Total Fwd Packets',
        'back_packets': 'Total Bwd packets' if corrected else 'Total Backward Packets',
        'fwd_bytes': 'Total Length of Fwd Packet' if corrected else 'Total Length of Fwd Packets',
        'back_bytes': 'Total Length of Bwd Packet' if corrected else 'Total Length of Bwd Packets',
    }
    fmt = '%Y-%m-%d %H:%M:%S.%f' if corrected else '%d/%m/%Y %H:%M'
    starts = pd.to_datetime(raw.Timestamp, format=fmt, errors='coerce')
    duration = pd.to_numeric(raw['Flow Duration'], errors='coerce')
    packets = pd.to_numeric(raw[names['fwd_packets']], errors='coerce') + pd.to_numeric(raw[names['back_packets']], errors='coerce')
    byte_count = pd.to_numeric(raw[names['fwd_bytes']], errors='coerce') + pd.to_numeric(raw[names['back_bytes']], errors='coerce')
    ports = pd.to_numeric(raw[names['port']], errors='coerce')
    valid_numeric = np.isfinite(duration) & duration.ge(0)
    for field in ['fwd_packets', 'back_packets', 'fwd_bytes', 'back_bytes']:
        numeric_field = pd.to_numeric(raw[names[field]], errors='coerce')
        valid_numeric &= np.isfinite(numeric_field) & numeric_field.ge(0)
    def address_ok(value):
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False
    address_validity = {value: address_ok(value) for value in
                        pd.concat([raw[names['src']], raw[names['dst']]]).unique()}
    valid_addresses = raw[names['src']].map(address_validity) & raw[names['dst']].map(address_validity)
    # Bound conversion before creating timedeltas; no clock repair or AM/PM inference.
    safe_duration = duration.where(valid_numeric & duration.lt(86_400_000_000))
    ends = starts + pd.to_timedelta(safe_duration, unit='us')
    valid = valid_numeric & safe_duration.notna() & starts.notna() & ports.between(0, 65535) & valid_addresses
    temporal = valid if corrected else (valid & starts.dt.hour.between(8, 11) & ends.dt.hour.lt(12) & starts.dt.date.eq(ends.dt.date))
    labels = raw.Label.astype(str).str.strip()
    attempted = labels.str.contains('Attempted', case=False, regex=False)
    known = labels.isin(['BENIGN', 'FTP-Patator', 'SSH-Patator'])
    flows = pd.DataFrame({'src_ip': raw[names['src']], 'dst_ip': raw[names['dst']],
        'dst_port': ports, 'start': starts, 'end': ends, 'duration_us': duration,
        'packets': packets, 'bytes': byte_count, 'label': labels, 'attempted': attempted,
        'known': known, 'attack': labels.isin(['FTP-Patator', 'SSH-Patator'])})
    scoped = flows.loc[temporal].copy()
    scoped['window_start'] = scoped.end.dt.floor('5min')
    windows = scoped.groupby(['src_ip', 'window_start']).agg(
        flow_count=('src_ip', 'size'), attack_flows=('attack', 'sum'),
        unknown_flows=('known', lambda s: (~s).sum()), attempted_flows=('attempted', 'sum')).reset_index()
    content_columns = [c for c in raw if c != 'id']
    numeric = raw.select_dtypes(include='number')
    rates = {}
    for column in ['Flow Bytes/s', 'Flow Packets/s']:
        rates[column] = int((~np.isfinite(pd.to_numeric(raw[column], errors='coerce'))).sum())
    positive = windows.attack_flows.gt(0)
    audit = {
        'scope': 'complete Tuesday CSV only', 'archive_sha256': file_hash(archive),
        'member': member, 'member_sha256': digest, 'input_rows': len(raw),
        'columns': len(header), 'duplicate_header_names': [k for k, v in Counter(h.strip() for h in header).items() if v > 1],
        'header': header, 'label_counts': labels.value_counts().to_dict(),
        'timestamp_parse_failures': int(starts.isna().sum()),
        'invalid_numeric_required_rows': int((~valid_numeric).sum()),
        'invalid_address_rows': int((~valid_addresses).sum()),
        'required_fields_valid_rows': int(valid.sum()), 'temporal_eligible_rows': int(temporal.sum()),
        'negative_duration_rows': int(duration.lt(0).sum()),
        'nonfinite_rate_rows_by_column': rates,
        'numeric_columns_with_nonfinite': {c: int((~np.isfinite(numeric[c])).sum()) for c in numeric if (~np.isfinite(numeric[c])).any()},
        'duplicate_content_rows_excluding_id': int(raw[content_columns].duplicated().sum()),
        'missing_cells_by_column': {c: int(v) for c, v in raw.isna().sum().items() if v},
        'raw_timestamp_examples': raw.Timestamp.drop_duplicates().iloc[:5].tolist(),
        'timestamp_min': str(starts.min()), 'timestamp_max': str(starts.max()),
        'timestamp_microsecond_nonzero_rows': int((starts.notna() & starts.dt.microsecond.ne(0)).sum()),
        'timestamp_hour_counts': starts.dt.hour.value_counts().sort_index().to_dict(),
        'nonmonotonic_adjacent_start_steps': int(starts.diff().lt(pd.Timedelta(0)).sum()),
        'source_count': int(scoped.src_ip.nunique()), 'active_windows': len(windows),
        'positive_windows': int(positive.sum()), 'unknown_windows': int(windows.unknown_flows.gt(0).sum()),
        'positive_sources': int(windows.loc[positive, 'src_ip'].nunique()),
        'attempted_rows': int(attempted.sum()),
        'attempted_policy': 'unresolved; excluded from binary model targets pending a documented policy',
        'positive_windows_attempted_as_benign': int(positive.sum()),
        'positive_windows_attempted_as_attack': int((positive | windows.attempted_flows.gt(0)).sum()),
        'clock_policy': 'explicit date/time with fractional seconds; UTC according to author label documentation' if corrected else 'unrepaired minute clock; morning eligibility only',
    }
    return audit, scoped, windows


def compare_sources():
    output = RESEARCH / 'sources'; output.mkdir(parents=True, exist_ok=True)
    original_path = Path.home() / 'Downloads' / 'GeneratedLabelledFlows.zip'
    audits, hourly, window_tables = {}, {}, {}
    for key, path, member, corrected in [
        ('original', original_path, ORIGINAL_MEMBER, False),
        ('corrected', ROOT / 'data/raw/CICIDS2017_improved.zip', CORRECTED_MEMBER, True),
    ]:
        audit, flows, windows = audit_tuesday(path, member, corrected)
        if corrected:
            expected = json.loads(path.with_suffix('.download.json').read_text())['sha256']
            if audit['archive_sha256'] != expected:
                raise ValueError('Corrected archive differs from downloaded source manifest')
        else:
            expected = json.loads((RESEARCH / 'snapshot/data_quality.json').read_text())['sha256']
            if audit['member_sha256'] != expected:
                raise ValueError('Original Tuesday differs from frozen experiment source')
        audits[key] = audit
        (output / f'{key}_audit.json').write_text(json.dumps(audit, indent=2, default=str))
        windows.to_csv(output / f'{key}_windows.csv', index=False)
        hourly[key] = flows.groupby([flows.start.dt.hour, 'label']).size().unstack(fill_value=0)
        hourly[key].to_csv(output / f'{key}_hourly.csv')
        window_tables[key] = windows
    rows = []
    for key, a in audits.items():
        rows.append({'source': key, 'evidence': 'full Tuesday records audited',
            **{k: a[k] for k in ['input_rows', 'columns', 'negative_duration_rows',
            'duplicate_content_rows_excluding_id', 'temporal_eligible_rows', 'active_windows',
            'positive_windows', 'positive_sources', 'unknown_windows', 'attempted_rows']},
            'unambiguous_full_day_clock': key == 'corrected',
            'endpoint_fields': True, 'adapter_ready': key == 'original'})
    rows.append({'source': 'UNSW-NB15', 'evidence': 'official documentation only; download HTTP 403',
                 'unambiguous_full_day_clock': None, 'endpoint_fields': None, 'adapter_ready': False})
    comparison = pd.DataFrame(rows)
    comparison.to_csv(output / 'source_comparison.csv', index=False)
    decision = {'selected_for_next_data_adapter': 'corrected CIC-IDS2017, CNS2022 release',
        'active_prototype_source': 'original CIC-IDS2017 remains active',
        'decision_basis': 'Tuesday audit: explicit subsecond clocks preserve full-day temporal coverage and source/destination fields; richer attempted-label provenance.',
        'conditions_before_ml_use': ['Resolve attempted-label target policy and run sensitivity analysis.',
            'Audit semantic mappings and duration units against author code.',
            'Create a new UTC-aware ingestion adapter and frozen source manifest.',
            'Redesign splits around independent episodes; do not transplant original clock intervals.',
            'Audit other development days without evaluating a final holdout.'],
        'limitations': ['Tuesday-only comparison; no representative current enterprise traffic.',
            'Corrected and original share the same capture, so they are not independent validation sources.',
            'UNSW not numerically audited; cannot rank its quality empirically.',
            'An acquisition preview read the corrected Friday header and first record before Tuesday selection. Neither entered this audit or model comparison; do not claim Friday is entirely unseen.'],
        'unsw_download_check': {'status': 403, 'date': '2026-10-24 America/New_York',
            'url': 'https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS'}}
    # Fail rather than produce an evidence-free recommendation if the observed clock advantage disappears.
    if audits['corrected']['timestamp_parse_failures'] or audits['corrected']['negative_duration_rows']:
        decision['selected_for_next_data_adapter'] = 'needs manual review'
    (output / 'source_decision.json').write_text(json.dumps(decision, indent=2))
    return comparison, audits, hourly, window_tables, decision
