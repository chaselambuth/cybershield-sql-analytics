"""Pin an existing experiment and collect read-only SQL audit evidence."""
import json
import shutil
import time

import pandas as pd

from cybershield.db import ROOT, file_hash
from cybershield.evaluate import frame
from cybershield.research import RESEARCH
from cybershield.source_audit import compare_sources
from cybershield.workspace import reader_connection


def main():
    snapshot = RESEARCH / 'snapshot'; snapshot.mkdir(parents=True, exist_ok=True)
    latest = json.loads((ROOT / 'reports/latest_real.json').read_text())
    run = ROOT / latest['output_directory']
    names = ['window_scores.csv', 'development_protocol.json', 'data_quality.json', 'artifact_manifest.json']
    for name in names:
        shutil.copyfile(run / name, snapshot / name)
    manifest = {'experiment_id': latest['experiment_id'], 'feature_run_id': latest['feature_run_id'],
        'schema': latest['schema'], 'snapshot_created_utc': pd.Timestamp.now(tz='UTC').isoformat(),
        'files': {name: file_hash(snapshot / name) for name in names},
        'source_run_directory': str(run.relative_to(ROOT)), 'read_only_research': True}
    (snapshot / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    feature_id = latest['feature_run_id']
    queries = {
        'source_provenance': '''SELECT s.* FROM source_file s JOIN feature_run r
            ON s.source_id=ANY(r.source_ids) WHERE r.feature_run_id=%s''',
        'ingestion': '''SELECT i.* FROM ingestion_run i JOIN feature_run r
            ON i.source_id=ANY(r.source_ids) WHERE r.feature_run_id=%s ORDER BY i.started_at''',
        'flow_quality': '''SELECT count(*) AS accepted_rows,
            count(*) FILTER (WHERE clock_usable) AS clock_usable_rows,
            count(*) FILTER (WHERE bytes_per_second IS NULL) AS missing_bytes_rate,
            count(*) FILTER (WHERE packets_per_second IS NULL) AS missing_packets_rate,
            count(*)-count(DISTINCT record_hash) AS duplicate_content_rows
            FROM flow f JOIN feature_run r ON f.source_id=ANY(r.source_ids)
            WHERE r.feature_run_id=%s''',
        'flow_labels': '''SELECT l.label,count(*) AS flows,
            count(*) FILTER (WHERE f.clock_usable) AS temporal_eligible_flows
            FROM flow f JOIN flow_label l USING(flow_id)
            JOIN feature_run r ON f.source_id=ANY(r.source_ids)
            WHERE r.feature_run_id=%s GROUP BY l.label ORDER BY flows DESC''',
        'attack_sources': '''SELECT host(f.src_ip) AS src_ip,count(*) AS attack_flows,
            count(*) FILTER (WHERE f.clock_usable) AS temporal_eligible_attack_flows
            FROM flow f JOIN flow_label l USING(flow_id)
            JOIN feature_run r ON f.source_id=ANY(r.source_ids)
            WHERE r.feature_run_id=%s AND l.is_attack GROUP BY f.src_ip ORDER BY attack_flows DESC''',
        'feature_fetch': '''SELECT host(f.src_ip) AS src_ip,f.window_start,f.flow_count,f.unique_ports,
            f.unique_destinations,f.service_flows,f.packets,f.bytes,f.mean_duration_us
            FROM window_features f WHERE feature_run_id=%s ORDER BY window_start,src_ip''',
    }
    output = RESEARCH / 'sql_audit'; output.mkdir(parents=True, exist_ok=True)
    with reader_connection('real') as conn:
        conn.execute("SET LOCAL statement_timeout='60s'")
        conn.execute("SET LOCAL idle_in_transaction_session_timeout='60s'")
        assert conn.execute('SHOW transaction_read_only').fetchone()[0] == 'on'
        for name, query in queries.items():
            table = frame(conn, query, (feature_id,))
            table.to_csv(output / f'{name}.csv', index=False)
        times = []
        frame(conn, queries['feature_fetch'], (feature_id,))  # Warm cache.
        for repeat in range(10):
            started = time.perf_counter_ns()
            fetched = frame(conn, queries['feature_fetch'], (feature_id,))
            times.append({'repeat': repeat, 'rows': len(fetched),
                          'sql_fetch_dataframe_ms': (time.perf_counter_ns() - started) / 1e6})
        pd.DataFrame(times).to_csv(output / 'feature_fetch_latency.csv', index=False)
    (output / 'queries.json').write_text(json.dumps({'feature_run_id': feature_id, 'queries': queries}, indent=2))
    comparison, _, _, _, decision = compare_sources()
    print(comparison.to_string(index=False))
    print(json.dumps(decision, indent=2))


if __name__ == '__main__':
    main()
