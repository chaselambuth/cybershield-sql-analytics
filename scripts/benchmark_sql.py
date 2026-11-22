"""Measure the existing partial source/time index on a disposable synthetic workload."""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
import uuid
from datetime import datetime,timezone
from pathlib import Path

import numpy as np
from psycopg import sql
from cybershield.db import ROOT,connect,file_hash,migrate

QUERY="""SELECT flow_id,host(src_ip),host(dst_ip),dst_port,reported_end,packets,bytes
FROM flow
WHERE src_ip=%s::inet AND clock_usable
  AND reported_end >= %s AND reported_end < %s + interval '5 minutes'
ORDER BY reported_end,flow_id LIMIT 25"""
INDEX='CREATE INDEX flow_source_time_idx ON flow (src_ip,reported_end) WHERE clock_usable'


def digest(rows):
    return hashlib.sha256(json.dumps(rows,default=str,separators=(',',':')).encode()).hexdigest()


def check_result(reference,case,rows):
    if not rows:
        raise RuntimeError(f'Empty synthetic probe: {case}')
    actual=digest(rows)
    if case in reference and reference[case]!=actual:
        raise RuntimeError('Index changed the returned rows/order')
    reference[case]=actual
    return actual


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows',type=int,default=250_000)
    parser.add_argument('--repeats',type=int,default=10)
    parser.add_argument('--output',type=Path,default=ROOT/'.tmp/sql_performance.json')
    args=parser.parse_args()
    if args.rows<10_000 or args.repeats<3:
        parser.error('Use at least 10,000 synthetic rows and three repetitions.')
    schema='cs_test_perf_'+uuid.uuid4().hex[:10]
    results={};reference={};build_times=[];comparisons=0
    with connect(schema) as conn:
        try:
            migrate(conn,schema)
            source=conn.execute("""INSERT INTO source_file
                (filename,sha256,release,synthetic,bytes,header)
                VALUES ('generated_sql_workload',%s,'synthetic',true,0,'[]') RETURNING source_id""",('0'*64,)).fetchone()[0]
            run=uuid.uuid4()
            conn.execute("INSERT INTO ingestion_run(run_id,source_id,status) VALUES (%s,%s,'complete')",(run,source))
            # Synthetic physical rows only: this is not an ingestion or detector evaluation.
            conn.execute("""INSERT INTO flow(source_id,run_id,row_number,source_flow_id,record_hash,
                src_ip,dst_ip,src_port,dst_port,protocol,raw_timestamp,reported_start,reported_end,
                clock_usable,duration_us,packets,bytes)
                SELECT %s,%s,g+1,g::text,md5(g::text)||md5(g::text),
                    inet '10.0.0.1'+(g%%512),inet '10.1.0.1'+(g%%16),1024+g%%50000,
                    CASE WHEN g%%2=0 THEN 21 ELSE 443 END,6,'synthetic generated UTC-naive proxy',
                    timestamp '2017-07-04'+(g%%86400)*interval '1 second'-interval '1 millisecond',
                    timestamp '2017-07-04'+(g%%86400)*interval '1 second',g%%19<>0,1000,3,128
                FROM generate_series(1,%s) AS g""",(source,run,args.rows))
            conn.commit()
            conn.execute('ANALYZE flow');conn.commit()
            count,table_bytes=conn.execute('SELECT count(*),pg_table_size(\'flow\') FROM flow').fetchone()
            probes=conn.execute("""SELECT host(src_ip),date_bin(interval '5 minutes',reported_end,timestamp '2000-01-01')
                FROM flow WHERE flow_id=ANY(%s) ORDER BY flow_id""",
                ([int(args.rows*f) for f in (.1,.3,.6,.9)],)).fetchall()
            cases=[(ip,start,start) for ip,start in probes]
            server=conn.execute('SELECT version()').fetchone()[0]
            settings=dict(conn.execute("SELECT name,setting FROM pg_settings WHERE name IN ('shared_buffers','work_mem','max_parallel_workers_per_gather','jit')").fetchall())
            conn.commit()
            # ABBA order reduces a simple first/last phase effect. Warm each case
            # before measuring; the time-only and record-hash indexes stay in place.
            for phase,indexed in enumerate([False,True,True,False]):
                conn.execute('DROP INDEX IF EXISTS flow_source_time_idx')
                if indexed:
                    start=time.perf_counter();conn.execute(INDEX);conn.commit()
                    build_times.append((time.perf_counter()-start)*1000)
                    index_bytes=conn.execute("SELECT pg_relation_size('flow_source_time_idx')").fetchone()[0]
                conn.commit()
                label='with_source_time_index' if indexed else 'without_source_time_index'
                entry=results.setdefault(label,{'execution_ms':[],'shared_hit_blocks':[],
                    'shared_read_blocks':[],'representative_plan':None,'result_hashes':[]})
                for ci,params in enumerate(cases):
                    rows=conn.execute(QUERY,params).fetchall()
                    compared=ci in reference
                    actual=check_result(reference,ci,rows)
                    comparisons+=int(compared)
                    if actual not in entry['result_hashes']:entry['result_hashes'].append(actual)
                    for _ in range(3):conn.execute(QUERY,params).fetchall()
                    for _ in range(args.repeats):
                        plan=conn.execute('EXPLAIN (ANALYZE,BUFFERS,SETTINGS,FORMAT JSON) '+QUERY,params).fetchone()[0][0]
                        entry['execution_ms'].append(plan['Execution Time'])
                        entry['shared_hit_blocks'].append(plan['Plan'].get('Shared Hit Blocks',0))
                        entry['shared_read_blocks'].append(plan['Plan'].get('Shared Read Blocks',0))
                        if entry['representative_plan'] is None:entry['representative_plan']=plan
                conn.commit()
            for entry in results.values():
                entry['samples']=len(entry['execution_ms'])
                entry['execution_median_ms']=statistics.median(entry['execution_ms'])
                entry['execution_p95_ms']=float(np.quantile(entry['execution_ms'],.95))
                entry['shared_hit_blocks_median']=statistics.median(entry['shared_hit_blocks'])
                entry['shared_read_blocks_median']=statistics.median(entry['shared_read_blocks'])
            equal_ordered_results=bool(cases) and len(reference)==len(cases) and comparisons==3*len(cases)
            report={'recorded_utc':datetime.now(timezone.utc).isoformat(),
                'scope':'Synthetic warm-cache source/window evidence lookup; not real-data or end-to-end latency',
                'rows':count,'table_bytes':table_bytes,'server':server,'settings':settings,
                'script_sha256':file_hash(Path(__file__)),'query':QUERY,'index_ddl':INDEX,
                'other_indexes':'Primary key, source/row unique, time-only partial index and record-hash index retained',
                'phase_order':['without','with','with','without'],'cases':[(ip,str(start)) for ip,start in probes],
                'warmups_per_case_per_phase':3,'repeats_per_case_per_phase':args.repeats,
                'equal_ordered_results':equal_ordered_results,'ordered_result_comparisons':comparisons,'index_bytes':index_bytes,
                'index_build_ms':build_times,'results':results,
                'limitations':['One local PostgreSQL container; no concurrency or cold-cache experiment',
                    'Generated addresses/times and fixed row widths do not represent the real traffic distribution',
                    'EXPLAIN server execution excludes client, HTTP, ingestion, fitting and investigation time',
                    'Index build/storage measured; sustained insert overhead was not measured']}
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
            print(json.dumps({'output':str(args.output),'rows':count,'equal_ordered_results':equal_ordered_results,
                'median_ms':{k:v['execution_median_ms'] for k,v in results.items()}}))
        finally:
            conn.rollback()
            conn.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
            conn.commit()


if __name__=='__main__':main()
