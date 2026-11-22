# SQL evidence lookup: measuring the source/time index

The partial index already defined in `001_core.sql` lets PostgreSQL narrow an investigation by source and reported-completion time together. This experiment measures that choice on **250,000 generated flow rows**, with the same ordered lookup results before and after enabling the index. It does not change the application schema or its saved detector results.

## Query and comparison

The task is to retrieve up to 25 supporting records for one source in a half-open five-minute window:

```sql
SELECT flow_id, host(src_ip), host(dst_ip), dst_port,
       reported_end, packets, bytes
FROM flow
WHERE src_ip = $1::inet AND clock_usable
  AND reported_end >= $2
  AND reported_end < $2 + interval '5 minutes'
ORDER BY reported_end, flow_id
LIMIT 25;
```

The treatment is the existing partial B-tree:

```sql
CREATE INDEX flow_source_time_idx
ON flow (src_ip, reported_end)
WHERE clock_usable;
```

The baseline retains the time-only partial index, primary key, source/row unique index and record-hash index. This compares the additional source/time index against an already indexed table.

## Recorded local results

Recorded November 20, 2026, America/New_York, using PostgreSQL 16.15 in a disposable synthetic schema in the local Linux Docker database. [Exact samples, settings, result hashes and representative plans](../reports/sql_performance/summary.json) are retained in a compact JSON artifact. This rerun uses the reviewed result checks under `python -O`; it replaces the earlier unpublished microbenchmark snapshot.

| Measure | Without source/time index | With source/time index |
|---|---:|---:|
| Server execution median | 0.0910 ms | 0.0190 ms |
| Server execution P95 | 0.1510 ms | 0.0220 ms |
| Median shared-buffer hits per lookup | 37 | 5 |
| Median shared-buffer reads per lookup | 0 | 0 |
| Timed calls | 80 | 80 |
| Ordered results | Identical in all four cases | Identical in all four cases |

The representative baseline plan uses a bitmap scan of `flow_end_idx`, then filters by source: 852 candidate rows become two returned rows, with 850 removed by the source filter. With the composite index, an index scan applies both source and time conditions and an incremental sort completes the ordering.

The added index occupies **7,495,680 bytes (7.15 MiB)**. Two measured builds took **121.2 and 121.5 ms**. The table occupies approximately 63.05 MiB, excluding indexes. Sustained ingestion overhead was not measured.

## Protocol and limits

The script applies the actual migrations in a generated `cs_test_perf_*` schema, then inserts deterministic synthetic rows directly. This isolates query execution from parser, ingestion and model behavior. Four fixed source/window cases run in **without / with / with / without** order; each case receives three warm-ups and ten measured calls per phase. `EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON)` supplies server timings and buffer counts. Empty or changed ordered results raise a runtime error, including under `python -O`. Twelve comparisons against the four baseline result hashes establish the report's `equal_ordered_results` field; that field is derived from completed checks.

Both configurations are warm-cache measurements with zero median physical reads. The absolute difference is small, and EXPLAIN instrumentation affects these short calls. These samples do not establish production latency, statistical significance, real-data speedup, cold-cache behavior, concurrent throughput or reduced analyst time. Generated addresses, times and fixed row sizes differ from the real source. Client transfer, HTTP, feature construction, ingestion and fitting are outside the timer.

## Reproduce

Start the dedicated PostgreSQL service and use the configured project environment:

```powershell
docker compose up -d --wait
.\.venv\Scripts\python.exe scripts/benchmark_sql.py
```

The default output is ignored at `.tmp/sql_performance.json`; use `--output PATH` to keep another run. The script creates and removes only its own generated schema, leaving `cs_fixture`, `cs_tuesday` and corrected-study schemas intact. The recorded artifact binds the exact script hash; rerun timings will vary by machine and load.
