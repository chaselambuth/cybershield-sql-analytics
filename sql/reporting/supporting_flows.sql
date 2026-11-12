-- Question: which original records support each pinned active source window?
-- Grain: one actual flow_id. Never use CIC's non-unique source_flow_id as a key.
-- Membership and clock bucket must agree with source_windows.sql/window_labels.sql.
-- A LEFT JOIN intentionally retains unmatched eligible records so preparation fails.
SELECT f.flow_id::text AS flow_id,f.source_id::text AS source_file_id,
       f.source_flow_id,host(f.src_ip) AS src_ip,host(f.dst_ip) AS dst_ip,
       f.src_port,f.dst_port,f.protocol,f.raw_timestamp,f.reported_start,f.reported_end,
       f.duration_us,f.packets,f.bytes,l.label AS retrospective_label,
       date_bin(interval '5 minutes',f.reported_end,timestamp '2000-01-01') AS window_start,
       w.feature_run_id::text AS matched_feature_run_id
FROM feature_run r
JOIN flow f ON f.source_id=ANY(r.source_ids)
JOIN flow_label l USING(flow_id)
LEFT JOIN window_features w ON w.feature_run_id=r.feature_run_id AND w.src_ip=f.src_ip
  AND w.window_start=date_bin(interval '5 minutes',f.reported_end,timestamp '2000-01-01')
WHERE r.feature_run_id=%(feature_run_id)s AND f.clock_usable
ORDER BY f.flow_id;
