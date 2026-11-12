-- Question: when does observed, usable morning-clock traffic change?
-- Grain: one five-minute bucket. Labels are retrospective, not predictors.
SELECT w.window_start,sum(w.flow_count)::bigint AS flows,
       sum(l.attack_flows)::bigint AS attack_flows,count(*) AS active_sources
FROM window_features w JOIN window_label l USING(feature_run_id,src_ip,window_start)
WHERE w.feature_run_id=%(feature_run_id)s
GROUP BY w.window_start ORDER BY w.window_start;

