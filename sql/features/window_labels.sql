-- Separate retrospective target construction after predictor materialization.
INSERT INTO window_label
SELECT %(feature_run_id)s,f.src_ip,
       date_bin(interval '5 minutes',f.reported_end,timestamp '2000-01-01'),
       count(*) FILTER (WHERE l.is_attack),count(*) FILTER (WHERE l.is_attack IS NULL),
       coalesce(array_agg(DISTINCT l.label ORDER BY l.label) FILTER (WHERE l.is_attack),'{}'::text[])
FROM flow f JOIN flow_label l USING (flow_id)
WHERE f.clock_usable AND f.source_id=ANY(%(source_ids)s)
GROUP BY f.src_ip,date_bin(interval '5 minutes',f.reported_end,timestamp '2000-01-01');

