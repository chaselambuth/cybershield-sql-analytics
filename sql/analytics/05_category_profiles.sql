-- Retrospective label-based analysis at flow grain, usable morning clocks only.
SELECT l.label,count(*) AS flows,count(DISTINCT f.src_ip) AS sources,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_us) AS median_duration_us,
       sum(f.bytes) AS total_bytes
FROM flow f JOIN flow_label l USING(flow_id)
WHERE f.clock_usable AND f.source_id=ANY(%(source_ids)s)
GROUP BY l.label ORDER BY flows DESC;

