-- Retrospective WINDOW transitions. No assertion about within-minute sequence.
WITH transitions AS (
    SELECT host(src_ip) AS src_ip,window_start,flow_count,
           lag(flow_count) OVER w AS previous_count,
           lead(flow_count) OVER w AS next_count,
           extract(epoch FROM window_start-lag(window_start) OVER w)/60 AS gap_minutes
    FROM window_features WHERE feature_run_id=%(feature_run_id)s
    WINDOW w AS (PARTITION BY src_ip ORDER BY window_start)
)
SELECT * FROM transitions WHERE previous_count IS NOT NULL
ORDER BY abs(flow_count-previous_count) DESC,window_start,src_ip LIMIT 100;

