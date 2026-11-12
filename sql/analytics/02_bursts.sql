-- Question: which active source windows have the largest change from their
-- earlier observed ACTIVE windows? Missing history remains NULL (cold start).
SELECT host(src_ip) AS src_ip,window_start,flow_count,historical_mean,historical_windows,
       volume_change,dense_rank() OVER (ORDER BY volume_change DESC NULLS LAST) AS burst_rank
FROM window_features WHERE feature_run_id=%(feature_run_id)s
ORDER BY burst_rank,window_start,src_ip LIMIT 100;

