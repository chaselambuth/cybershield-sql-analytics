-- Audit concentration: repeated windows do not equal independent attacks.
SELECT host(f.src_ip) AS src_ip,count(*) AS windows,
       count(*) FILTER (WHERE l.attack_flows>0) AS positive_windows,
       sum(l.attack_flows) AS attack_flows,
       min(f.window_start) AS first_window,max(f.window_start) AS last_window
FROM window_features f JOIN window_label l USING(feature_run_id,src_ip,window_start)
WHERE f.feature_run_id=%(feature_run_id)s GROUP BY f.src_ip
ORDER BY positive_windows DESC,attack_flows DESC,src_ip;

