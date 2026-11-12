-- Candidates only: high port diversity is not proof of scanning.
SELECT host(src_ip) AS src_ip,window_start,flow_count,unique_ports,unique_destinations
FROM window_features WHERE feature_run_id=%(feature_run_id)s AND flow_count>=10
ORDER BY unique_ports DESC,flow_count DESC,window_start,src_ip LIMIT 100;

