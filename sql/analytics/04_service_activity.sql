-- Network flows to ports 21/22 do not establish failed authentication.
SELECT host(src_ip) AS src_ip,window_start,flow_count,service_flows,
       service_flows::float8/flow_count AS service_share
FROM window_features WHERE feature_run_id=%(feature_run_id)s AND service_flows>0
ORDER BY service_flows DESC,window_start,src_ip LIMIT 100;

