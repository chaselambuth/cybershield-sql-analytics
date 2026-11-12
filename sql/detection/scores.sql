-- Native interpretable rule scores. Gates/scales are versioned per experiment.
WITH scores AS (
SELECT feature_run_id,host(src_ip) AS src_ip,window_start,
       flow_count / %(volume_scale)s::float8 AS rule_volume,
       CASE WHEN flow_count >= 10 THEN unique_ports / %(ports_scale)s::float8 ELSE 0 END AS rule_ports,
       service_flows / %(services_scale)s::float8 AS rule_services
FROM window_features WHERE feature_run_id=%(feature_run_id)s
)
SELECT *,greatest(rule_volume,rule_ports,rule_services) AS sql_combined
FROM scores ORDER BY window_start,src_ip;

