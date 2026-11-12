-- Post-scoring labels join here; the triage queue itself never contains labels.
SELECT p.method,p.split,count(*) AS windows,
       count(*) FILTER (WHERE p.predicted_attack AND l.attack_flows>0) AS tp,
       count(*) FILTER (WHERE p.predicted_attack AND l.attack_flows=0) AS fp,
       count(*) FILTER (WHERE NOT p.predicted_attack AND l.attack_flows>0) AS fn,
       count(*) FILTER (WHERE NOT p.predicted_attack AND l.attack_flows=0) AS tn
FROM prediction p JOIN window_label l USING(feature_run_id,src_ip,window_start)
WHERE p.experiment_id=%(experiment_id)s AND l.unknown_flows=0
GROUP BY p.method,p.split ORDER BY p.split,p.method;

