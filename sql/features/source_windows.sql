-- One active source per five-minute availability-proxy window.
-- Labels are deliberately absent. Historical mean covers observed ACTIVE windows;
-- it does not fabricate zeros or claim complete sensor coverage.
WITH buckets AS (
    SELECT src_ip,date_bin(interval '5 minutes',reported_end,timestamp '2000-01-01') AS window_start,
           count(*) AS flow_count,count(DISTINCT dst_port) AS unique_ports,
           count(DISTINCT dst_ip) AS unique_destinations,
           count(*) FILTER (WHERE dst_port IN (21,22)) AS service_flows,
           sum(packets) AS packets,sum(bytes) AS bytes,avg(duration_us) AS mean_duration_us
    FROM flow WHERE clock_usable AND source_id=ANY(%(source_ids)s)
    GROUP BY src_ip,window_start
), history AS (
    SELECT *,avg(flow_count) OVER w AS historical_mean,count(*) OVER w AS historical_windows
    FROM buckets
    WINDOW w AS (PARTITION BY src_ip ORDER BY window_start
       RANGE BETWEEN interval '60 minutes' PRECEDING AND interval '5 minutes' PRECEDING)
)
INSERT INTO window_features
SELECT %(feature_run_id)s,src_ip,window_start,flow_count,unique_ports,unique_destinations,
       service_flows,packets,bytes,mean_duration_us,historical_mean,historical_windows,
       flow_count / NULLIF(historical_mean,0)
FROM history;

