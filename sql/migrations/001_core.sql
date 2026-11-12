CREATE TABLE source_file (
    source_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    filename text NOT NULL,
    sha256 text NOT NULL CHECK (length(sha256) = 64),
    archive_sha256 text,
    release text NOT NULL,
    synthetic boolean NOT NULL,
    bytes bigint NOT NULL,
    header jsonb NOT NULL,
    UNIQUE (sha256, filename)
);
CREATE TABLE ingestion_run (
    run_id uuid PRIMARY KEY,
    source_id bigint NOT NULL REFERENCES source_file,
    status text NOT NULL CHECK (status IN ('running','complete','failed','skipped')),
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    input_rows bigint NOT NULL DEFAULT 0,
    accepted_rows bigint NOT NULL DEFAULT 0,
    rejected_rows bigint NOT NULL DEFAULT 0,
    audit jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE quarantine_record (
    run_id uuid NOT NULL REFERENCES ingestion_run,
    row_number bigint NOT NULL,
    reason text NOT NULL,
    raw_row jsonb NOT NULL,
    PRIMARY KEY (run_id, row_number)
);
CREATE TABLE flow (
    flow_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id bigint NOT NULL REFERENCES source_file,
    run_id uuid NOT NULL REFERENCES ingestion_run,
    row_number bigint NOT NULL,
    source_flow_id text NOT NULL,
    record_hash text NOT NULL,
    src_ip inet NOT NULL,
    dst_ip inet NOT NULL,
    src_port integer NOT NULL CHECK (src_port BETWEEN 0 AND 65535),
    dst_port integer NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
    protocol smallint NOT NULL CHECK (protocol BETWEEN 0 AND 255),
    raw_timestamp text NOT NULL,
    reported_start timestamp NOT NULL,
    reported_end timestamp NOT NULL,
    clock_usable boolean NOT NULL,
    duration_us bigint NOT NULL CHECK (duration_us >= 0),
    packets bigint NOT NULL CHECK (packets >= 0),
    bytes bigint NOT NULL CHECK (bytes >= 0),
    bytes_per_second double precision,
    packets_per_second double precision,
    UNIQUE (source_id, row_number)
);
CREATE INDEX flow_source_time_idx ON flow (src_ip, reported_end) WHERE clock_usable;
CREATE INDEX flow_end_idx ON flow (reported_end) WHERE clock_usable;
CREATE INDEX flow_record_hash_idx ON flow (record_hash);
CREATE TABLE flow_label (
    flow_id bigint PRIMARY KEY REFERENCES flow,
    label_raw text NOT NULL,
    label text NOT NULL,
    is_attack boolean
);
CREATE TABLE feature_run (
    feature_run_id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    config_sha256 text NOT NULL,
    sql_sha256 text NOT NULL,
    config jsonb NOT NULL,
    source_ids bigint[] NOT NULL
);
CREATE TABLE window_features (
    feature_run_id uuid NOT NULL REFERENCES feature_run,
    src_ip inet NOT NULL,
    window_start timestamp NOT NULL,
    flow_count bigint NOT NULL,
    unique_ports bigint NOT NULL,
    unique_destinations bigint NOT NULL,
    service_flows bigint NOT NULL,
    packets bigint NOT NULL,
    bytes bigint NOT NULL,
    mean_duration_us double precision NOT NULL,
    historical_mean double precision,
    historical_windows integer NOT NULL,
    volume_change double precision,
    PRIMARY KEY (feature_run_id, src_ip, window_start)
);
CREATE TABLE window_label (
    feature_run_id uuid NOT NULL,
    src_ip inet NOT NULL,
    window_start timestamp NOT NULL,
    attack_flows bigint NOT NULL,
    unknown_flows bigint NOT NULL,
    categories text[] NOT NULL,
    PRIMARY KEY (feature_run_id,src_ip,window_start),
    FOREIGN KEY (feature_run_id,src_ip,window_start) REFERENCES window_features
);
CREATE TABLE experiment_run (
    experiment_id uuid PRIMARY KEY,
    feature_run_id uuid NOT NULL REFERENCES feature_run,
    created_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status = 'development_only'),
    protocol_sha256 text NOT NULL,
    artifact_manifest jsonb NOT NULL,
    summary jsonb NOT NULL
);
CREATE TABLE rule_version (
    experiment_id uuid NOT NULL REFERENCES experiment_run,
    rule_name text NOT NULL,
    scale double precision NOT NULL CHECK (scale > 0),
    cutoff double precision NOT NULL,
    PRIMARY KEY (experiment_id,rule_name)
);
CREATE TABLE prediction (
    experiment_id uuid NOT NULL REFERENCES experiment_run,
    feature_run_id uuid NOT NULL,
    src_ip inet NOT NULL,
    window_start timestamp NOT NULL,
    method text NOT NULL,
    split text NOT NULL CHECK (split IN ('train','calibration','development','unscored')),
    score double precision NOT NULL,
    predicted_attack boolean NOT NULL,
    PRIMARY KEY (experiment_id,src_ip,window_start,method),
    FOREIGN KEY (feature_run_id,src_ip,window_start) REFERENCES window_features
);
CREATE VIEW v_triage_queue AS
SELECT p.experiment_id,p.feature_run_id,
       row_number() OVER (PARTITION BY p.experiment_id ORDER BY p.score DESC,p.window_start,p.src_ip) AS rank,
       p.src_ip,p.window_start,p.split,p.score,p.predicted_attack,
       f.flow_count,f.unique_ports,f.unique_destinations,f.service_flows,f.volume_change,
       (SELECT array_agg(r.rule_name ORDER BY r.rule_name)
        FROM prediction rp JOIN rule_version r USING (experiment_id)
        WHERE rp.experiment_id=p.experiment_id AND rp.src_ip=p.src_ip
          AND rp.window_start=p.window_start AND rp.method=r.rule_name
          AND rp.predicted_attack) AS fired_rules
FROM prediction p JOIN window_features f USING (feature_run_id,src_ip,window_start)
WHERE p.method='sql_combined';

