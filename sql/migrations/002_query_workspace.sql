-- Stable, latest-run views for exploration: avoid counting repeated feature runs.
CREATE VIEW latest_experiment AS
SELECT * FROM experiment_run ORDER BY created_at DESC,experiment_id DESC LIMIT 1;

CREATE VIEW latest_features AS
SELECT f.* FROM window_features f
JOIN latest_experiment e USING (feature_run_id);

CREATE VIEW latest_window_labels AS
SELECT l.* FROM window_label l
JOIN latest_experiment e USING (feature_run_id);

CREATE VIEW latest_predictions AS
SELECT p.* FROM prediction p JOIN latest_experiment e USING (experiment_id,feature_run_id);

CREATE VIEW latest_triage AS
SELECT q.* FROM v_triage_queue q JOIN latest_experiment e USING (experiment_id,feature_run_id);

