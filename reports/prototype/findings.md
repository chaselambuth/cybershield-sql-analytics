# CyberShield Analytics — Prototype Findings

**REAL DATA: original CIC-IDS2017 Tuesday file**

**Development-only evaluation. No Friday data scored; no final benchmark claims.**

## Data reconciliation

- Input rows: 445,909; accepted: 445,892; quarantined: 17.
- Morning-clock records eligible for temporal features: 207,006.
- Repeated-content rows flagged and retained: 4.
- Benign calibration windows: 1,242; target: 10 false alerts per 1,000.

## Development comparison

| Method | Caught / attack windows | False alerts / benign windows | Precision |
|---|---:|---:|---:|
| rule_volume | 4 / 6 | 34 / 3407 | 0.105 |
| rule_ports | 0 / 6 | 30 / 3407 | 0.000 |
| rule_services | 5 / 6 | 31 / 3407 | 0.139 |
| sql_combined | 5 / 6 | 21 / 3407 | 0.192 |
| logistic_regression | 5 / 6 | 64 / 3407 | 0.072 |
| flow_count_baseline | 4 / 6 | 34 / 3407 | 0.105 |
| random_baseline | 0 / 6 | 28 / 3407 | 0.000 |
| always_benign | 0 / 6 | 0 / 3407 | undefined |

## Interpretation and limits

- All predictors, rolling summaries, and native rule scores are generated in PostgreSQL.
- The full selected file is ingested. Temporal analyses exclude reported hours 1–7 and 12, and flows ending at noon or later; raw values remain in the database.
- No AM/PM repair is applied. Clock values 8–11 are treated as morning based on the documented daytime capture; timezone remains unknown and timestamp precision is one minute.
- Completion time is a coarse proxy (minute-rounded start plus duration), not a measured arrival timestamp. Boundary membership can be uncertain.
- Adjacent development intervals can share one attack episode and source identity. Exact window counts do not represent independent attacks.
- Thresholds use benign calibration traffic only. The observed development false-alert rate can exceed the calibration target.
- Calibration has 1,242 benign windows. The final-study support gate also requires independent attack support, which this single-day prototype does not establish.
- Historical averages cover observed ACTIVE windows, excluding current and future windows; missing windows are not fabricated zeros. The ML baseline excludes history and raw identity.
- Sparse support prevents reliable uncertainty intervals. No generalization or real-time effectiveness claim is made.

## Outputs

- `triage_queue.csv` ranks windows without exposing ground-truth labels; `triage_evidence.csv` links sample supporting flows.
- `analytics/` contains eight inspectable query outputs; `metrics.csv` and `window_scores.csv` provide reproducible evaluation evidence.
- `development_protocol.json` records cutoffs/configuration; `artifact_manifest.json` records model, code, SQL, and library hashes.
- `figures/` contains activity, operating-point comparison, and precision-recall figures.
