# Measured research findings

All three notebooks contain completed executions. They do not modify the application source or model.

## Data source decision

**Select the CNS2022 corrected CIC-IDS2017 release for the next ingestion adapter.** The complete Tuesday audits favor it for explicit subsecond timestamps, usable full-day coverage, preserved endpoints and clearer label provenance. This decision concerns source fitness, not model accuracy.

| Tuesday audit | Original | Corrected |
|---|---:|---:|
| Input records | 445,909 | 322,078 |
| Temporally eligible records | 207,006 | 322,078 |
| Negative durations | 17 | 0 |
| Repeated content excluding row ID | 4 | 0 |
| Positive recorded sources | 1 | 1 |
| Unresolved attempted-label records | 0 | 39 |

The original follows the restricted unrepaired morning-clock policy; the corrected follows its explicit timestamp convention. Different extraction and labeling mean record/window counts are not one-to-one retention estimates. UNSW-NB15 is a third candidate reviewed from official documentation only: its official download returned 403, so no numeric quality or endpoint/time suitability is inferred.

Before corrected-source model use:

- Resolve attempted-label target policy and run sensitivity analysis.
- Audit semantic mappings and duration units against author code.
- Create a new UTC-aware ingestion adapter and frozen source manifest.
- Redesign splits around independent episodes; do not transplant original clock intervals.
- Audit other development days without evaluating a final holdout.

Both CIC releases still concentrate Tuesday attacks in one recorded source and share a capture. They do not provide independent validation. An acquisition preview read the corrected Friday header and first record; those are absent from these audit/model results. Do not call Friday entirely unseen.

## Eight-model development comparison

Fixed configurations; same seven SQL features and 3,413 known-label development windows (6 positive, 3,407 benign). Training and benign-only threshold calibration are separate. Adjacent roles can share one campaign. No reliable general model winner follows from this support.

| Method | Caught / 6 | False / 3,407 | AP | Single-window median / P95 ms | Fit median ms |
|---|---:|---:|---:|---:|---:|
| Random forest | 6 | 61 | 0.869 | 23.536 / 29.768 | 686.5 |
| Extra trees | 6 | 78 | 0.860 | 24.437 / 28.836 | 450.1 |
| LightGBM | 5 | 31 | 0.834 | 1.578 / 1.959 | 82.9 |
| Histogram boosting | 5 | 39 | 0.771 | 4.507 / 5.572 | 561.5 |
| CatBoost | 5 | 57 | 0.834 | 1.808 / 2.409 | 1186.5 |
| Logistic regression | 5 | 64 | 0.843 | 1.110 / 1.763 | 19.8 |
| Linear SVM | 5 | 118 | 0.834 | 1.101 / 1.669 | 27.7 |
| XGBoost | 4 | 0 | 0.667 | 1.454 / 2.103 | 115.4 |

These are warm CPU **pipeline** calls, including preprocessing. Single-window P95 is an empirical percentile from 60 calls. Three complete fits support median/max fit summaries. Batch throughput and estimator-only timing are recorded separately; amortized per-row time is not single-query latency. SQL feature retrieval is measured separately. Feature construction, HTTP, cold starts, flow export and window waiting are excluded.

The existing combined SQL rule caught 5/6 with 21 false alerts; it remains a useful quality reference. Its execution path was not timed as though it were a Python estimator.

Environment: Windows-11-10.0.26200-SP0; Intel64 Family 6 Model 183 Stepping 1, GenuineIntel; 24 physical / 32 logical CPUs; 31.7 GiB RAM; Python 3.12.14; one requested compute thread. Exact package versions, fixed parameters, cutoffs, per-window scores and raw repetitions are retained.

## Controlled SQL-feature and alert-budget experiments

Six logistic feature variants hold the estimator and chronological roles fixed. Four saved SQL rule scores provide additional controls. Each method is calibrated at 0.1%, 0.5%, 1% and 2% using known-benign calibration windows only. All 40 scenarios are reported; no budget or feature set is selected on development outcomes.

| Logistic variant at 1% calibration budget | Caught / 6 | False / 3,407 | Changed decisions vs full |
|---|---:|---:|---:|
| LR: all features | 5 | 64 | 0 |
| LR: without volume | 5 | 67 | 3 |
| LR: without diversity | 5 | 73 | 11 |
| LR: without services | 5 | 47 | 103 |
| LR: without size_duration | 5 | 70 | 6 |
| LR: flow count only | 4 | 34 | 81 |

Removing a feature group can change the fitted estimator and cutoff together. Differences are matched system observations, not causal feature effects. Correlated features and one attack source constrain transfer conclusions. The 1% full-feature logistic and combined SQL decisions reproduce the frozen prototype.

| Calibration budget | LR caught / false | Combined SQL caught / false |
|---|---:|---:|
| 0.1% | 5 / 31 | 5 / 2 |
| 0.5% | 5 / 38 | 5 / 8 |
| 1.0% | 5 / 64 | 5 / 21 |
| 2.0% | 6 / 104 | 5 / 67 |

Calibration budgets do not guarantee future false-alert rates. Per-window scores, exact calibration allowances, reference errors, source concentration and training-fitted parameters are saved in `robustness/`. No new latency measurement is claimed.

## Research and artifacts

- [Primary-source evidence review](../../docs/model_research_2026-10-24.md), current through October 24, 2026.
- [Data audit notebook](../../notebooks/01_data_audit_and_source_selection.ipynb).
- [Model notebook](../../notebooks/02_model_quality_latency.ipynb).
- [Controlled sensitivity notebook](../../notebooks/03_sql_feature_ablation_and_alert_budgets.ipynb).
- Raw measurements: `models/raw_latency.csv`, `models/raw_fit_times.csv`, `models/latency_by_batch.csv`.
- Data evidence: `sources/*_audit.json`, `sources/source_comparison.csv`, `sources/label_sensitivity.csv`.
- Frozen input files and hashes: `snapshot/manifest.json`. Overall output hashes: `research_manifest.json`.
- [Reproduction instructions](../../notebooks/README.md).
