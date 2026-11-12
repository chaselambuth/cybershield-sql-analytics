# Project walkthrough

CyberShield Analytics is a solo project by Chase Lambuth.

CyberShield demonstrates an inspectable analytics workflow: a security analyst can rank suspicious five-minute source windows, inspect the original supporting flows, and compare transparent SQL rules with measured ML alternatives. The main engineering contribution is the path from validated records to reproducible evidence; the current Tuesday experiment is a limited development study.

## 1. Inspect the SQL implementation

Start with [source windows](../sql/features/source_windows.sql): `date_bin`, distinct counts, filtered service aggregates and elapsed-time `RANGE` history. Read [separate label construction](../sql/features/window_labels.sql) to see how retrospective targets stay outside feature generation. Then inspect [rule scores](../sql/detection/scores.sql) and [supporting-flow retrieval](../sql/reporting/supporting_flows.sql).

These files implement PostgreSQL feature engineering, relational lineage, half-open time bins, and inspectable ranking. Python provides parsing, orchestration, models and plots. Historical summaries describe observed active windows; absent windows do not prove zero traffic or sensor coverage.

## 2. Read three experiments in order

| Experiment | Read without running anything | What to look for |
|---|---|---|
| Source fitness | [Notebook 1](../notebooks/01_data_audit_and_source_selection.ipynb) | Reconciled row counts, clock defects, one-source attack concentration, corrected-release recommendation and unresolved labels. |
| Model selection evidence | [Notebook 2](../notebooks/02_model_quality_latency.ipynb) | Eight fixed configurations; caught/total attack windows, false/total benign alerts, training cost and actual single-call latency. |
| Controlled sensitivity | [Notebook 3](../notebooks/03_sql_feature_ablation_and_alert_budgets.ipynb) | Fixed estimator, feature-group removals, four calibration budgets, matching baseline decisions and concrete errors. |

Notebook 1 chooses a future source on data fitness. Notebooks 2 and 3 keep the current source fixed so that model and feature comparisons do not silently change populations. The [generated findings](../reports/research/findings.md) summarize measured results; the [notebook guide](../notebooks/README.md) explains reruns and hashes.

## 3. Follow an alert to its evidence

Launch the local [SQL workspace](query_workspace.md) with `Open CyberShield.cmd`. Inspect the label-free `v_triage_queue`, filter to `split='development'`, and examine supporting flow IDs and source-file record numbers. Join labels separately for retrospective error analysis. The [Power BI report](../power_bi/README.md) offers the same investigative story through source quality, security investigations, and model quality/cost pages.

The [investigation agent](investigation_agent.md) is an additional interface over bounded read-only evidence tools. Its cited brief and tool trace demonstrate orchestration; it does not replace the SQL implementation or validate the detectors.

## 4. Interpret the headline result

At the original calibration setting, the combined SQL rule catches 5/6 attack windows with 21/3,407 benign false alerts, compared with logistic regression's 5/6 and 64/3,407. That is useful evidence that added model complexity needs justification. Six correlated positive windows do not establish a generally superior detector. The eight-model benchmark and controlled feature removals expose tradeoffs that a single accuracy number would conceal.

The prototype excludes ambiguous afternoon times from scoring and has one dominant recorded attack source. Friday records are excluded here, but a prior acquisition preview prevents claiming an entirely untouched Friday holdout. These constraints determine the next experiment.

## Current extension and remaining work

The [corrected-data study](corrected_study.md) implements the corrected adapter, four-day ingestion, chronological roles, support gates and a matched model comparison. It remains separate from the historical application snapshot.

Further work includes independent attack-support adjudication, broader validation, measured SQL optimization with equal-result checks, and a portable fixture-based installation check. Existing execution plans are baseline measurements; no optimization speedup is claimed.
