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

Notebook 1 motivates the corrected source on data fitness; that recommendation is now implemented in the separate four-day study. Notebooks 2 and 3 retain the original source so that their model and feature comparisons do not silently change populations. The [generated findings](../reports/research/findings.md) summarize measured results; the [notebook guide](../notebooks/README.md) explains reruns and hashes.

## 3. Follow an alert to its evidence

Start with [the recorded 670-flow alert investigation](alert_investigation.md): it connects a ranked window to its SQL score, source record numbers and retrospective annotations. All referenced evidence is tracked for offline inspection.

Launch the local [SQL workspace](query_workspace.md) with `Open CyberShield.cmd`. Inspect the label-free `v_triage_queue`, filter to `split='development'`, and examine supporting flow IDs and source-file record numbers. Join labels separately for retrospective error analysis. The [Power BI report](../power_bi/README.md) offers the same investigative story through source quality, security investigations, and model quality/cost pages.

The [investigation agent](investigation_agent.md) is an additional interface over bounded read-only evidence tools. Its cited brief and tool trace demonstrate orchestration; it does not replace the SQL implementation or validate the detectors.

## 4. Interpret the headline result

The current corrected four-day comparison includes six classical models, a neural MLP, a neural autoencoder, the combined SQL rule and an always-benign control on 21 positive and 2,464 benign validation windows. CatBoost catches 17 positives with 18 false alerts; the combined SQL rule catches 11 with 9. The autoencoder catches 9 with 1 false alert, while the MLP catches none with 50. The [full comparison chart](../reports/neural_comparison_v1/comparison.png) shows all ten methods. These outcomes describe a detection/false-alert tradeoff on correlated windows, not a universal model winner.

The neural models replace Linear SVM and Extra Trees after inspection of the earlier validation results. The same validation windows are reused; this revision does not create an independent final holdout. The original registered roster and results remain in the study guide for provenance.

In the separate original Tuesday experiment, the combined SQL rule catches 5/6 attack windows with 21/3,407 benign false alerts, compared with logistic regression's 5/6 and 64/3,407. The later eight-model Tuesday benchmark includes CatBoost at 5/6 and 57/3,407; the earlier four-method prototype chart does not. The [670-flow case analysis](alert_investigation.md) explains a SQL alert from that original population. Its evidence should not be combined with corrected-study metrics as though they came from one experiment.

The prototype excludes ambiguous afternoon times from scoring and has one dominant recorded attack source. Friday records are excluded here, but a prior acquisition preview prevents claiming an entirely untouched Friday holdout. These constraints determine the next experiment.

## Current extension and remaining work

The [corrected-data study](corrected_study.md) implements the corrected adapter, four-day ingestion, chronological roles, support gates and a matched model comparison. It remains separate from the historical application snapshot.

The [SQL index experiment](sql_performance.md) now measures a synthetic supporting-record lookup with equal-result checks, query plans, buffer counts and storage cost. The [validation guide](repository_validation.md) records fresh-environment installation and synthetic workflow checks. Broader real-data performance work, independent attack-support adjudication and capture-independent validation remain open.

## A three-minute demonstration

1. **0:00-0:30:** Show the architecture and state the source-window grain. Explain that the synthetic quickstart and recorded real-data results have separate populations.
2. **0:30-1:15:** Open the synthetic SQL workspace, run the highest-priority-window example, then inspect service traffic and supporting records. Point out the read-only query boundary.
3. **1:15-2:00:** Use the recorded [670-flow alert](alert_investigation.md) to explain its service score, cutoff and original record references. If the reporting bundle is prepared, show the reference investigation and its evidence trace; disclose that reference mode makes no LLM calls.
4. **2:00-3:00:** Show the corrected-study detection/false-alert tradeoff, one measured SQL plan comparison, and the validation results. Finish with the limit: these are retrospective development studies with correlated windows.

This is a recording outline; no video is included. The SQL quickstart can be demonstrated without archives or an API key, while the agent requires its separately prepared reporting bundle.
