# Research notebooks

The three notebooks separate source fitness, model tradeoffs, and sensitivity to SQL features and alert budgets.

| Notebook | Question | Evidence |
|---|---|---|
| [01 — Data audit](01_data_audit_and_source_selection.ipynb) | Which source supports source-by-time analysis? | Complete Tuesday audits of the original and corrected CIC-IDS2017 releases; documentation-only UNSW-NB15 review. |
| [02 — Model quality and latency](02_model_quality_latency.ipynb) | What quality and CPU-cost tradeoffs do fixed models offer? | Eight configurations, benign-only calibration, confusion counts, repeated fitting and warm prediction timings. |
| [03 — Feature ablation and alert budgets](03_sql_feature_ablation_and_alert_budgets.ipynb) | Which features and budgets change the decisions? | Six matched logistic variants, four SQL controls, four budgets and error analysis. |

## Run and verify

Use the project virtual environment with the research dependencies installed. Notebook 01 locates the local `src` package when opened from the project root or this directory. Its source audit requires the two local archives documented in [the dataset audit](../docs/dataset_audit.md).

```powershell
.\.venv\Scripts\python.exe scripts/verify_research.py
# Optional: execute isolated copies without replacing saved research inputs.
.\.venv\Scripts\python.exe scripts/execute_research_notebooks.py
```

The executor prints a new local bundle path. Verify that exact path with `scripts/verify_research.py --bundle '<PRINTED_PATH>'`. Add `03` to the executor command to run only the controlled experiment without raw archives or PostgreSQL.

Canonical notebooks are stored once in this directory. `reports/research/notebook_execution.json` records their hashes and execution provenance. Optional execution copies, generated HTML, checkpoints and raw archives stay out of Git.

## Interpretation limits

Notebooks 2 and 3 use the frozen original-source development population: 3,413 known-label windows, including six positives from a correlated campaign. The [corrected-data study](../docs/corrected_study.md) is separate. Source selection does not use model scores, and labels stay outside SQL feature generation.

The timing experiment excludes feature construction/retrieval, HTTP, loading, cold starts and attack-onset-to-alert delay. Notebook 3 makes no new latency claim. See the [project walkthrough](../docs/project_walkthrough.md), [research findings](../reports/research/findings.md), and [source/method review](../docs/model_research_2026-10-24.md).
