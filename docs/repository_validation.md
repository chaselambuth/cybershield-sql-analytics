# Validation — November 12, 2026

The [validation summary](../reports/validation/summary.json) records the checks and repository size. Notebook hashes and execution provenance are in [the execution manifest](../reports/research/notebook_execution.json).

- Notebook 01 completed a fresh clean-kernel run.
- All three canonical notebooks contain complete, error-free saved outputs. Notebooks 02/03 retain their recorded executions; their code, outputs and results are unchanged.
- Offline tests: **91 passed**, with 8 PostgreSQL integration tests excluded. Dependency deprecation warnings remain visible in pytest output.
- The curated prototype report verifies all **21 artifact hashes**. Frozen scientific inputs and results remain unchanged.
- File-format, source syntax, notebook layout, secret-token and local Markdown-link checks cover the tracked files. Static SQL parsing does not establish database execution.

```powershell
.\.venv\Scripts\python.exe scripts/verify_research.py
.\.venv\Scripts\python.exe -m cybershield verify reports/prototype
.\.venv\Scripts\python.exe -m pip check
```

Generated notebook copies, HTML exports, synthetic CSVs and superseded audit records are excluded from Git. The historical research manifest remains an input-provenance record; current notebook verification uses the dedicated execution manifest.

The PostgreSQL integration tests were not rerun for this validation. It does not establish a new model benchmark, live provider evaluation, fresh Power BI Desktop validation or production readiness.
