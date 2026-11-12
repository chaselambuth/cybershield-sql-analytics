# CyberShield Power BI

A locally saved **CyberShield.pbix** contains the report with imported data; it is not tracked in Git. For the editable project, open **CyberShield.pbip**, or double-click **Open CyberShield Power BI.cmd** in the project root. The launcher verifies the selected bundle's hashes before opening the project. There are three main pages and a hidden supporting-flow drill-through page.

- **Data quality:** ingestion reconciliation and candidate metrics, with explicit scope/policy/status. Unknown UNSW values are not zero defects.
- **Security investigations:** observed traffic, prototype decisions, false-alert sources, and supporting records. The Filters pane initially selects development and combined SQL. Change those explicit filters to inspect other roles/detectors. Select a window row to filter flows, or right-click its window key and use **Drill through → Flow evidence**.
- **Model quality and cost:** eight measured ML configurations and combined SQL. Quality stays on 6 positive / 3,407 benign development windows from one correlated campaign. Timing defaults to pipeline / batch 1; change scope/batch in the Filters pane. Source/time selections do not change fixed-cohort quality.

Power BI reads **one prepared local file bundle**, using only its packed `report_data.json` as the physical Power Query source. Separate CSVs/schema/manifest remain available for verification and review, but are not combined as separate private-file connections. PostgreSQL is required to regenerate supporting flows, not to refresh the report. Refresh does not fit models, recalibrate, publish data, or change the application.

## First refresh

A locally saved PBIX and project cache already contain the verified data. Opening them does not require PostgreSQL. Refresh uses the selected bundle's local path; moving the report to another computer requires copying the bundle and updating `BundleRoot` before refresh.

Select **Home → Refresh → Schema and data** (or the page's **Refresh now** banner). If Desktop requests privacy classification, classify the enabled local source entries (Private is appropriate for this research bundle) and save. Leave **Ignore Privacy Levels checks** disabled. These settings are not automated or committed. No cloud sign-in is needed.

A newly generated project's local cache starts empty. Save after refresh so Desktop keeps its cache. Cache/local-settings files are ignored by Git. Moving files requires deliberate source-path reconfiguration; the project never discovers a different bundle automatically.

## Rebuild

Close the report before regenerating definitions to avoid Desktop overwriting external edits. From the project root, with its PostgreSQL container running:

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[reporting]'
.\.venv\Scripts\python.exe scripts/prepare_power_bi.py
# Use the exact Prepared path printed above, not first/latest directory order.
.\.venv\Scripts\python.exe scripts/build_power_bi_project.py --bundle 'C:\absolute\path\to\the\prepared\bundle_ID'
.\.venv\Scripts\python.exe scripts/validate_power_bi_project.py
.\.venv\Scripts\python.exe scripts/open_power_bi.py
```

Preparation validates scientific hashes, all detector evaluations, SQL decisions, per-window flow membership, and timing groups before publishing a new immutable bundle. Existing matching bundles are verified/reused; they are not overwritten. Failed staging folders are retained for diagnosis and never selected.

Offline verification:

```powershell
.\.venv\Scripts\python.exe scripts/prepare_power_bi.py --verify 'C:\absolute\path\to\the\selected\bundle_ID'
```

The Power Query loader checks the packed payload's identity, validation status, schema, columns, rows and key uniqueness. SHA-256 checks run in preparation/verification and the launcher; they are not claimed as automatic Power Query cryptographic checks. `BundleRoot` selects a directory and `ExpectedPayloadId` binds the project to that payload. The external manifest/launcher separately verify the full bundle identity. Regenerate with a new validated bundle to switch deliberately.

## Evidence and precision

Benchmark identity covers scientific inputs/code/protocol and measured results, excluding notebooks, HTML and figures. Bundle identity separately binds reporting code, schema and exports. `project_context.json` records the selected bundle and Desktop-validation status.

Historical XGBoost scores require documented float32 restoration before float64 comparison. Naive float64 CSV parsing changes tied decisions. Its defective `calibration_false_alerts` field is excluded for every model; original benchmark artifacts remain unchanged. All models expose tie concentration, including random forest and constant-score controls. SVM margins, probability-like scores and rule scales never share a raw-score comparison axis.

Warm CPU timing includes preprocessing in `pipeline` and excludes it in `model_only` (estimator-only). Batch 1 has 60 calls; larger batches have 25. Percentiles are descriptive, not SLAs/confidence bounds. Three training fits support median/max. SQL controls have no invented model-call timings.

## Reviewable files

- `CyberShield.SemanticModel/definition/`: TMDL tables, Power Query and DAX; six single-direction relationships; Auto date/time disabled.
- `CyberShield.Report/definition/`: PBIR pages, filters, visuals and drill-through.
- `measures.dax`, `power_query.m`: readable generated definitions.
- `validation/project_schema.json`: schema-validation evidence; Desktop results are recorded separately after actual refresh.
- `validation/desktop_dax.json`, `implementation_status.json`: actual Desktop reconciliation and completed UI checks.
- `data/bundle_*/manifest.json`, `schema.json`, `validation.json`: local identity, types and reconciliations. Generated large exports are ignored by Git; regenerate the approximately 207k-row flow table.

Corrected-source audit evidence is not corrected-source model performance; unscored windows are not test results; six correlated positives are not six independent attacks.

## Completed verification

Validated in Power BI Desktop 2.159.883.0: import, save/reopen, native window-to-flow drill-through, 11,398 windows, 207,006 supporting flows, 91,184 prototype decisions, all 15 detector quality rows, and 64 latency groups. The Python suite passed 54 tests. Screenshots of the three main pages are in `screenshots/`.

Desktop upgraded some visual definitions to schema 2.14.0, whose Microsoft schema URL returns 404. The 33 saved JSON files pass structural validation using the published 2.3.0 visual schema where needed; this limitation and the exact replacements are recorded. Recheck a Desktop-saved project with `scripts/validate_power_bi_project.py --allow-published-schema-fallback`. Exact-schema validation remains the default for newly generated projects.
