# Corrected-data development study

This study is an opt-in extension of CyberShield. The original Tuesday application, historical reports, investigation agent and Power BI bundle remain separate. The new commands do not update application pointers or import a new dashboard bundle automatically.

## What is implemented

`cybershield.corrected` validates the CNS2022 schema, explicit UTC clock and microsecond durations, endpoint fields, integer counts and label policy. Accepted records retain their raw time, duration, label, source-record ID and attempted-category text through an additive provenance table. Source/archive hashes and CSV record numbers remain available. Repeated content is flagged and retained. Unknown or attempted labels stay unknown; any affected window is excluded from binary evaluation.

The original streaming `ingest` function accepts an explicit adapter. Its default original-format Tuesday behavior is preserved. Corrected ingestion requires a fresh `cs_study_*` schema (or a generated test schema); it cannot silently load into `cs_tuesday`. The additive migration creates `flow_provenance` and does not replace existing tables or modify old migration bytes.

`cybershield.protocol` assigns whole source-by-five-minute windows to chronological roles, checks all contributing flow starts, enforces temporal gaps, detects attack-family/source/day groups crossing roles, and writes support reports. Labels remain outside the reused feature SQL and alert-ranking view. Source identity may recur across roles; source-disjoint generalization is not claimed.

`cybershield.study` registers exact protocol, source archive, dependency and source-code identities. A registration also saves the source bytes. Preparation binds the SQL feature run, normalized source IDs, window input and split membership. Evaluation requires separately supplied expected design/input hashes. A change requires a new registration, not silent replacement of a frozen run.

`cybershield.study_benchmark` reuses the existing eight fixed CPU configurations, conservative `calibrate` function and metric definitions. It evaluates the combined SQL rule and always-benign control separately, using identical known-label windows. Model-native scores are explicitly promoted to float64 before calibration/comparison; CSV serialization uses 17 significant digits and round-trip parsing. Verification recomputes calibration allowances and confusion counts from saved scores and cutoffs.

## Registered protocol revisions

The first source-support design is preserved in `configs/corrected_development_v1.json`. Its calibration interval yielded only 60 known-benign windows, failing the prespecified minimum of 100. No corrected-data model was fitted or scored to select that interval.

The explicitly disclosed second design, `configs/corrected_development_v2.json`, extends calibration by 30 minutes and preserves the 65-minute embargo. Its changes were made using source-support counts before new model-quality evaluation. Candidates, features, target mapping, operating budgets and minimum support were unchanged. `source_support_v1` and `source_support_v2` preserve both outcomes. The tracked role-support tables and gate records preserve the failed and accepted screens; full generated audit packages remain local.

| Role | v2 interval, UTC; half-open |
|---|---|
| Training | July 3, 2017 00:00 through July 5 00:00 |
| Calibration | July 5 01:05 through July 5 12:30 |
| Validation | July 5 13:35 through July 7 00:00 |

An assigned window's entire five-minute extent and all constituent flow starts must fit within one role. Unassigned/embargo/boundary windows remain in the source audit with reasons. Friday is excluded. Its earlier acquisition preview is disclosed; there is no pristine or sealed final test in this workflow.

Episodes are conservative **UTC day + source + annotated base attack family** proxies. Attempted labels link to the same base family for overlap checks. An arbitrary idle gap never creates another episode. Larger source/day dependency blocks expose shared actors/families. These definitions prevent obvious campaign fragments from crossing assigned roles but do not prove statistical independence or exclude all cross-day campaign dependence.

The screen requires both training classes, two positive training groups, two positive validation groups, two positive validation days, two positive validation dependency blocks and 100 known-benign calibration windows. Passing authorizes only descriptive development/validation comparison. It does not authorize independent-episode confidence intervals, a production claim, final-test selection or MLP training.

## Source audit and reconciled support

The four-day adapter audit parsed 1,552,419 rows, with zero required-field rejections and zero observed duplicate-content rows under its declared definition. Subsequent PostgreSQL preparation independently loaded and reconciled those rows. Tuesday reconciles to 322,078 records and 39 unresolved attempted-label rows. The corrected and original releases share the same capture; they are not independent validation datasets.

| Day | Accepted audit rows | Active windows | Known-label windows | Unknown/excluded windows | Known positive windows |
|---|---:|---:|---:|---:|---:|
| Monday | 371,624 | 1,397 | 1,397 | 0 | 0 |
| Tuesday | 322,078 | 1,514 | 1,509 | 5 | 24 |
| Wednesday | 496,641 | 1,477 | 1,459 | 18 | 7 |
| Thursday | 362,076 | 1,398 | 1,377 | 21 | 14 |
| Total | 1,552,419 | 5,786 | 5,742 | 44 | 45 |

| v2 role | All active windows | Known windows | Unknown/excluded | Known positive | Known benign |
|---|---:|---:|---:|---:|---:|
| Training | 2,911 | 2,906 | 5 | 24 | 2,882 |
| Calibration | 152 | 152 | 0 | 0 | 152 |
| Validation | 2,513 | 2,485 | 28 | 21 | 2,464 |
| Unscored | 210 | 199 | 11 | 0 | 199 |

The source-only support audit finds seven positive validation annotation groups, four positive source/day dependency blocks and three positive sources across two days. Thirty-two source addresses occur in both training and validation. The subsequent PostgreSQL preparation independently reconciled all 5,786 source-window keys, flow/target counts and time bounds to that audit. Re-ingesting real corrected Tuesday preserved the 1,552,419 normalized rows and four completed ingestion runs.

With 152 calibration negatives, the 1% allowance is **one** benign calibration alert. Prespecified sensitivity targets 0.1%, 0.5% and 2% allow zero, zero and three, respectively. Ties can reduce achieved alerts further. A common budget does not guarantee identical achieved false-alert rates across methods or on validation data.

## Newly measured validation result

Run `9ef6eb5b-5439-4b25-8f97-c88eb8e14b04` completed with 2,485 known-label validation windows: 21 positive and 2,464 benign. At the common 1% benign calibration budget, CatBoost caught 17 positives with 18 false alerts; the combined SQL rule caught 11 with 9. Logistic regression caught none with 24 false alerts. These are separate methods; the result does not introduce a fused detector or select a universal winner.

The paired outcomes matter: CatBoost and SQL both caught ten positives; CatBoost alone caught seven; SQL alone caught one; both missed three. The additional detection and false-alert burden must be judged against a declared review capacity. The original Tuesday results have different source/split/support and remain separate.

Strict unknown-window exclusion removes all known-positive validation support for DoS Hulk, web brute force and XSS. The scored positives cover five base families with overlapping membership. Twenty-one positive windows are not 21 independent attacks. See the [class-coverage addendum](../reports/changes/2026-11-08/presentation_v1/validation_family_coverage.csv) and [comparison figure](../reports/changes/2026-11-08/presentation_v1/validation_comparison.png).

The saved design hash is `58c89d45db658372f95a32461634ccaece2726bae0af1dd73cc02d508d3f0599`; prepared-input hash is `5b5b33e1d074283cab7d20ff0979ae1b40fc1e0974d4fc65a0e635b0f8d9eb0b`. The verified result directory is `reports/studies/corrected_development_v2_20261108_live`. All eight saved model artifacts reproduce their saved scores bit for bit. MLP, independent-episode confidence intervals and final-test generalization remain deferred.

## Run commands

Run from the project root in PowerShell. Input paths must point to locally stored archives obtained from the official release. Commands do not download data or call the agent provider.

```powershell
# Source audit only: choose a NEW output directory on every attempt.
.\.venv\Scripts\python.exe -m cybershield.study audit --archive data/raw/CICIDS2017_improved.zip --protocol configs/corrected_development_v2.json --output reports/changes/my_new_audit

# Derive source-support tables; no model fitting or SQL features are claimed.
.\.venv\Scripts\python.exe -m cybershield.study audit-support --bundle reports/changes/my_new_audit --protocol configs/corrected_development_v2.json --output reports/changes/my_new_support

# Create a fresh design registration and save its printed directory and expected hash.
.\.venv\Scripts\python.exe -m cybershield.study register --archive data/raw/CICIDS2017_improved.zip --protocol configs/corrected_development_v2.json
```

Use the exact directory and hash returned by registration for `prepare`. A registration attempt already marked blocked/failed is preserved; create a fresh run rather than overwriting it. The following are command templates: replace the bracketed tokens with values saved from the preceding commands, not a freshly recomputed hash of changed files.

```powershell
docker compose up -d --wait
.\.venv\Scripts\python.exe -m cybershield.study prepare --run '<REGISTERED_DIRECTORY>' --design-sha256 '<SAVED_DESIGN_HASH>'

# Only after preparation succeeds, save its prepared_sha256 and inspect support_gate.json.
.\.venv\Scripts\python.exe -m cybershield.study benchmark --run '<REGISTERED_DIRECTORY>' --design-sha256 '<SAVED_DESIGN_HASH>' --prepared-sha256 '<SAVED_INPUT_HASH>'
.\.venv\Scripts\python.exe -m cybershield.study verify --run '<REGISTERED_DIRECTORY>' --design-sha256 '<SAVED_DESIGN_HASH>' --prepared-sha256 '<SAVED_INPUT_HASH>'
```

The CLI requires both expected hashes explicitly. Local receipts are conveniences, not tamper-proof external registrations or permission to call this a final-test seal. There is deliberately no final-test scoring command.

If the support gate fails, evaluation saves support and limitations without fitting models or producing a performance headline. If PostgreSQL is unavailable, preparation records its failed/blocked attempt before any claim of a new feature run. Do not substitute source-audit counts or synthetic fixture outputs for database-backed benchmark results.

## Outputs and timing

A prepared run contains ingestion audits, source/feature IDs, exact split membership, window data, role/day/source/episode support, and a prepared-input manifest. A completed comparison adds scores, per-budget cutoffs, exact metrics, paired decisions, day/source/family/episode breakdowns, model files, preprocessing parameters, repeated fit/latency measurements, environment, plots and result hashes.

All eight models use train-only imputation/transformation/class weighting. Rule reference scales use training-benign windows. Cutoffs use only known-benign calibration windows. Validation labels never set preprocessing, class weights, scales or cutoffs. Average precision is reported by its actual definition; it is not silently substituted for a separately computed trapezoidal PR area.

Timing uses three interleaved fits, one thread, five warmups, 60 single-row calls and 25 larger-batch calls at sizes 32, 256 and the full validation population. Pipeline timing includes fitted preprocessing. Estimator-only timing excludes preprocessing. Both exclude SQL feature construction/retrieval, file/model loading, network, HTTP, serialization, cold starts, flow export and window waiting. A separate single full-population SQL-score-query wall time is not comparable to warm single-row model P95. The measured model frontier does not select a universal winner.

Raw per-window counts and paired overlap are reported. Episode/family tables may overlap and are not additive. False alerts are review-burden proxies, not measured analyst hours. No window-level bootstrap confidence intervals are produced. The optional MLP is explicitly deferred pending independently reviewed episodes and stronger support; no neural result or GPU requirement is invented.

## Notebook verification and application compatibility

The published notebooks and their execution hashes are stored once, under `notebooks/` and `reports/research/notebook_execution.json`. Optional reruns create isolated local outputs; generated copies and HTML exports are excluded from Git.

```powershell
.\.venv\Scripts\python.exe scripts/verify_research.py
.\.venv\Scripts\python.exe scripts/execute_research_notebooks.py
.\.venv\Scripts\python.exe -m pytest -m 'not integration' -q --tb=short --basetemp=.pytest_tmp_offline
.\.venv\Scripts\python.exe -m pytest -m integration -q --tb=short --basetemp=.pytest_tmp_db
```

New study results are not automatically compatible with the original Power BI semantic model or agent evidence store. The original experiment tables also have prototype role/status constraints; this study stores new evaluation records in its explicitly identified file bundle. A chosen new experiment needs an explicit, validated reporting/export adapter before downstream import. Existing saved dashboards remain based on their frozen local data.

## Source attribution and remaining uncertainty

The release authors document UTC microsecond timestamps in [Tools and Documentation](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html); their [CICFlowMeter implementation](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) specifies duration in microseconds. The [label documentation](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html) supplies capture/attack annotations. [Download guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) discusses attempted traffic; this study takes the conservative unresolved/exclusion policy rather than treating it as a new model class.

Cite Liu, Engelen, Lynar, Essam and Joosen, *Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS 2022, and the original CIC-IDS2017 attribution in the README. The local corrected ZIP inventory contains CSV files, not a separate license file. Local hashes identify supplied bytes; no independent provider checksum or general redistribution permission has been attested. Raw archives and raw-row quarantine records are excluded from version control and were not uploaded externally.

The source population remains a dated laboratory capture with shared infrastructure, small positive window support and uncertain campaign independence. Full-day clock formatting and a functioning adapter do not establish realistic detection delay or generalization to contemporary enterprise networks.
