# Local validation and automated checks

The [machine-readable summary](../reports/validation/summary.json) records the latest local results. The [GitHub Actions workflow](../.github/workflows/validate.yml) defines two jobs: portable Python checks and PostgreSQL 16 integration plus synthetic HTTP verification. A hosted Actions result exists only after the workflow is pushed and runs on GitHub.

## Saved-result verification and screenshot refresh - November 22, 2026

The full Windows suite passed 124 Python tests, including seven new saved-result integrity cases. The saved comparison verifier checks its registration, protocol, 17 output hashes, population, model/budget coverage and recomputed confusion counts independently of routine edits to current producer files. A regression case applies a comment-only producer edit: saved-result verification succeeds, while the optional strict producer audit rejects it. Refitting retains the original strict source and dependency checks. The portable CI job now also verifies the headline comparison; no hosted run is claimed before pushing.

The SQL chart, reference-workbench overview and expanded-evidence screenshots were refreshed in place using the default dark theme. The SQL example plotted all four returned rows as a line chart. The free reference investigation completed with five tool calls, zero tokens and zero estimated API cost; its trace now identifies reference steps without implying an LLM chose them. The expanded-evidence minus glyph was corrected. Original detector results, timings, protocol and source registration remain unchanged.

```powershell
.\.venv\Scripts\python.exe -m cybershield verify reports/neural_comparison_v1 --registration-sha256 f3382bd99e8d30e43fb3fc8b693d774e08e542901bcde2f1bdad552e3887a98c
# Optional: also audit the current checkout against the original producer.
.\.venv\Scripts\python.exe -m cybershield verify reports/neural_comparison_v1 --registration-sha256 f3382bd99e8d30e43fb3fc8b693d774e08e542901bcde2f1bdad552e3887a98c --check-producer
```

## Default website theme and alignment - November 22, 2026

The architecture-inspired styling shown in the README now loads by default on both the SQL explorer and Investigations pages, without a preview parameter. The shared theme uses the SQL explorer's page width and responsive padding. A stable scrollbar gutter prevents centered content from shifting when only one page needs a scrollbar. Both views share title and subtitle typography, sidebar geometry and primary-action button sizing.

Browser measurements after page initialization confirmed identical title positions at 2560, 1280 and 390 pixels wide, with no horizontal page overflow. The saved traffic query returned four hourly rows and plotted all four returned rows. All 43 affected workspace, agent and SQL-assistant tests passed, including local database and prepared-bundle checks. No paid provider calls, detector refitting or new latency measurements were made. At that stage, the last full Python-suite run was the November 21 record below.

## Earlier verification - November 21, 2026

The Windows suite passed 117 Python tests: 100 portable checks, eight PostgreSQL integration checks and nine prepared-bundle checks. This includes the four neural-comparison tests. All seven JavaScript chart tests also passed using the bundled Node runtime. The saved-result verifier checked all 17 registered files and recomputed the matched confusion counts and calibration allowances. The current comparison replaces Linear SVM and Extra Trees with the neural MLP and autoencoder; it reuses previously inspected validation windows and provides no independent final holdout.

The dated summary now binds the current README, shared templates, architecture-preview stylesheet and neural comparison to repository-relative hashes. Validation records are consolidated there rather than published as a second neural-specific receipt. The walkthrough points to the revised chart, and the report discloses that the stopped implementation attempt had already saved the same validation scores before the thread-setting check was corrected. These documentation fixes do not change the registered protocol, model code, results or measured latency.

The earlier Linux installation/integration and wheel checks remain under their original dates below; they are not a fresh Linux or hosted CI run for this version. The interface measurements in the supplied review confirmed matching sidebar and navigation geometry and matching titles in architecture-preview mode. Differences in default-style title typography, primary-button styling and reference trace wording remain optional follow-up items. No paid provider calls or Power BI Desktop refresh were made for these fixes.

## Earlier review fixes and verification - November 20, 2026

The November 20 Windows working tree passed **113 Python tests**: 96 portable checks, eight PostgreSQL integration checks and nine prepared-bundle checks. **Seven JavaScript tests** passed, including regressions for line gaps, invalid values, isolated points and display caps. A real database/browser check confirmed that a missing middle value leaves its horizontal position empty and cannot connect its neighbours. The singular omission caption and saved-query accessibility label were also checked.

The lighter PostgreSQL CI job was reproduced from a clean candidate-source export in a fresh Python 3.12 Linux container with its own disposable PostgreSQL 16 database. All **eight integration tests** passed; the synthetic pipeline produced **8,802 accepted flows and 708 windows**, and all **six HTTP example queries** passed. Draft requests without a page token and destructive SQL were rejected. The export contained no credentials, raw data, local Python environment or reporting bundle. No hosted Actions run or new Linux portable-suite run is claimed here.

An actual wheel build succeeded, and its shared templates and static assets were checked against the source inventory. All three notebook hashes, 21 prototype output hashes and 38 scientific input hashes remain valid. The synthetic SQL-index experiment was rerun under `python -O` with always-on ordered-result checks; [its dated measurements](sql_performance.md) are separate from detector results.

That snapshot binds the November 20 reviewed code to repository-relative hashes and keeps older validation snapshots under their original dates. The November 19 pre-fix review passed 95 portable Python tests and four chart tests; the November 14 totals below describe that earlier code, not the current interface. Existing NumPy/Pandas timedelta deprecation warnings remain visible. No live-provider quality evaluation, real-data model fitting or new Power BI Desktop refresh was performed in that review.

`requirements.lock` is a verified Windows environment snapshot. Linux can resolve platform-only dependencies outside that file's pins; it is not a complete Linux lock. The portable job retains the full research environment. The PostgreSQL job installs the constrained runtime/development dependencies plus `psutil`, which its corrected-study test imports require, without the boosting/notebook stack. The clean Linux dependency list is retained locally with the review results.

`evaluate.py` remains hash-bound to the original benchmark. Its historical manifest writer is preserved; compatible readers accept its Windows-style paths. New run-output manifests use forward slashes. Power BI project context now stores an internal bundle path relative to the repository; the launcher still accepts an existing absolute path.

## Question-and-chart extension - November 14, 2026

The later SQL-workspace review passed **112 Python tests** in the current Windows environment, including eight PostgreSQL checks, nine prepared-bundle checks and eleven new SQL-drafting tests. **Four JavaScript tests** cover chart numeric handling, missing/unsafe values, row order and display caps. The synthetic HTTP checker also verifies the new interface, status route and page-token requirement without calling a model.

The browser review used a saved traffic question against the actual Tuesday PostgreSQL dataset and verified table, bar and line views. The [workspace guide](query_workspace.md#ask-with-plain-english) explains the schema-only drafting boundary, explicit SQL review and separate read-only execution. Provider responses were mocked; this is not a live-model quality evaluation. No paid provider calls or new detector study were run. The earlier Windows/Linux clean-environment results below remain a separate snapshot, retained in `prior_readiness_review` in the machine-readable summary.

To run the chart checks with Node's built-in test runner:

```powershell
node --test tests/test_charts.cjs
```

## Earlier fresh-environment verification

The local review used source exports from tracked paths plus the pending project additions. Credentials, raw archives, generated reporting bundles, existing Python environments and local run directories were excluded. Windows used a newly created Python 3.12 environment installed from `requirements.lock`, followed by an editable project install. Linux used a disposable Python 3.12 container with Git and `libgomp1`. This verifies the local working-tree snapshot; it is not a checkout of a newly published commit.

Both platforms use disposable PostgreSQL databases, separate from the existing project database and volume. The integration tests create generated `cs_test_*` schemas; workspace checks also create and remove a generated reader role. The synthetic quickstart creates `cs_fixture` only inside the disposable database.

| Check | Windows | Linux container |
|---|---:|---:|
| Portable tests | 84 passed | 84 passed |
| PostgreSQL integration tests | 8 passed | 8 passed |
| Synthetic pipeline and six HTTP queries | Passed | Passed |
| Dependency, notebook and prototype integrity checks | Passed | Passed |

The nine reporting-bundle tests also passed separately against the existing verified local bundle. They were excluded from both fresh source exports.

The review verifies:

- Saved outputs and hashes for all three canonical notebooks, plus all 21 prototype report hashes.
- Portable parser, protocol, model, reporting, integrity and SQL-boundary tests without a prepared reporting bundle.
- PostgreSQL ingestion reconciliation, idempotency, rollback/retry, corrected provenance, temporal features and reader privileges.
- A synthetic pipeline with **8,804 input rows, 8,802 accepted rows, two quarantined rows and 708 source windows**.
- A real local HTTP server running all **six built-in SQL examples**, loading fixture metadata and rejecting a destructive statement.
- Legacy Windows-style artifact paths on both platforms, without rewriting frozen manifests or changing their identities.
- All 38 frozen scientific input hashes and three notebook hashes also match the committed Git blobs, preventing a local line-ending conversion from masking a checkout mismatch.

Exact platform versions, passing test counts and the current benchmark identity are in the summary. NumPy/Pandas timedelta deprecation warnings remain visible; they are not suppressed or reported as failures. The local Linux container approximates the workflow commands; it does not establish a hosted `ubuntu-latest` run.

## Reproduce the checks

After the README installation steps, portable checks require no database, raw data or API key:

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe scripts/verify_research.py
.\.venv\Scripts\python.exe -m cybershield verify reports/prototype
.\.venv\Scripts\python.exe -m pytest -m "not integration and not reporting_bundle" -q
```

Database tests use generated synthetic data and do not require the real Tuesday load:

```powershell
docker compose up -d --wait
.\.venv\Scripts\python.exe -m pytest -m integration -q
.\.venv\Scripts\python.exe -m cybershield run --mode fixture
.\.venv\Scripts\python.exe scripts/check_quickstart.py
```

The HTTP checker starts its own loopback server on an available port and terminates it afterward. It makes no agent or provider calls. The workflow's PostgreSQL service follows [GitHub's documented service-container pattern](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers).

The nine tests marked `reporting_bundle` require a locally prepared, verified Power BI/agent bundle:

```powershell
.\.venv\Scripts\python.exe -m pytest -m reporting_bundle -q
```

Prepare that bundle following the [Power BI guide](../power_bi/README.md). These checks are intentionally excluded from fresh-checkout CI; they are not silently skipped and counted as passed. They use the reference/scripted agent paths without paid model requests.

## Evidence and scope

The [synthetic SQL index experiment](sql_performance.md) retains repeated execution samples, representative plans, identical ordered-result hashes, buffer counts and index storage/build costs. It is a separate microbenchmark, outside the detector study and ordinary pass/fail CI.

Notebook execution provenance remains in the [dedicated manifest](../reports/research/notebook_execution.json). Notebook 01's successful clean execution was recorded November 12; Notebooks 02/03 retain their earlier executions. This review verifies them without refitting the real-data research models. Historical research manifests remain unchanged.

The earlier November 12 review recorded 91 offline passes with eight database checks excluded. The current review adds isolated database and fresh-install evidence, along with two regression cases for portable manifest paths. It does not establish a new real-data detector benchmark, live-provider evaluation, fresh Power BI Desktop validation or production readiness. No demonstration video is included; the walkthrough contains a recording outline.
