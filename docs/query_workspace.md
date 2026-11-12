# Browser SQL workspace

Open **http://127.0.0.1:8765** while the local server is running. To reopen it later, double-click **Open CyberShield.cmd** in the project folder. That launcher reuses a healthy workspace or starts PostgreSQL and the local server, then opens the page.

To start it manually from the project directory:

```powershell
docker compose up -d --wait
.\.venv\Scripts\python.exe -m cybershield serve
```

Keep that terminal running. Open the page in a browser on this computer.

## Explore

1. Select the Tuesday real dataset or the clearly marked synthetic fixture.
2. Choose an example from the sidebar, or type your own SQL in the editor.
3. Click **Run query**, or press **Ctrl+Enter** (**Cmd+Enter** on macOS).
4. Inspect the returned table and elapsed time. Expand a table in the schema reference to see its columns.
5. Click **Export CSV** to download the displayed results. The selected result limit also applies to exports.

Start with:

```sql
SELECT label, COUNT(*) AS flows
FROM flow_label
GROUP BY label
ORDER BY flows DESC;
```

Use `latest_features`, `latest_window_labels`, `latest_predictions`, and `latest_triage` for the most recent completed experiment. Their joins prevent repeated experiment runs from inflating a simple exploration query. `flow` retains the original source-record grain. The example triage query restricts results to development windows.

## Query behavior

- One `SELECT` or `WITH … SELECT` statement per request, including joins, aggregates, unions, and window expressions.
- Up to 500 returned rows and a five-second database timeout. The interface marks truncated results explicitly.
- Common analytical functions are supported. Unsupported functions, cross-dataset relations, write operations, and locking clauses return a clear message.
- Exact numeric/decimal values are returned as text to preserve their precision. Dates use the stored capture clock, without an invented timezone.
- SQL output is rendered as text. It cannot inject HTML into the table.

The server binds only to loopback. A separate `cybershield_workspace_reader` login has SELECT-only grants on the listed dataset objects, default read-only transactions, and no owner/superuser privileges. User queries never execute as the ingestion owner. A parser validates the query shape, and PostgreSQL privileges independently prevent data modification. Reader credentials are generated into ignored `.env` during startup and never sent to the browser.

The browser uses a per-process page token for query requests, with same-host validation and no external scripts/assets. These are controls for a local development interface; network hosting/authentication is outside this release.

## Dataset interpretation

The interface queries the existing development database. It does not ingest new data, change thresholds, or run a final evaluation. The real dataset's temporal views cover the same restricted morning-clock population as the prototype. Fifteen attack-labeled windows in that population share the recorded source; counts do not represent independent attack episodes. The label-distribution example covers the complete accepted Tuesday file, including rows excluded from temporal scoring.

## Stop or restart

For a manually started server, press **Ctrl+C** in its terminal. For the double-click/background launcher, use the process ID in `.workspace.pid` to stop that workspace process. Stop PostgreSQL with `docker compose stop` when finished; its named volume preserves data.

For a fresh environment, install dependencies from `requirements.lock`. Startup applies migration `002_query_workspace.sql` to existing fixture/Tuesday schemas. If data are not yet loaded, first run the corresponding prototype pipeline.

Implementation references: [Flask](https://flask.palletsprojects.com/en/stable/quickstart/), [PostgreSQL read-only transactions](https://www.postgresql.org/docs/16/sql-set-transaction.html), [server-side cursors](https://www.postgresql.org/docs/16/sql-declare.html), [SQLGlot parser](https://github.com/tobymao/sqlglot).

