"use strict";
const $ = id => document.getElementById(id);
const state = {examples: [], result: null, busy: false, generation: 0, selection: "triage",
  configured: false, drafting: false, editorVersion: 0, chartSpec: null, preferredView: "table"};
const editor = $("sql-editor");
const token = document.querySelector('meta[name="workspace-token"]').content;
const number = value => new Intl.NumberFormat("en-US").format(value);

function updateLines() {
  $("line-numbers").textContent = Array.from({length: editor.value.split("\n").length}, (_, i) => i + 1).join("\n");
}
function chooseExample(example, focus = true) {
  state.editorVersion++; state.chartSpec = null; state.preferredView = "table";
  editor.value = example.sql;
  state.selection = example.id;
  $("query-title").textContent = example.title;
  document.querySelectorAll(".example-button").forEach(button => button.classList.toggle("active", button.dataset.id === example.id));
  updateLines();
  if (focus) editor.focus();
}
function renderSchema(tables) {
  const container = $("schema-list");
  container.replaceChildren();
  const visible = ["latest_triage", "latest_features", "latest_predictions", "latest_window_labels", "flow", "flow_label", "source_file", "ingestion_run"];
  for (const name of visible) {
    const table = tables.find(item => item.name === name);
    if (!table) continue;
    const details = document.createElement("details");
    details.className = "schema-table";
    const summary = document.createElement("summary"); summary.textContent = table.name;
    const description = document.createElement("p"); description.textContent = table.description;
    const columns = document.createElement("div"); columns.className = "column-list";
    for (const column of table.columns) {
      const row = document.createElement("div"); row.className = "column";
      const title = document.createElement("span"); title.textContent = column.name;
      const type = document.createElement("span"); type.textContent = column.type.replace("timestamp without time zone", "timestamp").replace("double precision", "float8");
      row.append(title, type); columns.append(row);
    }
    details.append(summary, description, columns); container.append(details);
  }
}
function message(text, kind = "") {
  const element = $("result-message");
  element.textContent = text; element.className = `result-message ${kind}`; element.hidden = !text;
}
function cellText(value) {
  if (value === null) return "NULL";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "—";
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}
function renderResult(result) {
  const table = $("results-table"); const head = table.tHead; const body = table.tBodies[0];
  head.replaceChildren(); body.replaceChildren();
  const titles = document.createElement("tr");
  for (const name of result.columns) {const th = document.createElement("th"); th.scope = "col"; th.textContent = name; titles.append(th);}
  head.append(titles);
  for (const row of result.rows) {
    const tr = document.createElement("tr");
    for (const value of row) {const td = document.createElement("td"); td.textContent = cellText(value); td.title = cellText(value); if (value === null) td.className = "null-value"; tr.append(td);}
    body.append(tr);
  }
  $("table-scroll").hidden = !result.rows.length;
  $("result-count").textContent = number(result.row_count);
  $("query-timing").textContent = `${number(result.elapsed_ms)} ms`;
  $("result-summary").textContent = result.truncated ? `Showing first ${number(result.row_count)} rows · result limit reached` : `${number(result.row_count)} ${result.row_count === 1 ? "row" : "rows"} returned`;
  $("export-csv").disabled = !result.rows.length;
  message(result.rows.length ? "" : "The query ran successfully and returned no matching rows.");
  configureChart(result);
}
function draftMessage(text, kind = "") {
  $("draft-message").textContent = text; $("draft-message").className = `draft-message ${kind}`;
}
function setView(view) {
  const chart = view === "chart" && !$("view-chart").disabled;
  $("chart-panel").hidden = !chart;
  $("table-scroll").hidden = chart || !state.result?.rows.length;
  $("view-table").setAttribute("aria-pressed", String(!chart));
  $("view-chart").setAttribute("aria-pressed", String(chart));
  if (chart) drawChart();
}
function configureChart(result) {
  const numeric = CyberShieldCharts.numericColumns(result);
  const supported = numeric.length > 0 && result.columns.length > 1 && result.rows.length > 0;
  $("view-chart").disabled = !supported;
  for (const id of ["chart-x", "chart-y"]) $(id).replaceChildren();
  if (!supported) {setView("table"); return;}
  result.columns.forEach((column, i) => {
    const x = document.createElement("option"); x.value = i; x.textContent = column; $("chart-x").append(x);
    if (numeric.includes(i)) {const y = x.cloneNode(true); $("chart-y").append(y);}
  });
  const preferred = result.chartSpec;
  let x = preferred ? result.columns.indexOf(preferred.x) : -1;
  if (x < 0) x = result.columns.findIndex((_, i) => !numeric.includes(i));
  if (x < 0) x = 0;
  let y = preferred ? result.columns.indexOf(preferred.y) : -1;
  if (!numeric.includes(y) || y === x) y = numeric.find(i => i !== x);
  if (y === undefined) {$("view-chart").disabled = true; setView("table"); return;}
  $("chart-x").value = String(x); $("chart-y").value = String(y);
  $("chart-type").value = preferred?.type === "line" ? "line" : "bar";
  $("chart-title").textContent = result.title;
  setView(result.preferredView);
}
function drawChart() {
  if (!state.result) return;
  const x = Number($("chart-x").value), y = Number($("chart-y").value);
  const data = CyberShieldCharts.render($("query-chart"), state.result,
    {x, y, type: $("chart-type").value, title: $("chart-title").textContent});
  if (data.empty) {
    const empty = document.createElement("p"); empty.className = "chart-empty";
    empty.textContent = "No finite numeric values are available for these axes. Choose another value column or use the table.";
    $("query-chart").append(empty);
  }
  const notes = [`${data.points.length} of ${data.total} returned rows plotted in query order.`,
    "Display values are approximate; use the table or CSV for exact values."];
  if (data.omitted) notes.push(`${data.omitted} ${data.omitted === 1 ? "row" : "rows"} omitted: missing, nonnumeric or outside safe numeric range.`);
  if ($("chart-type").value === "line") notes.push("Line spacing follows query order; missing values leave gaps.");
  if (data.hidden) notes.push(`${data.hidden} additional ${data.hidden === 1 ? "row is" : "rows are"} available in the table.`);
  if (state.result.truncated) notes.push("The query result limit was reached; this is a partial result.");
  if (x === y) notes.push("The same column is selected for labels and values.");
  $("chart-note").textContent = notes.join(" ");
}
async function assistantStatus() {
  try {
    const response = await fetch("/api/sql-assistant/status"); const data = await response.json();
    if (!response.ok) throw new Error(data.error);
    state.configured = data.configured;
    $("assistant-status").textContent = data.configured ? "AI drafting available" : "Examples available · AI key not configured";
    $("draft-sql").disabled = !data.configured || state.drafting;
  } catch (_) {$("assistant-status").textContent = "AI drafting unavailable · try an example";}
}
async function draftSQL() {
  if (state.drafting || !state.configured) return;
  const question = $("data-question").value.trim();
  if (question.length < 5) {draftMessage("Ask a question about the selected dataset.", "error"); $("data-question").focus(); return;}
  const generation = state.generation, version = state.editorVersion;
  const dataset = $("dataset").value;
  state.drafting = true; $("draft-sql").disabled = true; $("draft-label").textContent = "Drafting…";
  draftMessage("Drafting from your question and the selected schema. No SQL is being executed.");
  try {
    const response = await fetch("/api/sql-assistant/draft", {method: "POST", headers: {"Content-Type": "application/json", "X-Workspace-Token": token}, body: JSON.stringify({question, dataset})});
    const data = await response.json();
    if (generation !== state.generation) return;
    if (!response.ok) throw new Error(data.error || "SQL drafting was unavailable.");
    if (version !== state.editorVersion) {draftMessage("Your editor changed during drafting. Submit again to replace it."); return;}
    editor.value = data.sql; state.editorVersion++; state.selection = null;
    state.chartSpec = data.chart; state.preferredView = data.chart.type === "table" ? "table" : "chart";
    $("query-title").textContent = data.title;
    document.querySelectorAll("#examples .example-button").forEach(b => b.classList.remove("active"));
    updateLines(); draftMessage(`${data.explanation} Review the SQL below, then select Run query.`, "ready");
    $("editor-heading").scrollIntoView({behavior: "smooth", block: "nearest"});
  } catch (error) {if (generation === state.generation) draftMessage(error.message || "Could not reach the local server.", "error");}
  finally {state.drafting = false; $("draft-sql").disabled = !state.configured; $("draft-label").textContent = "Draft SQL";}
}
async function runQuery() {
  if (state.busy) return;
  if (!editor.value.trim()) {message("Write a SELECT query, or choose an example to start.", "error"); editor.focus(); return;}
  const generation = state.generation;
  const dataset = $("dataset").value;
  const sql = editor.value, title = $("query-title").textContent;
  const chartSpec = state.chartSpec, preferredView = state.preferredView;
  state.busy = true; $("run-query").disabled = true;
  $("run-label").textContent = "Running…"; $("run-icon").textContent = "◌"; $("run-icon").className = "loading-spinner";
  $("export-csv").disabled = true;
  $("table-scroll").hidden = true; message("Running your query against PostgreSQL…", "loading");
  $("chart-panel").hidden = true; $("view-chart").disabled = true;
  try {
    const response = await fetch("/api/query", {method: "POST", headers: {"Content-Type": "application/json", "X-Workspace-Token": token}, body: JSON.stringify({sql, dataset, limit: Number($("row-limit").value)})});
    const result = await response.json();
    if (generation !== state.generation) return;
    if (!response.ok) throw new Error(result.error || "The query could not be completed.");
    state.result = {...result, title, chartSpec, preferredView}; renderResult(state.result);
  } catch (error) {
    if (generation !== state.generation) return;
    state.result = null; $("result-count").textContent = "0"; $("query-timing").textContent = "";
    $("result-summary").textContent = "Adjust the query and try again.";
    message(error.message || "Unable to reach the local server.", "error");
  } finally {
    state.busy = false; $("run-query").disabled = false;
    $("run-label").textContent = "Run query"; $("run-icon").textContent = "▶"; $("run-icon").className = "";
  }
}
async function bootstrap(autoRun = false) {
  const generation = ++state.generation;
  state.result = null; $("export-csv").disabled = true;
  state.editorVersion++; state.chartSpec = null; $("chart-panel").hidden = true; $("view-chart").disabled = true;
  draftMessage("AI drafting sends your question and schema to OpenAI. Result rows stay local. Review the SQL, then run it.");
  $("connection-text").textContent = "Connecting to database…";
  $("connection-dot").className = "connection-dot";
  $("table-scroll").hidden = true; $("result-count").textContent = "0"; $("query-timing").textContent = "";
  try {
    const response = await fetch(`/api/bootstrap?dataset=${encodeURIComponent($("dataset").value)}`);
    const data = await response.json();
    if (generation !== state.generation) return;
    if (!response.ok) throw new Error(data.error || "Could not connect to the dataset.");
    $("stat-flows").textContent = number(data.flows); $("stat-windows").textContent = number(data.windows);
    $("stat-positive").textContent = number(data.positive_windows); $("stat-categories").textContent = number(data.categories);
    $("schema-name").textContent = data.schema; $("connection-dot").className = "connection-dot online";
    $("connection-text").textContent = "PostgreSQL · Connected";
    $("source-description").textContent = data.dataset === "real" ? "Original labeled flows · Tuesday\nLocal PostgreSQL database" : "Deterministic synthetic data\nFunctional verification only";
    $("data-note").textContent = data.dataset === "real" ? "Development dataset · Morning-clock scoring only. Adjacent windows can share an attack episode." : "Synthetic fixture · Generated test data. These results are not real security observations.";
    state.examples = data.examples;
    const examples = $("examples"); examples.replaceChildren();
    for (const example of data.examples) {
      const button = document.createElement("button"); button.type = "button"; button.className = "example-button";
      button.dataset.id = example.id; button.textContent = example.title; button.title = example.description;
      button.addEventListener("click", () => chooseExample(example)); examples.append(button);
    }
    const chosen = data.examples.find(example => example.id === state.selection) || data.examples[0];
    chooseExample(chosen, false); renderSchema(data.tables);
    message("Your data is ready. Run the query to see its results.");
    $("result-summary").textContent = "Ready when you are.";
    if (autoRun && !state.busy) await runQuery();
  } catch (error) {
    if (generation !== state.generation) return;
    for (const id of ["stat-flows", "stat-windows", "stat-positive", "stat-categories"]) $(id).textContent = "—";
    $("connection-dot").className = "connection-dot offline"; $("connection-text").textContent = "Database unavailable";
    message(error.message, "error");
  }
}
$("run-query").addEventListener("click", runQuery);
$("draft-sql").addEventListener("click", draftSQL);
$("view-table").addEventListener("click", () => setView("table"));
$("view-chart").addEventListener("click", () => setView("chart"));
for (const id of ["chart-type", "chart-x", "chart-y"]) $(id).addEventListener("change", drawChart);
document.querySelectorAll("[data-question-example]").forEach(button => button.addEventListener("click", () => {
  const example = state.examples.find(item => item.id === button.dataset.questionExample);
  if (!example) {draftMessage("Connect to a dataset to load an example question.", "error"); return;}
  chooseExample(example, false);
  $("data-question").value = {traffic: "How does traffic change over time?", services: "Which sources generated the most FTP or SSH traffic?", labels: "How many flows belong to each category?"}[example.id];
  state.chartSpec = {type: example.id === "traffic" ? "line" : "bar", x: example.id === "traffic" ? "hour" : example.id === "services" ? "source" : "label", y: example.id === "services" ? "service_flows" : "flows"};
  state.preferredView = "chart"; draftMessage("Saved example loaded without an API call. Review the SQL, then select Run query.", "ready");
}));
$("dataset").addEventListener("change", () => bootstrap(false));
$("clear-query").addEventListener("click", () => {editor.value = ""; state.editorVersion++; state.chartSpec = null; state.preferredView = "table"; updateLines(); $("query-title").textContent = "Untitled query"; editor.focus();});
editor.addEventListener("input", () => {
  state.editorVersion++; state.chartSpec = null; state.preferredView = "table";
  updateLines();
  state.selection = null; $("query-title").textContent = "Custom query";
  document.querySelectorAll("#examples .example-button").forEach(button => button.classList.remove("active"));
});
editor.addEventListener("scroll", () => {$("line-numbers").scrollTop = editor.scrollTop;});
editor.addEventListener("keydown", event => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {event.preventDefault(); runQuery();}
  if (event.key === "Tab") {event.preventDefault(); const start = editor.selectionStart; const end = editor.selectionEnd; editor.setRangeText("  ", start, end, "end"); editor.dispatchEvent(new Event("input"));}
});
$("export-csv").addEventListener("click", () => {
  if (!state.result) return;
  const quote = value => {let text = value === null ? "" : cellText(value); if (typeof value === "string" && /^[=+@-]/.test(text)) text = "'" + text; return `"${text.replaceAll('"', '""')}"`;};
  const rows = [state.result.columns, ...state.result.rows];
  const blob = new Blob(["\uFEFF" + rows.map(row => row.map(quote).join(",")).join("\r\n")], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = `cybershield-${state.result.dataset}-query.csv`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
assistantStatus();
bootstrap(true);

