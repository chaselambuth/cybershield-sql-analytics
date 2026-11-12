"use strict";
const $ = id => document.getElementById(id);
const state = {examples: [], result: null, busy: false, generation: 0, selection: "triage"};
const editor = $("sql-editor");
const token = document.querySelector('meta[name="workspace-token"]').content;
const number = value => new Intl.NumberFormat("en-US").format(value);

function updateLines() {
  $("line-numbers").textContent = Array.from({length: editor.value.split("\n").length}, (_, i) => i + 1).join("\n");
}
function chooseExample(example, focus = true) {
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
}
async function runQuery() {
  if (state.busy) return;
  if (!editor.value.trim()) {message("Write a SELECT query, or choose an example to start.", "error"); editor.focus(); return;}
  const generation = state.generation;
  const dataset = $("dataset").value;
  state.busy = true; $("run-query").disabled = true;
  $("run-label").textContent = "Running…"; $("run-icon").textContent = "◌"; $("run-icon").className = "loading-spinner";
  $("export-csv").disabled = true;
  $("table-scroll").hidden = true; message("Running your query against PostgreSQL…", "loading");
  try {
    const response = await fetch("/api/query", {method: "POST", headers: {"Content-Type": "application/json", "X-Workspace-Token": token}, body: JSON.stringify({sql: editor.value, dataset, limit: Number($("row-limit").value)})});
    const result = await response.json();
    if (generation !== state.generation) return;
    if (!response.ok) throw new Error(result.error || "The query could not be completed.");
    state.result = result; renderResult(result);
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
$("dataset").addEventListener("change", () => bootstrap(false));
$("clear-query").addEventListener("click", () => {editor.value = ""; updateLines(); $("query-title").textContent = "Untitled query"; editor.focus();});
editor.addEventListener("input", () => {
  updateLines();
  const example = state.examples.find(item => item.id === state.selection);
  if (example && editor.value !== example.sql) {
    state.selection = null; $("query-title").textContent = "Custom query";
    document.querySelectorAll(".example-button").forEach(button => button.classList.remove("active"));
  }
});
editor.addEventListener("scroll", () => {$("line-numbers").scrollTop = editor.scrollTop;});
editor.addEventListener("keydown", event => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {event.preventDefault(); runQuery();}
  if (event.key === "Tab") {event.preventDefault(); const start = editor.selectionStart; const end = editor.selectionEnd; editor.setRangeText("  ", start, end, "end"); updateLines();}
});
$("export-csv").addEventListener("click", () => {
  if (!state.result) return;
  const quote = value => {let text = value === null ? "" : cellText(value); if (typeof value === "string" && /^[=+@-]/.test(text)) text = "'" + text; return `"${text.replaceAll('"', '""')}"`;};
  const rows = [state.result.columns, ...state.result.rows];
  const blob = new Blob(["\uFEFF" + rows.map(row => row.map(quote).join(",")).join("\r\n")], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = `cybershield-${state.result.dataset}-query.csv`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
bootstrap(true);

