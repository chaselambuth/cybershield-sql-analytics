"use strict";
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="workspace-token"]').content;
let current = null, timer = null, started = 0;
const examples = [
  ["Investigate a top alert", "Follow a window to its original flows", "Investigate the highest-priority SQL alert. Inspect its supporting flows and explain what remains uncertain."],
  ["Compare quality and latency", "Find feasible model tradeoffs", "Compare models with at most 40 false positives and pipeline P95 under 2 ms. Explain tradeoffs and score-tie limitations."],
  ["Trace a specific source", "Scope evidence to one address", "Investigate source 172.16.0.1 using combined SQL alerts and supporting flows. Separate observations from retrospective labels."],
  ["Challenge the conclusion", "Check what the benchmark can support", "Does the XGBoost result prove it is the best production detector? Check its latency, ties, and evaluation scope."]
];
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
for (const [title, subtitle, question] of examples) {
  const button = el("button", title, "example"); button.append(el("span", subtitle));
  button.addEventListener("click", () => { $("question").value = question; $("question").focus(); });
  $("examples").append(button);
}
function modeNote() {
  $("mode-note").textContent = $("mode").value === "live"
    ? "Live mode sends your question and retrieved public benchmark evidence to OpenAI. Credentials stay on this server."
    : "Reference mode runs a deterministic tool workflow. No LLM, API calls, or API cost; it does not evaluate model intelligence.";
}
$("mode").addEventListener("change", modeNote);
async function api(url, options = {}) {
  const response = await fetch(url, options); const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed."); return body;
}
function setBusy(busy) { $("investigate").disabled = busy; $("mode").disabled = busy; $("question").disabled = busy; document.querySelectorAll('.example').forEach(button => {button.disabled = busy;}); }
function linkedText(parent, text) {
  const pattern = /\[(E\d+)\]/g; let last = 0;
  for (const match of text.matchAll(pattern)) {
    parent.append(document.createTextNode(text.slice(last, match.index)));
    const a = el("a", match[1], "cite"); a.href = "#evidence-" + match[1];
    a.addEventListener("click", () => { const card = $("evidence-" + match[1]); if (card) card.open = true; });
    parent.append(a); last = match.index + match[0].length;
  }
  parent.append(document.createTextNode(text.slice(last)));
}
const names = {get_context:"Establish cohort & provenance",search_windows:"Retrieve ranked alert windows",inspect_window:"Inspect supporting flow records",compare_models:"Compare quality & inference cost",search_knowledge:"Retrieve methodology",finish:"Validate investigation brief"};
function dataTable(rows, columns) {
  const scroll = el("div",undefined,"evidence-table");
  if (!rows.length) { scroll.append(el("p","No matching records.","evidence-note")); return scroll; }
  const table = el("table"), head = el("thead"), header = el("tr"), body = el("tbody");
  for (const [,label] of columns) header.append(el("th",label)); head.append(header);
  for (const row of rows) { const tr = el("tr"); for (const [key,,format] of columns) {
    const v = row[key]; tr.append(el("td",v == null ? "—" : format ? format(v) : String(v)));
  } body.append(tr); }
  table.append(head,body); scroll.append(table); return scroll;
}
function facts(pairs) {
  const dl = el("dl",undefined,"evidence-facts");
  for (const [key,value] of pairs) {const pair=el("div");pair.append(el("dt",key),el("dd",value == null ? "Unknown" : String(value)));dl.append(pair);} return dl;
}
function evidenceData(record, body) {
  const d=record.data, percent=v=>(v*100).toFixed(1)+"%", ms=v=>Number(v).toFixed(3);
  if (record.tool === "inspect_window") {
    if (!d.window) {body.append(el("p","No window matches this evidence key.","evidence-note"));return;}
    const w=d.window;
    body.append(facts([["Source",w.src_ip],["Window start",w.window_start],["Observed flows",w.flow_count],["Service flows",w.service_flows],["Destinations",w.unique_destinations],["Role",w.split]]));
    body.append(el("p",d.label_warning,"evidence-warning"),facts([["Attack-labeled flows",w.attack_flows],["Unknown labels",w.unknown_flows],["Recorded category",w.categories]]));
    body.append(el("h4",`Supporting flows · showing ${d.supporting_flows.length} of ${d.supporting_flow_count}`));
    body.append(dataTable(d.supporting_flows,[["flow_id","Record"],["dst_ip","Destination"],["dst_port","Port"],["reported_end","Reported end"],["packets","Packets"],["bytes","Bytes"],["retrospective_label","Retrospective label"]]));
    const decisions=el("details",undefined,"secondary-detail");decisions.append(el("summary","Decisions by detector"),dataTable(d.decisions,[["detector_id","Detector"],["predicted_attack","Alert",v=>v?"Yes":"No"],["within_detector_rank","Within-detector rank"]]));body.append(decisions);
  } else if (record.tool === "search_windows") {
    body.append(el("p",d.selection,"evidence-note"),dataTable(d.windows,[["src_ip","Source"],["window_start","Window start"],["detector_id","Detector"],["within_detector_rank","Rank"],["flow_count","Flows"],["service_flows","Service flows"]]));
  } else if (record.tool === "compare_models") {
    body.append(el("p",d.timing,"evidence-note"),facts([["False-positive cap",d.constraints.max_false_positives ?? "Unconstrained"],["Pipeline P95 cap",d.constraints.max_p95_ms == null ? "Unconstrained" : d.constraints.max_p95_ms+" ms"]]));
    body.append(dataTable(d.models,[["display_name","Model"],["tp","TP"],["fp","FP"],["fn","Missed"],["recall","Recall",percent],["precision","Precision",percent],["single_pipeline_p95_ms","P95 · ms",ms],["largest_tie_share","Largest tie",percent]]));
    for (const model of d.models) if (model.caveat) body.append(el("p",model.display_name+": "+model.caveat,"evidence-warning"));
    body.append(el("p",d.sql_note,"evidence-note"));
  } else if (record.tool === "get_context") {
    const c=d.context;body.append(facts([["Dataset",c.dataset],["Cohort",c.cohort],["Clock policy",c.clock_policy],["Benchmark",c.benchmark_id]]),el("p",d.limitation,"evidence-warning"));
  } else if (record.tool === "search_knowledge") {
    if (!d.passages.length) body.append(el("p","No methodology passage matched this query.","evidence-note"));
    for (const passage of d.passages) {const section=el("section",undefined,"passage");section.append(el("h4",passage.title),el("p",passage.text),el("small",passage.source));body.append(section);}
  }
  const raw=el("details",undefined,"secondary-detail");raw.append(el("summary","Raw evidence · full precision"),el("pre",JSON.stringify(d,null,2)));body.append(raw);
}
function render(run) {
  current = run; $("run-status").textContent = run.status[0].toUpperCase()+run.status.slice(1);
  $("latency").textContent = ((run.latency_ms ?? performance.now()-started)/1000).toFixed(2)+" s";
  $("tool-count").textContent = String(run.tool_calls ?? run.events.filter(x => x.kind === "tool_started").length);
  $("tokens").textContent = run.usage ? run.usage.input_tokens.toLocaleString()+" / "+run.usage.output_tokens.toLocaleString() : "—";
  $("cost").textContent = run.estimated_cost_usd == null ? "—" : "$"+run.estimated_cost_usd.toFixed(4);
  $("run-message").className = run.status === "failed" ? "error" : "";
  $("run-message").textContent = run.error || (run.mode === "reference" ? "Reference workflow · deterministic demo, no LLM used" : run.status === "completed" ? "Completed · citation references checked · synthesis requires analyst review" : "Investigation running · retrieving bounded evidence");
  const trace = $("trace"); trace.replaceChildren();
  for (const event of run.events) {
    if (event.kind === "tool_started" || event.kind === "model_started") continue;
    const item = el("li", names[event.tool] || event.detail || (event.kind === "model_completed" ? "Model selected its next action" : event.kind));
    item.append(el("small", (event.elapsed_ms/1000).toFixed(2)+"s"+(event.duration_ms != null ? " · "+event.duration_ms.toFixed(1)+" ms" : "")+(event.evidence_id ? " · "+event.evidence_id : "")));
    trace.append(item);
  }
  const evidence = $("evidence");
  for (const record of run.evidence) {
    if ($("evidence-"+record.evidence_id)) continue;
    const card = el("details", undefined, "evidence-card"); card.id = "evidence-"+record.evidence_id;
    const summary = el("summary"); summary.append(el("span", record.evidence_id, "cite"), document.createTextNode(names[record.tool] || record.tool)); card.append(summary);
    const body = el("div", undefined, "evidence-body"); evidenceData(record,body);
    const provenance = el("div", undefined, "provenance"); provenance.append(el("div", "SOURCE HASHES · SHA-256"));
    for (const [source, hash] of Object.entries(record.sources)) provenance.append(el("div", source+" · "+hash));
    if (record.sql) { provenance.append(el("div", "PRIMARY READ-ONLY QUERY"),el("pre",record.sql),el("div","Parameters: "+JSON.stringify(record.parameters))); }
    const sourceDetail=el("details",undefined,"secondary-detail");sourceDetail.append(el("summary","Query & source provenance"),provenance);
    body.append(sourceDetail); card.append(body); evidence.append(card);
  }
  if (run.report) {
    const brief = el("div", undefined, "brief"); brief.append(el("span", run.report.verdict.replaceAll("_"," "),"verdict"),el("h3",run.report.title));
    const p = el("p"); linkedText(p,run.report.synthesis); brief.append(p);
    if (run.report.next_steps.length) { brief.append(el("h4","Suggested analyst next steps")); const list = el("ul"); for (const step of run.report.next_steps) { const item = el("li"); linkedText(item,step); list.append(item); } brief.append(list); }
    $("brief").replaceChildren(brief);
  }
  $("download").disabled = run.status === "running";
}
async function poll(runId) {
  try {
    const run = await api("/api/agent/runs/"+runId); render(run);
    if (run.status === "running") timer = setTimeout(() => poll(runId), 750); else setBusy(false);
  } catch (error) {
    $("run-message").textContent = error.message+" Refresh to reconnect; the server run may still finish.";
    $("run-message").className = "error"; setBusy(false);
  }
}
$("investigate").addEventListener("click", async () => {
  if ($("question").value.trim().length < 5) { $("question").focus(); return; }
  clearTimeout(timer); current = null; started = performance.now(); setBusy(true);
  $("evidence").replaceChildren(); $("brief").replaceChildren(el("div","Building your investigation brief…","empty")); $("trace").replaceChildren();
  $("download").disabled = true; $("run-message").className = ""; $("run-message").textContent = "Starting investigation…";
  try {
    const body = await api("/api/agent/runs", {method:"POST",headers:{"Content-Type":"application/json","X-Workspace-Token":token},body:JSON.stringify({question:$("question").value,mode:$("mode").value})});
    await poll(body.run_id);
  } catch (error) { $("run-message").textContent = error.message; $("run-message").className = "error"; setBusy(false); }
});
$("download").addEventListener("click", () => {
  if (!current) return; const url = URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:"application/json"}));
  const a = el("a"); a.href = url; a.download = "cybershield-investigation-"+current.run_id+".json"; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
});
api("/api/agent/status").then(status => {
  $("provider").textContent = status.configured ? "Model · "+status.model : "Reference demo available";
  if (!status.configured) { $("mode").value = "reference"; $("mode").options[0].disabled = true; } modeNote();
}).catch(() => { $("provider").textContent = "Check local configuration"; });
