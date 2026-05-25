package web

const reconscopeIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Logy</title>
<style>
:root {
  --bg: #080D14;
  --s1: #0E1620;
  --s2: #152030;
  --s3: #1C2B3F;
  --s4: #22344a;
  --b1: rgba(255,255,255,0.07);
  --b2: rgba(255,255,255,0.13);
  --accent: #00C896;
  --accent-bg: rgba(0,200,150,0.1);
  --accent-bd: rgba(0,200,150,0.28);
  --t1: #CBD5E1;
  --t2: #8B9AAF;
  --t3: #52657A;
  --cr: #F04438; --cr-bg: rgba(240,68,56,0.13);
  --co: #F97316; --co-bg: rgba(249,115,22,0.13);
  --cm: #F59E0B; --cm-bg: rgba(245,158,11,0.13);
  --cl: #3B82F6; --cl-bg: rgba(59,130,246,0.13);
  --ci: #5A6A7D; --ci-bg: rgba(90,106,125,0.13);
  --mono: "SF Mono","SFMono-Regular",Menlo,Monaco,Consolas,"Courier New",monospace;
  --sans: -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  --r: 6px; --rl: 10px;
  --sw: 236px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--t1);font-family:var(--sans);font-size:13px;line-height:1.5}
#app{display:flex;height:100vh;overflow:hidden}
aside{width:var(--sw);min-width:var(--sw);background:var(--s1);border-right:1px solid var(--b1);display:flex;flex-direction:column;overflow-y:auto}
main{flex:1;overflow:hidden;display:flex;flex-direction:column;background:var(--bg)}
.s-logo{padding:18px 16px 14px;border-bottom:1px solid var(--b1)}
.s-logo-name{font-size:14px;font-weight:700;letter-spacing:.12em;color:#E2E8F0}
.s-logo-name span{color:var(--accent)}
.s-logo-sub{font-size:9px;color:var(--t3);font-family:var(--mono);margin-top:3px;letter-spacing:.05em}
.s-eng{margin:12px 10px 0;background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:9px 11px}
.s-eng-l{font-size:9px;text-transform:uppercase;letter-spacing:.09em;color:var(--t3);margin-bottom:3px}
.s-eng-n{font-size:12px;font-weight:500;color:var(--t1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.s-eng-s{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--accent);margin-top:5px}
.pulse{width:5px;height:5px;border-radius:50%;background:var(--accent);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 var(--accent-bg)}50%{opacity:.4;box-shadow:0 0 0 4px transparent}}
.s-sec{padding:14px 8px 2px}
.s-sec-l{font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);padding:0 8px;margin-bottom:4px}
.nav-item{display:flex;align-items:center;gap:8px;padding:7px 9px;border-radius:var(--r);cursor:pointer;color:var(--t2);font-size:12.5px;transition:all .12s;user-select:none}
.nav-item:hover{background:var(--s2);color:var(--t1)}
.nav-item.active{background:var(--accent-bg);color:var(--accent)}
.nb{margin-left:auto;font-size:10px;background:var(--s3);padding:1px 6px;border-radius:9px;color:var(--t2);font-family:var(--mono)}
.nav-item.active .nb{background:rgba(0,200,150,0.18);color:var(--accent)}
.s-foot{margin-top:auto;padding:12px;border-top:1px solid var(--b1)}
.s-foot p{font-size:10px;color:var(--t3);font-family:var(--mono);line-height:1.7}
.ph{padding:16px 24px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;gap:12px}
.ph-l .pt{font-size:15px;font-weight:600;color:#E2E8F0}
.ph-l .ps{font-size:10px;color:var(--t3);font-family:var(--mono);margin-top:2px}
.ph-r{display:flex;align-items:center;gap:8px}
.fsel,.field-select,.field-input{background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:8px 10px;color:var(--t1);font-size:11px;font-family:var(--sans);outline:none}
.fsel{cursor:pointer;min-width:220px}
.vbody{flex:1;overflow-y:auto;padding:20px 24px}
.mg{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}
.mc{background:var(--s1);border:1px solid var(--b1);border-radius:var(--rl);padding:16px 18px}
.mc-l{font-size:9px;text-transform:uppercase;letter-spacing:.09em;color:var(--t3);margin-bottom:7px}
.mc-v{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1;color:#E2E8F0}
.mc-s{font-size:11px;color:var(--t2);margin-top:5px}
.mc.a{border-color:var(--accent-bd)}
.mc.a .mc-v{color:var(--accent)}
.g2{display:grid;grid-template-columns:1.3fr .7fr;gap:12px;margin-bottom:12px}
.panel{background:var(--s1);border:1px solid var(--b1);border-radius:var(--rl);overflow:hidden}
.ph2{padding:12px 16px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between}
.ph2 .pt2{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--t2)}
.pb{padding:16px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--t3);padding:8px 12px;border-bottom:1px solid var(--b1);text-align:left;font-weight:500;white-space:nowrap}
.tbl td{padding:9px 12px;border-bottom:1px solid var(--b1);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr:hover td{background:var(--s2);cursor:pointer}
.tbl tbody tr.sel td{background:var(--accent-bg)!important}
.mono{font-family:var(--mono);font-size:11.5px}
.dim{color:var(--t2)}
.tb{display:flex;align-items:center;gap:8px;padding:12px 24px;border-bottom:1px solid var(--b1);flex-shrink:0;background:var(--bg);flex-wrap:wrap}
.sr{display:flex;align-items:center;gap:6px;background:var(--s2);border:1px solid var(--b1);border-radius:var(--r);padding:6px 10px;min-width:220px}
.sr input{background:none;border:none;outline:none;color:var(--t1);font-size:12px;font-family:var(--sans);width:100%}
.sr input::placeholder{color:var(--t3)}
.rc{font-size:11px;color:var(--t3);white-space:nowrap}
.sp{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;border-radius:var(--r);border:1px solid var(--b1);background:var(--s2);color:var(--t1);cursor:pointer;font-size:11px}
.btn:hover{background:var(--s3)}
.btn-a{background:var(--accent-bg);border-color:var(--accent-bd);color:var(--accent)}
.btn-d{background:var(--cr-bg);border-color:rgba(240,68,56,0.28);color:var(--cr)}
.hl{display:grid;grid-template-columns:320px 1fr;flex:1;overflow:hidden;border:1px solid var(--b1);border-radius:var(--rl);background:var(--s1)}
.ht{overflow-y:auto;border-right:1px solid var(--b1);background:var(--s1)}
.hd{overflow-y:auto;padding:20px 24px;background:var(--bg)}
.tree-header{padding:10px 16px 6px;font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);border-bottom:1px solid var(--b1);margin-bottom:4px}
.tree-item{display:flex;align-items:center;gap:8px;padding:8px 16px;cursor:pointer;transition:background .08s}
.tree-item:hover{background:var(--s2)}
.tree-item.sel{background:var(--accent-bg)!important;border-right:2px solid var(--accent)}
.ti-label{font-size:12.5px;color:var(--t1);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ti-meta{font-size:10px;color:var(--t3);flex-shrink:0;font-family:var(--mono)}
.dp-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--t3);text-align:center}
.dp-section{margin-bottom:18px}
.dp-label{font-size:9px;text-transform:uppercase;letter-spacing:.09em;color:var(--t3);margin-bottom:5px}
.dp-value{font-size:13px;color:var(--t1);font-family:var(--mono)}
.dp-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.port-chip,.host-badge,.tag-chip{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;background:var(--s2);border:1px solid var(--b1);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--t2);margin:2px}
.port-num{color:var(--accent);font-weight:600}
.port-chip.open{border-color:var(--accent-bd)}
.scan-item{display:flex;align-items:flex-start;gap:12px;padding:14px 0;border-bottom:1px solid var(--b1)}
.scan-item:last-child{border-bottom:none}
.scan-icon{width:34px;height:34px;border-radius:var(--r);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:9px;font-weight:800;font-family:var(--mono);letter-spacing:-.5px;background:rgba(0,200,150,0.12);color:var(--accent);border:1px solid var(--accent-bd)}
.scan-body{flex:1;min-width:0}
.scan-title{font-size:13px;font-weight:500;color:var(--t1)}
.scan-cmd{font-family:var(--mono);font-size:10.5px;color:var(--t2);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scan-meta{font-size:10px;color:var(--t3);margin-top:4px;display:flex;gap:10px;flex-wrap:wrap}
.scan-r{text-align:right;flex-shrink:0}
.stag,.sev{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
.sev::before{content:"";width:5px;height:5px;border-radius:50%;flex-shrink:0;display:inline-block;background:currentColor}
.severity-critical,.severity-high{background:var(--cr-bg);color:var(--cr)}
.severity-medium{background:var(--cm-bg);color:var(--cm)}
.severity-low{background:var(--cl-bg);color:var(--cl)}
.severity-info{background:var(--ci-bg);color:var(--ci)}
.status-open{background:var(--cl-bg);color:var(--cl)}
.status-verified{background:var(--cm-bg);color:var(--cm)}
.status-fixed{background:var(--accent-bg);color:var(--accent)}
.status-false_positive{background:var(--ci-bg);color:var(--ci)}
.status-running{background:var(--cm-bg);color:var(--cm)}
.status-completed{background:var(--accent-bg);color:var(--accent)}
.status-failed{background:var(--cr-bg);color:var(--cr)}
.empty{display:flex;flex-direction:column;align-items:center;padding:40px;color:var(--t3);gap:6px}
.find-wrap{display:grid;grid-template-columns:1.1fr .9fr;gap:12px}
.find-table{border:1px solid var(--b1);border-radius:var(--rl);overflow:hidden;background:var(--s1)}
.find-editor{border:1px solid var(--b1);border-radius:var(--rl);background:var(--s1);overflow:hidden}
.find-editor-body{padding:16px;display:flex;flex-direction:column;gap:14px}
.field-group{display:flex;flex-direction:column;gap:6px}
.field-label{font-size:9px;text-transform:uppercase;letter-spacing:.09em;color:var(--t3)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.service-combo{border:1px solid var(--b1);border-radius:var(--r);background:var(--s2);overflow:hidden}
.service-combo input{width:100%;border:0;border-bottom:1px solid var(--b1);border-radius:0;background:transparent}
.service-results{max-height:220px;overflow:auto}
.service-option{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;width:100%;border:0;border-bottom:1px solid var(--b1);background:transparent;color:var(--t1);padding:8px 10px;text-align:left;cursor:pointer;font-family:var(--sans);font-size:12px}
.service-option:last-child{border-bottom:0}
.service-option:hover,.service-option.sel{background:var(--accent-bg)}
.service-main{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.service-meta{color:var(--t3);font-family:var(--mono);font-size:10.5px;white-space:nowrap}
.editor-toolbar{display:flex;align-items:center;gap:6px;padding:8px;border:1px solid var(--b1);border-bottom:none;border-radius:var(--r) var(--r) 0 0;background:var(--s2);flex-wrap:wrap}
.editor-btn{padding:4px 8px;border:1px solid var(--b1);border-radius:4px;background:var(--s3);color:var(--t1);cursor:pointer;font-size:11px}
.editor-surface{min-height:220px;border:1px solid var(--b1);border-radius:0 0 var(--r) var(--r);background:var(--s2);padding:12px;color:var(--t1);outline:none;overflow:auto}
.editor-surface:empty:before{content:attr(data-placeholder);color:var(--t3)}
.find-actions{display:flex;align-items:center;gap:8px;justify-content:space-between}
.find-preview{border:1px solid var(--b1);border-radius:var(--r);background:var(--s2);padding:12px;min-height:110px}
.find-preview h1,.find-preview h2,.find-preview h3{margin:8px 0;color:#E2E8F0}
.find-preview p,.find-preview ul,.find-preview ol{margin:8px 0}
.find-preview code,.find-preview pre{font-family:var(--mono)}
.find-preview pre{white-space:pre-wrap;background:var(--s3);padding:8px;border-radius:4px}
.find-note{font-size:11px;color:var(--t2)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--s3);border-radius:3px}
@media (max-width: 1180px){
  aside{display:none}
  .mg,.g2,.find-wrap{grid-template-columns:1fr 1fr}
  .hl{grid-template-columns:1fr}
  .ht{border-right:none;border-bottom:1px solid var(--b1);max-height:260px}
}
@media (max-width: 860px){
  .mg,.g2,.find-wrap,.field-row{grid-template-columns:1fr}
  .ph{padding:14px 16px}
  .tb,.vbody{padding-left:16px;padding-right:16px}
}
</style>
</head>
<body>
<div id="app">
  <aside>
    <div class="s-logo">
      <div class="s-logo-name">LOG<span>Y</span></div>
      <div class="s-logo-sub">RECON CONSOLE / READ WRITE FINDINGS</div>
    </div>
    <div class="s-eng">
      <div class="s-eng-l">Selected Domain</div>
      <div class="s-eng-n" id="sidebarDomain">No domains loaded</div>
      <div class="s-eng-s"><span class="pulse"></span><span id="sidebarStatus">Awaiting database selection</span></div>
    </div>
    <div class="s-sec">
      <div class="s-sec-l">Workspace</div>
      <div class="nav-item active" data-view="overview"><span>Overview</span><span class="nb" id="nav-overview">0</span></div>
      <div class="nav-item" data-view="hosts"><span>Hosts &amp; Services</span><span class="nb" id="nav-hosts">0</span></div>
      <div class="nav-item" data-view="candidates"><span>Candidates</span><span class="nb" id="nav-candidates">0</span></div>
      <div class="nav-item" data-view="findings"><span>Findings</span><span class="nb" id="nav-findings">0</span></div>
      <div class="nav-item" data-view="scans"><span>Scans</span><span class="nb" id="nav-scans">0</span></div>
    </div>
  </aside>
  <main>
    <div class="ph">
      <div class="ph-l">
        <div class="pt" id="pageTitle">Overview</div>
        <div class="ps" id="pageSubtitle">Loading recon data</div>
      </div>
      <div class="ph-r">
        <select id="domainSelect" class="fsel"></select>
      </div>
    </div>
    <div class="tb" id="toolbar"></div>
    <div class="vbody" id="view"></div>
  </main>
</div>
<script>
const state = {
  summaries: [],
  domain: "",
  view: "overview",
  cache: {},
  hostSearch: "",
  candidateSearch: "",
  findingSearch: "",
  scanSearch: "",
  selectedHost: "",
  selectedCandidate: "",
  selectedFindingId: null,
  findingDraft: null
};

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]; });
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error((await res.text()).trim() || ("HTTP " + res.status));
  if (res.status === 204) return null;
  return res.json();
}

function postJSON(path, method, payload) {
  return api(path, {
    method: method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}

function statusClass(value) {
  return "status-" + String(value || "").toLowerCase();
}

function severityClass(value) {
  return "severity-" + String(value || "").toLowerCase();
}

function metricCard(label, value, sub, accent) {
  return "<div class=\"mc" + (accent ? " a" : "") + "\"><div class=\"mc-l\">" + esc(label) + "</div><div class=\"mc-v\">" + esc(value) + "</div><div class=\"mc-s\">" + esc(sub) + "</div></div>";
}

function emptyBlock(message) {
  return "<div class=\"empty\"><div>" + esc(message) + "</div></div>";
}

async function boot() {
  state.summaries = await api("/api/domains");
  const select = document.getElementById("domainSelect");
  if (!state.summaries.length) {
    select.innerHTML = "<option value=\"\">No domains</option>";
    renderNoDomains();
    return;
  }
  select.innerHTML = state.summaries.map(function(item){
    return "<option value=\"" + esc(item.domain) + "\">" + esc(item.domain) + "</option>";
  }).join("");
  state.domain = state.summaries[0].domain;
  select.value = state.domain;
  select.addEventListener("change", function(){
    state.domain = select.value;
    resetDomainUIState();
    render();
  });
  document.querySelectorAll(".nav-item").forEach(function(item){
    item.addEventListener("click", function(){
      document.querySelectorAll(".nav-item").forEach(function(node){ node.classList.remove("active"); });
      item.classList.add("active");
      state.view = item.dataset.view;
      render();
    });
  });
  render();
}

function resetDomainUIState() {
  state.cache = {};
  state.selectedHost = "";
  state.selectedCandidate = "";
  state.selectedFindingId = null;
  state.findingDraft = null;
}

function renderNoDomains() {
  document.getElementById("sidebarDomain").textContent = "No domains loaded";
  document.getElementById("sidebarStatus").textContent = "Database is empty";
  document.getElementById("pageTitle").textContent = "Overview";
  document.getElementById("pageSubtitle").textContent = "No domains in the current database";
  document.getElementById("toolbar").innerHTML = "";
  document.getElementById("view").innerHTML = emptyBlock("No domains in the database yet.");
}

async function fetchDomainData() {
  if (!state.domain) return null;
  const key = state.domain;
  if (!state.cache[key]) {
    const domainPath = "/api/domain/" + encodeURIComponent(key);
    const requests = await Promise.all([
      api(domainPath + "/summary"),
      api(domainPath + "/hosts").catch(function(){ return []; }),
      api(domainPath + "/candidates").catch(function(){ return []; }),
      api(domainPath + "/findings").catch(function(){ return []; }),
      api(domainPath + "/runs").catch(function(){ return []; }),
      api(domainPath + "/subdomains").catch(function(){ return []; })
    ]);
    state.cache[key] = {
      summary: requests[0],
      hosts: requests[1],
      candidates: requests[2],
      findings: requests[3],
      runs: requests[4],
      subdomains: requests[5]
    };
  }
  return state.cache[key];
}

function invalidateDomainCache() {
  delete state.cache[state.domain];
}

function syncSummaryCache(summary) {
  const index = state.summaries.findIndex(function(item){ return item.domain === summary.domain; });
  if (index >= 0) state.summaries[index] = summary;
}

function renderNavCounts(data) {
  document.getElementById("nav-overview").textContent = "1";
  document.getElementById("nav-hosts").textContent = String(data.hosts.length);
  document.getElementById("nav-candidates").textContent = String(data.candidates.length);
  document.getElementById("nav-findings").textContent = String(data.findings.length);
  document.getElementById("nav-scans").textContent = String(data.runs.length);
}

function renderShellMeta(data) {
  const summary = data.summary;
  document.getElementById("sidebarDomain").textContent = summary.domain;
  document.getElementById("sidebarStatus").textContent = summary.resolved + " resolved / " + summary.candidates + " candidates / " + summary.findings + " findings";
  document.getElementById("pageTitle").textContent = viewTitle();
  document.getElementById("pageSubtitle").textContent = summary.domain + " / sqlite-backed recon workspace";
}

function viewTitle() {
  if (state.view === "overview") return "Overview";
  if (state.view === "hosts") return "Hosts & Services";
  if (state.view === "candidates") return "Candidates";
  if (state.view === "findings") return "Findings";
  return "Scans";
}

function renderToolbar(data) {
  const toolbar = document.getElementById("toolbar");
  if (state.view === "hosts") {
    toolbar.innerHTML = "<div class=\"sr\"><input id=\"hostSearch\" type=\"text\" placeholder=\"Search IPs, hostnames, services\"></div><div class=\"sp\"></div><div class=\"rc\">" + esc(data.hosts.length) + " hosts</div>";
    bindToolbarInput("hostSearch", "hostSearch", data);
    return;
  }
  if (state.view === "candidates") {
    toolbar.innerHTML = "<div class=\"sr\"><input id=\"candidateSearch\" type=\"text\" placeholder=\"Search candidate names\"></div><div class=\"sp\"></div><div class=\"rc\">" + esc(data.candidates.length) + " candidates</div>";
    bindToolbarInput("candidateSearch", "candidateSearch", data);
    return;
  }
  if (state.view === "findings") {
    toolbar.innerHTML = "<div class=\"sr\"><input id=\"findingSearch\" type=\"text\" placeholder=\"Search findings, assets, statuses\"></div><button class=\"btn btn-a\" id=\"newFindingBtn\">New Finding</button><div class=\"sp\"></div><div class=\"rc\">" + esc(data.findings.length) + " findings</div>";
    bindToolbarInput("findingSearch", "findingSearch", data);
    document.getElementById("newFindingBtn").addEventListener("click", function(){
      state.selectedFindingId = null;
      state.findingDraft = defaultFindingDraft();
      renderView(data);
    });
    return;
  }
  if (state.view === "scans") {
    toolbar.innerHTML = "<div class=\"sr\"><input id=\"scanSearch\" type=\"text\" placeholder=\"Search tools, targets, commands\"></div><div class=\"sp\"></div><div class=\"rc\">" + esc(data.runs.length) + " tracked scans</div>";
    bindToolbarInput("scanSearch", "scanSearch", data);
    return;
  }
  toolbar.innerHTML = "<div class=\"rc\">Selected domain: " + esc(data.summary.domain) + "</div>";
}

function bindToolbarInput(id, key, data) {
  const input = document.getElementById(id);
  input.value = state[key];
  input.addEventListener("input", function(){
    state[key] = input.value;
    renderView(data);
  });
}

function renderOverview(data) {
  const summary = data.summary;
  const recentRuns = data.runs.slice(0, 6);
  const topHosts = data.hosts.slice(0, 8);
  return ""
    + "<div class=\"mg\">"
    + metricCard("Hosts", data.hosts.length, "IP-centric assets with related services", true)
    + metricCard("Subdomains", summary.subdomains, summary.resolved + " resolved", false)
    + metricCard("Candidates", summary.candidates, "Awaiting DNS or vhost confirmation", false)
    + metricCard("Findings", summary.findings, "Analyst-authored domain findings", false)
    + metricCard("Ports", summary.ports, "Open service records in the database", false)
    + metricCard("Scans", summary.command_runs, "Tracked command executions", false)
    + "</div>"
    + "<div class=\"g2\">"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Host Coverage</div></div><div class=\"pb\">"
    + table(["IP","Hostnames","Ports","Web"], topHosts.map(function(host){
        return [host.IP || host.ip, String((host.Subdomains || host.subdomains || []).length), String((host.Ports || host.ports || []).length), String((host.Probes || host.probes || []).length)];
      }))
    + "</div></div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Finding Snapshot</div></div><div class=\"pb\">"
    + (data.findings.length ? table(["Finding","Severity","Status","Hostname","Service"], data.findings.slice(0, 8).map(function(item){
        const service = item.AffectedService || item.affected_service;
        return [item.Title, item.Severity, item.Status, findingHostname(item), service ? (String(service.port) + " " + String(service.service || service.protocol || "tcp")) : "n/a"];
      })) : emptyBlock("No findings created yet."))
    + "</div></div>"
    + "</div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Recent Scan Activity</div></div><div class=\"pb\">"
    + (recentRuns.length ? recentRuns.map(renderScanItem).join("") : emptyBlock("No tracked scan activity."))
    + "</div></div>";
}

function filteredHosts(hosts) {
  const query = state.hostSearch.trim().toLowerCase();
  if (!query) return hosts;
  return hosts.filter(function(host){
    const values = []
      .concat([host.IP || host.ip])
      .concat(host.Subdomains || host.subdomains || [])
      .concat((host.Ports || host.ports || []).map(function(port){ return String(port.Port || port.port) + " " + String(port.Service || port.service || ""); }))
      .join(" ")
      .toLowerCase();
    return values.indexOf(query) >= 0;
  });
}

function renderHostsView(data) {
  const hosts = filteredHosts(data.hosts);
  if (!hosts.length) return emptyBlock("No hosts match the current filter.");
  if (!state.selectedHost || !hosts.some(function(host){ return (host.IP || host.ip) === state.selectedHost; })) {
    state.selectedHost = hosts[0].IP || hosts[0].ip;
  }
  const selected = hosts.find(function(host){ return (host.IP || host.ip) === state.selectedHost; }) || hosts[0];
  return "<div class=\"hl\"><div class=\"ht\"><div class=\"tree-header\">Tracked Hosts</div>"
    + hosts.map(function(host){
        const ip = host.IP || host.ip;
        const cls = ip === state.selectedHost ? "tree-item sel" : "tree-item";
        return "<div class=\"" + cls + "\" data-ip=\"" + esc(ip) + "\"><div class=\"ti-label mono\">" + esc(ip) + "</div><div class=\"ti-meta\">" + esc((host.Ports || host.ports || []).length) + "p / " + esc((host.Probes || host.probes || []).length) + "w</div></div>";
      }).join("")
    + "</div><div class=\"hd\">" + renderHostDetail(selected) + "</div></div>";
}

function renderHostDetail(host) {
  const subdomains = host.Subdomains || host.subdomains || [];
  const ports = host.Ports || host.ports || [];
  const probes = host.Probes || host.probes || [];
  const candidates = host.Candidates || host.candidates || [];
  return ""
    + "<div class=\"dp-section\"><div class=\"dp-label\">Host</div><div class=\"dp-value\">" + esc(host.IP || host.ip) + "</div></div>"
    + "<div class=\"dp-row\">"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Linked Subdomains</div></div><div class=\"pb\">" + (subdomains.length ? subdomains.map(function(item){ return "<span class=\"host-badge\">" + esc(item) + "</span>"; }).join("") : "<div class=\"dim\">No resolved hostnames linked to this IP.</div>") + "</div></div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Candidate Links</div></div><div class=\"pb\">" + (candidates.length ? candidates.map(function(item){ return "<span class=\"host-badge\">" + esc(item.Subdomain || item.subdomain) + "</span>"; }).join("") : "<div class=\"dim\">No candidate permutations are heuristically linked to this host.</div>") + "</div></div>"
    + "</div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Open Services</div></div><div class=\"pb\">" + (ports.length ? ports.map(function(item){
        const service = joinNonEmpty([item.Service || item.service, item.Version || item.version], " ");
        return "<span class=\"port-chip open\"><span class=\"port-num\">" + esc(item.Port || item.port) + "</span>/" + esc(item.Protocol || item.protocol) + " " + esc(service || item.State || item.state || "open") + "</span>";
      }).join("") : "<div class=\"dim\">No portscan data for this host.</div>") + "</div></div>"
    + "<div class=\"panel\" style=\"margin-top:12px\"><div class=\"ph2\"><div class=\"pt2\">Web Observations</div></div><div class=\"pb\">" + (probes.length ? table(["Target","URL","Status","Title"], probes.map(function(item){
        return [item.Target || item.target, item.URL || item.url, String(item.StatusCode || item.status_code), item.Title || item.title || ""];
      })) : "<div class=\"dim\">No web probes linked to this host.</div>") + "</div></div>";
}

function filteredCandidates(candidates) {
  const query = state.candidateSearch.trim().toLowerCase();
  if (!query) return candidates;
  return candidates.filter(function(item){
    return String(item.Subdomain || "").toLowerCase().indexOf(query) >= 0;
  });
}

function renderCandidatesView(data) {
  const candidates = filteredCandidates(data.candidates);
  if (!candidates.length) return emptyBlock("No permutation candidates match the current filter.");
  if (!state.selectedCandidate || !candidates.some(function(item){ return item.Subdomain === state.selectedCandidate; })) {
    state.selectedCandidate = candidates[0].Subdomain;
  }
  const selected = candidates.find(function(item){ return item.Subdomain === state.selectedCandidate; }) || candidates[0];
  return "<div class=\"hl\"><div class=\"ht\"><div class=\"tree-header\">Permutation Candidates</div>"
    + candidates.map(function(item){
        const cls = item.Subdomain === state.selectedCandidate ? "tree-item sel" : "tree-item";
        return "<div class=\"" + cls + "\" data-candidate=\"" + esc(item.Subdomain) + "\"><div class=\"ti-label mono\">" + esc(item.Subdomain) + "</div><div class=\"ti-meta\">" + esc((item.Sources || []).join(",")) + "</div></div>";
      }).join("")
    + "</div><div class=\"hd\">"
    + "<div class=\"dp-section\"><div class=\"dp-label\">Candidate Hostname</div><div class=\"dp-value\">" + esc(selected.Subdomain) + "</div></div>"
    + "<div class=\"dp-row\">"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Sources</div></div><div class=\"pb\">" + (selected.Sources || []).map(function(src){ return "<span class=\"host-badge\">" + esc(src) + "</span>"; }).join("") + "</div></div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Lifecycle</div></div><div class=\"pb\"><div class=\"dp-section\"><div class=\"dp-label\">First Seen</div><div class=\"dp-value\">" + esc(formatTime(selected.FirstSeenAt)) + "</div></div><div class=\"dp-section\"><div class=\"dp-label\">Last Seen</div><div class=\"dp-value\">" + esc(formatTime(selected.LastSeenAt)) + "</div></div></div></div>"
    + "</div>"
    + "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Candidate Pool Notes</div></div><div class=\"pb\"><p class=\"dim\">This hostname is stored in the permutation candidate pool. It has not been confirmed into the main subdomain set yet. It can still be promoted later through vhost confirmation.</p></div></div>"
    + "</div></div>";
}

function filteredFindings(findings) {
  const query = state.findingSearch.trim().toLowerCase();
  if (!query) return findings;
  return findings.filter(function(finding){
    const values = [finding.Title, finding.Severity, finding.Status]
      .concat(findingServiceSearchValues(finding))
      .concat(finding.LinkedSubdomains || [])
      .concat(finding.LinkedHosts || [])
      .join(" ")
      .toLowerCase();
    return values.indexOf(query) >= 0;
  });
}

function defaultFindingDraft() {
  return {
    Title: "",
    Severity: "medium",
    Status: "open",
    DescriptionHTML: "",
    LinkedSubdomains: [],
    LinkedHosts: [],
    AffectedService: null
  };
}

function findingDraftFromRecord(record) {
  return {
    Title: record.Title || "",
    Severity: record.Severity || "medium",
    Status: record.Status || "open",
    DescriptionHTML: record.DescriptionHTML || "",
    LinkedSubdomains: (record.LinkedSubdomains || []).slice(),
    LinkedHosts: (record.LinkedHosts || []).slice(),
    AffectedService: normalizeAffectedService(record.AffectedService || record.affected_service || null)
  };
}

function selectedFinding(data, findings) {
  if (state.findingDraft && state.selectedFindingId === null) return null;
  if (!state.selectedFindingId || !findings.some(function(item){ return item.ID === state.selectedFindingId; })) {
    state.selectedFindingId = findings.length ? findings[0].ID : null;
  }
  return findings.find(function(item){ return item.ID === state.selectedFindingId; }) || null;
}

function renderFindingsView(data) {
  const findings = filteredFindings(data.findings);
  const selected = selectedFinding(data, findings);
  if (!state.findingDraft) {
    state.findingDraft = selected ? findingDraftFromRecord(selected) : defaultFindingDraft();
  } else if (selected && state.selectedFindingId !== null && state.findingDraft.__boundId !== selected.ID) {
    state.findingDraft = findingDraftFromRecord(selected);
    state.findingDraft.__boundId = selected.ID;
  }

  const rows = findings.map(function(item){
    const cls = item.ID === state.selectedFindingId && !state.findingDraft.__new ? "sel" : "";
    return "<tr class=\"" + cls + "\" data-finding-id=\"" + esc(item.ID) + "\">"
      + "<td>" + esc(item.Title) + "</td>"
      + "<td><span class=\"sev " + esc(severityClass(item.Severity)) + "\">" + esc(item.Severity) + "</span></td>"
      + "<td><span class=\"stag " + esc(statusClass(item.Status)) + "\">" + esc(item.Status.replace("_"," ")) + "</span></td>"
      + "<td class=\"mono\">" + esc(findingHostname(item)) + "</td>"
      + "<td class=\"mono\">" + renderFindingService(item) + "</td>"
      + "<td class=\"mono\">" + esc(formatTime(item.UpdatedAt)) + "</td>"
      + "</tr>";
  }).join("");

  return "<div class=\"find-wrap\">"
    + "<div class=\"find-table\">"
    + "<div class=\"ph2\"><div class=\"pt2\">Domain Findings</div><div class=\"dim\">" + esc(findings.length) + " rows</div></div>"
    + (findings.length ? "<table class=\"tbl\"><thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Hostname</th><th>Service</th><th>Updated</th></tr></thead><tbody>" + rows + "</tbody></table>" : emptyBlock("No findings yet. Use New Finding to start documenting evidence."))
    + "</div>"
    + "<div class=\"find-editor\">"
    + "<div class=\"ph2\"><div class=\"pt2\">" + esc(state.selectedFindingId ? "Edit Finding" : "New Finding") + "</div><div class=\"dim\">" + esc(state.domain) + "</div></div>"
    + "<div class=\"find-editor-body\">" + renderFindingEditor(data, selected) + "</div>"
    + "</div>"
    + "</div>";
}

function findingServiceSearchValues(finding) {
  const service = finding.AffectedService || finding.affected_service;
  if (!service) return [];
  return [service.hostname, service.host_ip, service.host, service.port, service.protocol, service.service];
}

function normalizeAffectedService(service) {
  if (!service) return null;
  const port = Number(service.port || service.Port || 0);
  const hostIP = service.host_ip || service.HostIP || service.host || service.Host || "";
  if (!hostIP || !port) return null;
  return {
    hostname: service.hostname || service.Hostname || "",
    host_ip: hostIP,
    port: port,
    protocol: service.protocol || service.Protocol || "tcp",
    service: service.service || service.Service || ""
  };
}

function findingHostname(finding) {
  const service = normalizeAffectedService(finding.AffectedService || finding.affected_service);
  if (service && service.hostname) return service.hostname;
  const linked = finding.LinkedSubdomains || [];
  return linked.length ? linked[0] : "n/a";
}

function renderFindingService(finding) {
  const service = normalizeAffectedService(finding.AffectedService || finding.affected_service);
  if (!service || !service.port) return "<span class=\"dim\">n/a</span>";
  const type = service.service || service.protocol || "tcp";
  return "<span class=\"port-chip open\"><span class=\"port-num\">" + esc(service.port) + "</span> " + esc(type) + "</span>";
}

function renderFindingEditor(data, selected) {
  const draft = state.findingDraft || defaultFindingDraft();
  const serviceOptions = findingServiceOptions(data);
  const selectedServiceKey = draft.AffectedService ? serviceOptionKey(draft.AffectedService) : "";
  const serviceSearch = draft.ServiceSearch !== undefined ? draft.ServiceSearch : serviceLabelForKey(serviceOptions, selectedServiceKey);
  return ""
    + "<div class=\"field-group\"><div class=\"field-label\">Title</div><input id=\"findingTitle\" class=\"field-input\" type=\"text\" value=\"" + esc(draft.Title || "") + "\" placeholder=\"Exposed administrative surface\"></div>"
    + "<div class=\"field-row\">"
    + "<div class=\"field-group\"><div class=\"field-label\">Severity</div><select id=\"findingSeverity\" class=\"field-select\">" + selectOptions(["critical","high","medium","low","info"], draft.Severity) + "</select></div>"
    + "<div class=\"field-group\"><div class=\"field-label\">Status</div><select id=\"findingStatus\" class=\"field-select\">" + selectOptions(["open","verified","fixed","false_positive"], draft.Status) + "</select></div>"
    + "</div>"
    + "<div class=\"field-group\"><div class=\"field-label\">Description</div>"
    + "<div class=\"editor-toolbar\">"
    + "<button class=\"editor-btn\" data-editor-cmd=\"bold\" type=\"button\">Bold</button>"
    + "<button class=\"editor-btn\" data-editor-cmd=\"italic\" type=\"button\">Italic</button>"
    + "<button class=\"editor-btn\" data-editor-cmd=\"insertUnorderedList\" type=\"button\">List</button>"
    + "<button class=\"editor-btn\" data-editor-cmd=\"formatBlock\" data-editor-value=\"pre\" type=\"button\">Code</button>"
    + "<button class=\"editor-btn\" data-editor-clear=\"true\" type=\"button\">Plain</button>"
    + "</div>"
    + "<div id=\"findingDescription\" class=\"editor-surface\" contenteditable=\"true\" data-placeholder=\"Describe the issue, evidence, and context.\">" + (draft.DescriptionHTML || "") + "</div>"
    + "</div>"
    + "<div class=\"field-group\"><div class=\"field-label\">Affected Service</div>" + renderServiceCombo(serviceOptions, selectedServiceKey, serviceSearch) + "</div>"
    + "<div class=\"field-group\"><div class=\"field-label\">Preview</div><div class=\"find-preview\" id=\"findingPreview\">" + (draft.DescriptionHTML || "<span class='find-note'>Start writing to preview the rich text description.</span>") + "</div></div>"
    + "<div class=\"find-actions\"><div class=\"find-note\">If evidence materially differs per service, create separate findings.</div><div style=\"display:flex;gap:8px\">"
    + (state.selectedFindingId ? "<button class=\"btn btn-d\" id=\"deleteFindingBtn\" type=\"button\">Delete</button>" : "")
    + "<button class=\"btn\" id=\"resetFindingBtn\" type=\"button\">Reset</button>"
    + "<button class=\"btn btn-a\" id=\"saveFindingBtn\" type=\"button\">Save Finding</button>"
    + "</div></div>";
}

function renderServiceCombo(options, selectedKey, query) {
  const filtered = filterServiceOptions(options, query, selectedKey);
  return "<div class=\"service-combo\">"
    + "<input id=\"findingServiceSearch\" class=\"field-input\" type=\"text\" value=\"" + esc(query || "") + "\" placeholder=\"Search hostname, IP, port, or service\">"
    + "<input id=\"findingService\" type=\"hidden\" value=\"" + esc(selectedKey || "") + "\">"
    + "<div class=\"service-results\" id=\"findingServiceResults\">"
    + (filtered.length ? filtered.map(function(option){ return renderServiceOption(option, option.key === selectedKey); }).join("") : "<div class=\"find-note\" style=\"padding:10px\">No matching services.</div>")
    + "</div></div>";
}

function renderServiceOption(option, selected) {
  return "<button class=\"service-option" + (selected ? " sel" : "") + "\" type=\"button\" data-service-key=\"" + esc(option.key) + "\" data-service-label=\"" + esc(option.label) + "\">"
    + "<span class=\"service-main\">" + esc(option.label) + "</span>"
    + "<span class=\"service-meta\">" + esc(option.meta) + "</span>"
    + "</button>";
}

function filterServiceOptions(options, query, selectedKey) {
  query = String(query || "").trim().toLowerCase();
  if (!query) {
    return options.slice().sort(function(a, b){
      if (a.key === selectedKey) return -1;
      if (b.key === selectedKey) return 1;
      return a.label.localeCompare(b.label);
    });
  }
  return options.filter(function(option){
    return option.search.indexOf(query) >= 0;
  });
}

function serviceLabelForKey(options, key) {
  if (!key) return "";
  const found = options.find(function(option){ return option.key === key; });
  return found ? found.label : "";
}

function findingServiceOptions(data) {
  const options = [];
  (data.hosts || []).forEach(function(host){
    const ip = host.IP || host.ip || "";
    const names = (host.Subdomains || host.subdomains || []).slice();
    if (!names.length) names.push("");
    (host.Ports || host.ports || []).forEach(function(port){
      names.forEach(function(hostname){
        const service = {
          hostname: hostname,
          host_ip: ip,
          port: Number(port.Port || port.port || 0),
          protocol: port.Protocol || port.protocol || "tcp",
          service: port.Service || port.service || ""
        };
        if (!service.host_ip || !service.port) return;
        const labelHost = service.hostname || service.host_ip;
        const labelType = service.service || service.protocol || "tcp";
        const label = labelHost + " / " + service.port + " " + labelType;
        const meta = service.host_ip + "/" + service.protocol;
        options.push({
          key: serviceOptionKey(service),
          service: service,
          label: label,
          meta: meta,
          search: [label, meta, service.hostname, service.host_ip, service.port, service.protocol, service.service].join(" ").toLowerCase()
        });
      });
    });
  });
  options.sort(function(a, b){ return a.label.localeCompare(b.label); });
  return options;
}

function serviceOptionKey(service) {
  service = normalizeAffectedService(service);
  if (!service) return "";
  return [service.hostname, service.host_ip, service.port, service.protocol, service.service].map(encodeURIComponent).join("|");
}

function serviceFromOptionKey(key) {
  if (!key) return null;
  const parts = String(key).split("|").map(decodeURIComponent);
  return normalizeAffectedService({
    hostname: parts[0] || "",
    host_ip: parts[1] || "",
    port: Number(parts[2] || 0),
    protocol: parts[3] || "tcp",
    service: parts[4] || ""
  });
}

function selectOptions(values, selected) {
  return values.map(function(value){
    const picked = value === selected ? " selected" : "";
    return "<option value=\"" + esc(value) + "\"" + picked + ">" + esc(value.replace("_"," ")) + "</option>";
  }).join("");
}

function syncFindingDraftFromForm() {
  if (!state.findingDraft) state.findingDraft = defaultFindingDraft();
  const selectedService = serviceFromOptionKey(document.getElementById("findingService").value);
  const serviceSearch = document.getElementById("findingServiceSearch");
  state.findingDraft.Title = document.getElementById("findingTitle").value;
  state.findingDraft.Severity = document.getElementById("findingSeverity").value;
  state.findingDraft.Status = document.getElementById("findingStatus").value;
  state.findingDraft.DescriptionHTML = document.getElementById("findingDescription").innerHTML;
  state.findingDraft.AffectedService = selectedService;
  state.findingDraft.ServiceSearch = serviceSearch ? serviceSearch.value : "";
  state.findingDraft.LinkedSubdomains = selectedService && selectedService.hostname ? [selectedService.hostname] : [];
  state.findingDraft.LinkedHosts = selectedService ? [selectedService.host_ip] : [];
  updateFindingPreview();
}

function updateFindingPreview() {
  const preview = document.getElementById("findingPreview");
  if (!preview) return;
  const html = (state.findingDraft && state.findingDraft.DescriptionHTML || "").trim();
  preview.innerHTML = html || "<span class='find-note'>Start writing to preview the rich text description.</span>";
}

function clearEditorFormatting() {
  if (document.queryCommandState("bold")) document.execCommand("bold", false, null);
  if (document.queryCommandState("italic")) document.execCommand("italic", false, null);
  if (document.queryCommandState("insertUnorderedList")) document.execCommand("insertUnorderedList", false, null);
  document.execCommand("formatBlock", false, "div");
  document.execCommand("removeFormat", false, null);
}

async function saveFinding() {
  syncFindingDraftFromForm();
  const payload = {
    title: state.findingDraft.Title,
    severity: state.findingDraft.Severity,
    status: state.findingDraft.Status,
    description_html: state.findingDraft.DescriptionHTML,
    linked_subdomains: state.findingDraft.LinkedSubdomains,
    linked_hosts: state.findingDraft.LinkedHosts,
    affected_service: state.findingDraft.AffectedService
  };
  if (state.selectedFindingId) {
    await postJSON("/api/finding/" + encodeURIComponent(state.selectedFindingId), "PUT", payload);
  } else {
    const created = await postJSON("/api/domain/" + encodeURIComponent(state.domain) + "/findings", "POST", payload);
    state.selectedFindingId = created.ID;
  }
  state.findingDraft = null;
  invalidateDomainCache();
  const data = await fetchDomainData();
  syncSummaryCache(data.summary);
  renderNavCounts(data);
  renderShellMeta(data);
  renderToolbar(data);
  renderView(data);
}

async function deleteFinding() {
  if (!state.selectedFindingId) return;
  if (!window.confirm("Delete this finding?")) return;
  await api("/api/finding/" + encodeURIComponent(state.selectedFindingId), { method: "DELETE" });
  state.selectedFindingId = null;
  state.findingDraft = defaultFindingDraft();
  invalidateDomainCache();
  const data = await fetchDomainData();
  syncSummaryCache(data.summary);
  renderNavCounts(data);
  renderShellMeta(data);
  renderToolbar(data);
  renderView(data);
}

function filteredRuns(runs) {
  const query = state.scanSearch.trim().toLowerCase();
  if (!query) return runs;
  return runs.filter(function(run){
    return [run.Tool, run.Target, run.Command, run.Status].join(" ").toLowerCase().indexOf(query) >= 0;
  });
}

function renderScansView(data) {
  const runs = filteredRuns(data.runs);
  if (!runs.length) return emptyBlock("No tracked scan activity for this domain.");
  return "<div class=\"panel\"><div class=\"ph2\"><div class=\"pt2\">Tracked Scan Activity</div></div><div class=\"pb\">" + runs.map(renderScanItem).join("") + "</div></div>";
}

function renderScanItem(run) {
  const status = String(run.Status || "").toLowerCase();
  return "<div class=\"scan-item\">"
    + "<div class=\"scan-icon\">" + esc((run.Tool || "run").slice(0, 4).toUpperCase()) + "</div>"
    + "<div class=\"scan-body\">"
    + "<div class=\"scan-title\">" + esc(run.Tool || "command") + " against " + esc(run.Target || "unknown target") + "</div>"
    + "<div class=\"scan-cmd\">" + esc(run.Command || "") + "</div>"
    + "<div class=\"scan-meta\"><span>started " + esc(formatTime(run.StartedAt)) + "</span><span>" + esc(run.Wordlist || "no wordlist metadata") + "</span></div>"
    + "</div>"
    + "<div class=\"scan-r\"><span class=\"stag " + esc(statusClass(status)) + "\">" + esc(run.Status || "unknown") + "</span></div>"
    + "</div>";
}

function renderView(data) {
  const root = document.getElementById("view");
  if (state.view === "overview") root.innerHTML = renderOverview(data);
  else if (state.view === "hosts") root.innerHTML = renderHostsView(data);
  else if (state.view === "candidates") root.innerHTML = renderCandidatesView(data);
  else if (state.view === "findings") root.innerHTML = renderFindingsView(data);
  else root.innerHTML = renderScansView(data);
  wireDynamicEvents(data);
}

function wireDynamicEvents(data) {
  if (state.view === "hosts") {
    document.querySelectorAll("[data-ip]").forEach(function(node){
      node.addEventListener("click", function(){
        state.selectedHost = node.getAttribute("data-ip");
        renderView(data);
      });
    });
  }
  if (state.view === "candidates") {
    document.querySelectorAll("[data-candidate]").forEach(function(node){
      node.addEventListener("click", function(){
        state.selectedCandidate = node.getAttribute("data-candidate");
        renderView(data);
      });
    });
  }
  if (state.view === "findings") {
    document.querySelectorAll("[data-finding-id]").forEach(function(node){
      node.addEventListener("click", function(){
        state.selectedFindingId = Number(node.getAttribute("data-finding-id"));
        state.findingDraft = null;
        renderView(data);
      });
    });
    const title = document.getElementById("findingTitle");
    const severity = document.getElementById("findingSeverity");
    const status = document.getElementById("findingStatus");
    const serviceSearch = document.getElementById("findingServiceSearch");
    const description = document.getElementById("findingDescription");
    if (title) title.addEventListener("input", syncFindingDraftFromForm);
    if (severity) severity.addEventListener("change", syncFindingDraftFromForm);
    if (status) status.addEventListener("change", syncFindingDraftFromForm);
    if (serviceSearch) {
      serviceSearch.addEventListener("input", function(){
        syncFindingDraftFromForm();
        renderView(data);
        const nextSearch = document.getElementById("findingServiceSearch");
        if (nextSearch) {
          nextSearch.focus();
          const pos = nextSearch.value.length;
          nextSearch.setSelectionRange(pos, pos);
        }
      });
    }
    document.querySelectorAll("[data-service-key]").forEach(function(node){
      node.addEventListener("click", function(){
        if (!state.findingDraft) state.findingDraft = defaultFindingDraft();
        state.findingDraft.AffectedService = serviceFromOptionKey(node.getAttribute("data-service-key"));
        state.findingDraft.ServiceSearch = node.getAttribute("data-service-label") || "";
        renderView(data);
      });
    });
    if (description) {
      description.addEventListener("input", syncFindingDraftFromForm);
      document.querySelectorAll("[data-editor-cmd]").forEach(function(button){
        button.addEventListener("click", function(){
          const cmd = button.getAttribute("data-editor-cmd");
          const value = button.getAttribute("data-editor-value");
          description.focus();
          document.execCommand(cmd, false, value || null);
          syncFindingDraftFromForm();
        });
      });
      document.querySelectorAll("[data-editor-clear]").forEach(function(button){
        button.addEventListener("click", function(){
          description.focus();
          clearEditorFormatting();
          syncFindingDraftFromForm();
        });
      });
    }
    const reset = document.getElementById("resetFindingBtn");
    if (reset) reset.addEventListener("click", function(){
      state.findingDraft = state.selectedFindingId ? null : defaultFindingDraft();
      renderView(data);
    });
    const save = document.getElementById("saveFindingBtn");
    if (save) save.addEventListener("click", function(){ saveFinding().catch(showError); });
    const del = document.getElementById("deleteFindingBtn");
    if (del) del.addEventListener("click", function(){ deleteFinding().catch(showError); });
  }
}

function showError(err) {
  window.alert(err && err.message ? err.message : String(err));
}

function formatTime(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (isNaN(date.getTime())) return String(value);
  return date.toISOString().replace(".000Z", "Z");
}

function joinNonEmpty(values, separator) {
  return values.filter(function(value){ return String(value || "").trim() !== ""; }).join(separator);
}

function table(headers, rows) {
  if (!rows.length) return emptyBlock("No records.");
  return "<table class=\"tbl\"><thead><tr>" + headers.map(function(h){ return "<th>" + esc(h) + "</th>"; }).join("") + "</tr></thead><tbody>"
    + rows.map(function(row){ return "<tr>" + row.map(function(cell){ return "<td>" + esc(cell) + "</td>"; }).join("") + "</tr>"; }).join("")
    + "</tbody></table>";
}

async function render() {
  if (!state.domain) {
    renderNoDomains();
    return;
  }
  try {
    const data = await fetchDomainData();
    syncSummaryCache(data.summary);
    renderNavCounts(data);
    renderShellMeta(data);
    renderToolbar(data);
    renderView(data);
  } catch (err) {
    document.getElementById("view").innerHTML = emptyBlock(err.message || "Failed to load UI data.");
  }
}

boot().catch(function(err){
  document.getElementById("view").innerHTML = emptyBlock(err.message || "Failed to boot UI.");
});
</script>
</body>
</html>`
