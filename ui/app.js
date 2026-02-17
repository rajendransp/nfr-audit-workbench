var state = {
  all: [],
  shown: [],
  pageRows: [],
  reviewState: {},
  selectedFindingKey: "",
  currentPage: 1,
  pageSize: 20,
  currentFile: "findings.json",
  viewMode: "findings",
  sortCol: "severity",
  sortDir: "asc",
  loadToken: 0,
  columns: {
    severity: true,
    source: true,
    trustTier: true,
    quickWin: true,
    effortBenefit: true,
    workflowStatus: true,
    rule: true,
    topLevelCategory: true,
    subCategory: true,
    language: true,
    fileType: true,
    location: true,
    confidence: true,
    recommendation: true,
    snippet: true,
    patch: true,
    title: true
  }
};

var severityEl = document.getElementById("severityFilter");
var sourceEl = document.getElementById("sourceFilter");
var ruleEl = document.getElementById("ruleFilter");
var trustTierEl = document.getElementById("trustTierFilter");
var safeAiRiskEl = document.getElementById("safeAiRiskFilter");
var validationEl = document.getElementById("validationFilter");
var workflowStatusEl = document.getElementById("workflowStatusFilter");
var quickWinEl = document.getElementById("quickWinFilter");
var fallbackEl = document.getElementById("fallbackFilter");
var topLevelEl = document.getElementById("topLevelFilter");
var subCategoryEl = document.getElementById("subCategoryFilter");
var searchEl = document.getElementById("searchInput");
var rowsEl = document.getElementById("rows");
var emptyEl = document.getElementById("empty");
var cardsEl = document.getElementById("summaryCards");
var detailsEl = document.getElementById("details");
var detailsBodyEl = document.getElementById("detailsBody");
var statusEl = document.getElementById("statusText");
var filePickerEl = document.getElementById("filePicker");
var uploadEl = document.getElementById("uploadInput");
var tabFindingsEl = document.getElementById("tabFindings");
var tabSafeAiEl = document.getElementById("tabSafeAi");
var columnTogglesEl = document.getElementById("columnToggles");
var snippetHeightEl = document.getElementById("snippetHeight");
var snippetHeightValueEl = document.getElementById("snippetHeightValue");
var patchHeightEl = document.getElementById("patchHeight");
var patchHeightValueEl = document.getElementById("patchHeightValue");
var splitterEl = document.getElementById("splitter");
var splitEl = document.querySelector(".split");
var pageSizeEl = document.getElementById("pageSize");
var pageInfoEl = document.getElementById("pageInfo");
var firstPageBtnEl = document.getElementById("firstPageBtn");
var prevPageBtnEl = document.getElementById("prevPageBtn");
var nextPageBtnEl = document.getElementById("nextPageBtn");
var lastPageBtnEl = document.getElementById("lastPageBtn");
var toggleFiltersPanelBtnEl = document.getElementById("toggleFiltersPanelBtn");
var filtersPanelBodyEl = document.getElementById("filtersPanelBody");
state.pageSize = Number(pageSizeEl && pageSizeEl.value ? pageSizeEl.value : 20) || 20;

var DEFAULT_COLUMN_ORDER = ["workflowStatus","severity","source","trustTier","quickWin","effortBenefit","rule","topLevelCategory","subCategory","language","fileType","location","confidence","recommendation","snippet","patch","title"];
var COLUMN_ORDER = DEFAULT_COLUMN_ORDER.slice();
var DEFAULT_EMPTY_TEXT = "No findings match current filters.";

function setStatus(message) {
  statusEl.textContent = message;
  console.log("[NFR-Audit-Workbench] " + message);
}

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>\"']/g, function (ch) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch];
  });
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function get(obj, path, fallback) {
  var cur = obj;
  for (var i = 0; i < path.length; i++) {
    if (cur == null || typeof cur !== "object" || !(path[i] in cur)) return fallback;
    cur = cur[path[i]];
  }
  return cur == null ? fallback : cur;
}

function sevOf(f) {
  return String(get(f, ["llm_review", "severity"], f.default_severity || "S3")).toUpperCase();
}

function quickWinOf(f) {
  return Boolean(get(f, ["llm_review", "quick_win"], false));
}

function isIssueOf(f) {
  return Boolean(get(f, ["llm_review", "isIssue"], false));
}

function workflowStatusOf(f) {
  var key = String(f.finding_key || "");
  var rec = key ? state.reviewState[key] : null;
  var status = String((rec && rec.status) || "").toLowerCase();
  if (status === "in_progress" || status === "verified" || status === "resolved" || status === "todo") return status;
  return "todo";
}

function workflowStatusLabel(status) {
  var s = String(status || "").toLowerCase();
  if (s === "in_progress") return "in_progress";
  if (s === "verified") return "verified";
  if (s === "resolved") return "resolved";
  return "todo";
}

function fallbackOf(f) {
  return Boolean(get(f, ["llm_transport", "fallback_used"], false));
}

function safeAiRiskOf(f) {
  var r = String(get(f, ["ai_policy", "risk"], "") || "").trim().toLowerCase();
  if (r === "high" || r === "medium" || r === "low") return r;
  return "none";
}

function trustTierOf(f) {
  var reviewStatus = String(f.review_status || "").trim().toLowerCase();
  var skipped = Boolean(get(f, ["llm_transport", "llm_skipped"], false));
  if (reviewStatus === "regex_only" || reviewStatus === "roslyn_only" || skipped) {
    var src = String(f.source || "").toLowerCase();
    if (src === "roslyn") return "roslyn";
    return "regex_only";
  }
  var explicitTier = String(f.trust_tier || "").trim().toLowerCase();
  if (explicitTier) return explicitTier;
  if (fallbackOf(f)) return "fallback";
  if (Boolean(get(f, ["llm_transport", "fast_routed"], false))) return "fast_routed";
  if (f.llm_review && typeof f.llm_review === "object") return "llm_confirmed";
  if (String(f.source || "").toLowerCase() === "regex") return "regex_only";
  if (String(f.source || "").toLowerCase() === "roslyn") return "roslyn";
  return "unknown";
}

function effortOf(f) {
  return String(get(f, ["llm_review", "effort"], "medium"));
}

function benefitOf(f) {
  return String(get(f, ["llm_review", "benefit"], "medium"));
}

function patchStatusOf(f) {
  var p = String(get(f, ["llm_review", "patch"], "unknown") || "unknown").toLowerCase();
  var q = String(get(f, ["llm_review", "patch_quality"], "unknown") || "unknown").toLowerCase();
  if (q === "no_op") return "no-op dropped";
  if (p && p !== "unknown") return "available";
  return "unknown";
}

function isSafeAiPayload(json) {
  if (!json || !Array.isArray(json.findings)) return false;
  if (json.findings.length === 0) return Boolean(json.summary && json.summary.total_findings != null && json.provider);
  return ("risk" in json.findings[0]) && !("llm_review" in json.findings[0]);
}

function severityFromRisk(risk) {
  var r = String(risk || "").toLowerCase();
  if (r === "high") return "S1";
  if (r === "medium") return "S2";
  return "S4";
}

function confidenceFromRisk(risk) {
  var r = String(risk || "").toLowerCase();
  if (r === "high") return 0.95;
  if (r === "medium") return 0.75;
  return 0.55;
}

function recommendationFromRisk(risk) {
  var r = String(risk || "").toLowerCase();
  if (r === "high") return "Do not send externally. Use local model or internal review.";
  if (r === "medium") return "Redact sensitive details before external AI usage.";
  return "Allowed for external AI under policy with normal review.";
}

function normalizeSafeAiPayload(json) {
  var raw = Array.isArray(json.findings) ? json.findings : [];
  var out = [];
  for (var i = 0; i < raw.length; i++) {
    var item = raw[i] || {};
    var risk = String(item.risk || "low").toLowerCase();
    out.push({
      finding_key: item.finding_key || ("safe_ai_" + i),
      source: item.source || "regex",
      rule_id: item.rule_id || "SAFE-AI-RISK",
      rule_title: "Safe AI risk classification",
      top_level_category: item.top_level_category || "safe_ai",
      sub_category: item.sub_category || "risk",
      file: item.file || "unknown",
      line: item.line || 1,
      file_type: "unknown",
      language: "unknown",
      match_text: item.match_text || "",
      snippet: item.match_text || "",
      llm_review: {
        isIssue: true,
        severity: severityFromRisk(risk),
        confidence: confidenceFromRisk(risk),
        title: "Safe AI " + risk + " risk",
        why: "Snippet classified as " + risk + " risk for external AI boundary.",
        recommendation: recommendationFromRisk(risk),
        effort: "low",
        benefit: "high",
        quick_win: risk !== "low",
        patch: "unknown",
        patch_quality: "unknown",
        patch_attention: "unavailable",
        patch_attention_reason: "risk_report_only"
      },
      ai_policy: {
        mode: "dry_run",
        risk: risk,
        external_boundary: Boolean(json.external_boundary),
        blocked: false,
        redacted: false
      }
    });
  }
  return {
    summary: {
      total_reviewed: (json.summary && json.summary.total_findings) != null ? json.summary.total_findings : out.length,
      confirmed_issues: out.length,
      by_severity: {
        S1: Number((json.summary || {}).high || 0),
        S2: Number((json.summary || {}).medium || 0),
        S3: 0,
        S4: Number((json.summary || {}).low || 0)
      },
      by_source: {},
      by_trust_tier: {},
      safe_ai: {
        provider: json.provider || "unknown",
        external_boundary: Boolean(json.external_boundary),
        high: Number((json.summary || {}).high || 0),
        medium: Number((json.summary || {}).medium || 0),
        low: Number((json.summary || {}).low || 0)
      }
    },
    findings: out
  };
}

function setViewMode(mode) {
  state.viewMode = (mode === "safe_ai") ? "safe_ai" : "findings";
  if (tabFindingsEl) tabFindingsEl.classList.toggle("active", state.viewMode === "findings");
  if (tabSafeAiEl) tabSafeAiEl.classList.toggle("active", state.viewMode === "safe_ai");
}

function topLevelOf(f) {
  return String(f.top_level_category || "unknown").toLowerCase();
}

function subCategoryOf(f) {
  return String(f.sub_category || "unknown").toLowerCase();
}

function ruleOf(f) {
  return String(f.rule_id || "unknown").toUpperCase();
}

function setSelectOptions(selectEl, values, keepValue) {
  if (!selectEl) return;
  var sorted = values.slice().sort();
  var html = '<option value="ALL">All</option>';
  for (var i = 0; i < sorted.length; i++) {
    html += '<option value="' + esc(sorted[i]) + '">' + esc(sorted[i]) + "</option>";
  }
  selectEl.innerHTML = html;
  if (keepValue && sorted.indexOf(keepValue) !== -1) selectEl.value = keepValue;
  else selectEl.value = "ALL";
}

function refreshCategoryFilters() {
  var prevTop = topLevelEl ? topLevelEl.value : "ALL";
  var prevSub = subCategoryEl ? subCategoryEl.value : "ALL";
  var prevRule = ruleEl ? ruleEl.value : "ALL";
  var topLevels = {};
  var rules = {};
  for (var i = 0; i < state.all.length; i++) topLevels[topLevelOf(state.all[i])] = true;
  for (var r = 0; r < state.all.length; r++) rules[ruleOf(state.all[r])] = true;
  setSelectOptions(ruleEl, Object.keys(rules), prevRule !== "ALL" ? prevRule : "");
  setSelectOptions(topLevelEl, Object.keys(topLevels), prevTop !== "ALL" ? prevTop : "");

  var selectedTop = topLevelEl ? topLevelEl.value : "ALL";
  var subs = {};
  for (var j = 0; j < state.all.length; j++) {
    var f = state.all[j];
    if (selectedTop !== "ALL" && topLevelOf(f) !== selectedTop) continue;
    subs[subCategoryOf(f)] = true;
  }
  setSelectOptions(subCategoryEl, Object.keys(subs), prevSub !== "ALL" ? prevSub : "");
}

function renderCards(summary) {
  summary = summary || {};
  if (state.viewMode === "safe_ai") {
    var safe = summary.safe_ai || {};
    var safeRows = [
      ["Total", summary.total_reviewed != null ? summary.total_reviewed : state.all.length],
      ["High", Number(safe.high || 0)],
      ["Medium", Number(safe.medium || 0)],
      ["Low", Number(safe.low || 0)],
      ["Provider", String(safe.provider || "unknown")],
      ["External", safe.external_boundary ? "Yes" : "No"],
      ["Mode", "safe_ai"]
    ];
    var safeHtml = "";
    for (var s = 0; s < safeRows.length; s++) {
      safeHtml += '<article class="card"><div class="k">' + esc(safeRows[s][0]) + '</div><div class="v">' + esc(safeRows[s][1]) + '</div></article>';
    }
    cardsEl.innerHTML = safeHtml;
    return;
  }
  var confirmedComputed = 0;
  var falsePositiveComputed = 0;
  for (var idx = 0; idx < state.all.length; idx++) {
    if (isIssueOf(state.all[idx])) confirmedComputed++;
    else falsePositiveComputed++;
  }
  var reviewedCount = summary.total_reviewed != null ? summary.total_reviewed : state.all.length;
  var confirmedCount = summary.confirmed_issues != null ? summary.confirmed_issues : confirmedComputed;
  var falsePositiveCount = Math.max(0, reviewedCount - confirmedCount);
  if (state.all.length > 0) falsePositiveCount = falsePositiveComputed;
  var rows = [
    ["Reviewed", reviewedCount],
    ["Confirmed", confirmedCount],
    ["False Positives", falsePositiveCount],
    ["S1", get(summary, ["by_severity", "S1"], 0)],
    ["S2", get(summary, ["by_severity", "S2"], 0)],
    ["Regex", get(summary, ["by_source", "regex"], 0)],
    ["Roslyn", get(summary, ["by_source", "roslyn"], 0)],
    ["Fallback", get(summary, ["by_trust_tier", "fallback"], 0)]
  ];
  var html = "";
  for (var i = 0; i < rows.length; i++) {
    html += '<article class="card"><div class="k">' + esc(rows[i][0]) + '</div><div class="v">' + esc(rows[i][1]) + '</div></article>';
  }
  cardsEl.innerHTML = html;
}

function shortText(v, max) {
  v = String(v || "");
  if (v.length <= max) return v;
  return v.slice(0, max - 1) + "...";
}

function td(col, content) {
  return '<td data-col="' + col + '">' + content + '</td>';
}

function _columnCellMap(f) {
  var sev = sevOf(f);
  var cls = sev.toLowerCase();
  var title = get(f, ["llm_review", "title"], f.rule_title || "Untitled");
  var loc = (f.file || "unknown") + ":" + (f.line || 1);
  var conf = get(f, ["llm_review", "confidence"], "-");
  var rec = get(f, ["llm_review", "recommendation"], "");
  var snippet = f.snippet || f.match_text || "";
  var patchStatus = patchStatusOf(f);
  var quickWin = quickWinOf(f);
  var effortBenefit = effortOf(f) + " / " + benefitOf(f);
  var ws = workflowStatusOf(f);
  return {
    workflowStatus:
      '<select class="row-workflow-select" data-fk="' + esc(f.finding_key || "") + '">' +
      '<option value="todo"' + (ws === "todo" ? " selected" : "") + '>To Do</option>' +
      '<option value="in_progress"' + (ws === "in_progress" ? " selected" : "") + '>In Progress</option>' +
      '<option value="verified"' + (ws === "verified" ? " selected" : "") + '>Verified</option>' +
      '<option value="resolved"' + (ws === "resolved" ? " selected" : "") + '>Resolved</option>' +
      '</select>',
    severity: '<span class="badge ' + esc(cls) + '">' + esc(sev) + '</span>',
    source: esc(f.source || "unknown"),
    trustTier: '<span class="trust-badge trust-' + esc(trustTierOf(f)) + '">' + esc(trustTierOf(f)) + '</span>',
    quickWin: quickWin ? '<span class="pill-yes">Yes</span>' : '<span class="pill-no">No</span>',
    effortBenefit: '<span class="mini">' + esc(effortBenefit) + '</span>',
    rule: esc(f.rule_id || "-"),
    topLevelCategory: esc(topLevelOf(f)),
    subCategory: esc(subCategoryOf(f)),
    language: esc(f.language || "unknown"),
    fileType: esc(f.file_type || "unknown"),
    location: '<code>' + esc(loc) + '</code>',
    confidence: esc(conf),
    recommendation: esc(shortText(rec, 80)),
    snippet: esc(shortText(snippet.replace(/\s+/g, " "), 90)),
    patch: esc(patchStatus),
    title: esc(title)
  };
}

function rowTemplate(f, i) {
  var cells = _columnCellMap(f);
  var html = '<tr class="clickable" data-i="' + i + '">';
  for (var c = 0; c < COLUMN_ORDER.length; c++) {
    var key = COLUMN_ORDER[c];
    html += td(key, cells[key] || "");
  }
  html += '</tr>';
  return html;
}

function normalizeColumnOrder(order) {
  var incoming = Array.isArray(order) ? order : [];
  var keep = {};
  var out = [];
  for (var i = 0; i < incoming.length; i++) {
    var c = String(incoming[i] || "");
    if (!c || keep[c] || DEFAULT_COLUMN_ORDER.indexOf(c) === -1) continue;
    keep[c] = true;
    out.push(c);
  }
  for (var j = 0; j < DEFAULT_COLUMN_ORDER.length; j++) {
    var d = DEFAULT_COLUMN_ORDER[j];
    if (!keep[d]) out.push(d);
  }
  return out;
}

function saveColumnPrefs() {
  try {
    localStorage.setItem("nfr_columns_visibility", JSON.stringify(state.columns));
    localStorage.setItem("nfr_columns_order", JSON.stringify(COLUMN_ORDER));
  } catch (e) {}
}

function loadColumnPrefs() {
  try {
    var rawVis = localStorage.getItem("nfr_columns_visibility");
    if (rawVis) {
      var vis = JSON.parse(rawVis);
      if (vis && typeof vis === "object") {
        for (var i = 0; i < DEFAULT_COLUMN_ORDER.length; i++) {
          var c = DEFAULT_COLUMN_ORDER[i];
          if (c in vis) state.columns[c] = Boolean(vis[c]);
        }
      }
    }
  } catch (e) {}
  try {
    var rawOrder = localStorage.getItem("nfr_columns_order");
    if (rawOrder) COLUMN_ORDER = normalizeColumnOrder(JSON.parse(rawOrder));
  } catch (e) {}
}

function moveColumn(col, dir) {
  var idx = COLUMN_ORDER.indexOf(col);
  if (idx === -1) return;
  var swapIdx = idx + (dir < 0 ? -1 : 1);
  if (swapIdx < 0 || swapIdx >= COLUMN_ORDER.length) return;
  var t = COLUMN_ORDER[idx];
  COLUMN_ORDER[idx] = COLUMN_ORDER[swapIdx];
  COLUMN_ORDER[swapIdx] = t;
  saveColumnPrefs();
  renderColumnToggles();
  renderTable();
  refreshSortIndicators();
}

function syncHeaderOrder() {
  var headerRow = document.querySelector("thead tr");
  if (!headerRow) return;
  var byCol = {};
  var ths = headerRow.querySelectorAll("th[data-col]");
  for (var i = 0; i < ths.length; i++) {
    byCol[ths[i].getAttribute("data-col")] = ths[i];
  }
  for (var c = 0; c < COLUMN_ORDER.length; c++) {
    var key = COLUMN_ORDER[c];
    if (byCol[key]) headerRow.appendChild(byCol[key]);
  }
}

function applyColumnVisibility() {
  syncHeaderOrder();
  var ths = document.querySelectorAll("th[data-col]");
  for (var i = 0; i < ths.length; i++) {
    var col = ths[i].getAttribute("data-col");
    ths[i].setAttribute("data-hide", state.columns[col] ? "0" : "1");
  }
  var tds = document.querySelectorAll("td[data-col]");
  for (var j = 0; j < tds.length; j++) {
    var c = tds[j].getAttribute("data-col");
    tds[j].setAttribute("data-hide", state.columns[c] ? "0" : "1");
  }
}

function renderColumnToggles() {
  var labels = {
    severity:"Severity",source:"Source",trustTier:"Trust Tier",quickWin:"Quick Win",effortBenefit:"Effort/Benefit",workflowStatus:"Workflow Status",rule:"Rule",topLevelCategory:"Top Level",subCategory:"Sub Category",language:"Language",fileType:"File Type",location:"Location",confidence:"Confidence",recommendation:"Recommendation",snippet:"Snippet",patch:"Patch",title:"Title"
  };
  var html = "";
  for (var i = 0; i < COLUMN_ORDER.length; i++) {
    var c = COLUMN_ORDER[i];
    var checked = state.columns[c] ? "checked" : "";
    html += '<div class="toggle-item">'
      + '<label><input type="checkbox" data-col-toggle="' + c + '" ' + checked + '/> ' + esc(labels[c]) + '</label>'
      + '<button type="button" class="mini-btn" data-col-move="' + c + '" data-dir="-1" title="Move up">↑</button>'
      + '<button type="button" class="mini-btn" data-col-move="' + c + '" data-dir="1" title="Move down">↓</button>'
      + '</div>';
  }
  columnTogglesEl.innerHTML = html;
}

function totalPages() {
  if (state.shown.length === 0) return 1;
  return Math.ceil(state.shown.length / state.pageSize);
}

function clampCurrentPage() {
  var pages = totalPages();
  if (state.currentPage < 1) state.currentPage = 1;
  if (state.currentPage > pages) state.currentPage = pages;
}

function updatePager() {
  clampCurrentPage();
  var pages = totalPages();
  var start = (state.currentPage - 1) * state.pageSize;
  var end = Math.min(start + state.pageSize, state.shown.length);
  pageInfoEl.textContent = "Page " + state.currentPage + " / " + pages + " (" + (state.shown.length === 0 ? 0 : (start + 1)) + "-" + end + " of " + state.shown.length + ")";
  firstPageBtnEl.disabled = state.currentPage <= 1;
  prevPageBtnEl.disabled = state.currentPage <= 1;
  nextPageBtnEl.disabled = state.currentPage >= pages;
  lastPageBtnEl.disabled = state.currentPage >= pages;
}

function renderTable() {
  clampCurrentPage();
  var start = (state.currentPage - 1) * state.pageSize;
  var end = start + state.pageSize;
  state.pageRows = state.shown.slice(start, end);

  var html = "";
  for (var i = 0; i < state.pageRows.length; i++) html += rowTemplate(state.pageRows[i], i);
  rowsEl.innerHTML = html;
  if (state.pageRows.length > 0) {
    emptyEl.classList.add("hidden");
  } else {
    emptyEl.textContent = DEFAULT_EMPTY_TEXT;
    emptyEl.classList.remove("hidden");
  }
  applyColumnVisibility();
  updatePager();
}

function sortValue(f, col) {
  if (col === "severity") return sevOf(f);
  if (col === "source") return String(f.source || "unknown");
  if (col === "trustTier") return trustTierOf(f);
  if (col === "quickWin") return quickWinOf(f) ? "1" : "0";
  if (col === "effortBenefit") return effortOf(f) + "/" + benefitOf(f);
  if (col === "workflowStatus") return workflowStatusOf(f);
  if (col === "rule") return String(f.rule_id || "");
  if (col === "topLevelCategory") return topLevelOf(f);
  if (col === "subCategory") return subCategoryOf(f);
  if (col === "language") return String(f.language || "");
  if (col === "fileType") return String(f.file_type || "");
  if (col === "location") return String(f.file || "") + ":" + String(f.line || 1);
  if (col === "confidence") return String(get(f, ["llm_review", "confidence"], 0));
  if (col === "recommendation") return String(get(f, ["llm_review", "recommendation"], ""));
  if (col === "snippet") return String(f.snippet || f.match_text || "");
  if (col === "patch") return patchStatusOf(f);
  if (col === "title") return String(get(f, ["llm_review", "title"], f.rule_title || ""));
  return "";
}

function sortShown() {
  var col = state.sortCol || "severity";
  var dir = state.sortDir === "desc" ? -1 : 1;
  state.shown.sort(function (a, b) {
    if (col === "confidence") {
      var av = Number(get(a, ["llm_review", "confidence"], 0)) || 0;
      var bv = Number(get(b, ["llm_review", "confidence"], 0)) || 0;
      return dir * (av - bv);
    }
    if (col === "severity") {
      var rank = {"S1":1,"S2":2,"S3":3,"S4":4};
      return dir * ((rank[sevOf(a)] || 9) - (rank[sevOf(b)] || 9));
    }
    var sa = String(sortValue(a, col)).toLowerCase();
    var sb = String(sortValue(b, col)).toLowerCase();
    if (sa < sb) return -1 * dir;
    if (sa > sb) return 1 * dir;
    return 0;
  });
}

function refreshSortIndicators() {
  var headers = document.querySelectorAll("th[data-col]");
  for (var i = 0; i < headers.length; i++) {
    var c = headers[i].getAttribute("data-col");
    headers[i].setAttribute("data-sort", c === state.sortCol ? state.sortDir : "none");
  }
}

function includeByFilters(f) {
  var sev = sevOf(f);
  var source = String(f.source || "unknown").toLowerCase();
  var isIssue = isIssueOf(f);
  if (severityEl.value !== "ALL" && sev !== severityEl.value) return false;
  if (sourceEl.value !== "ALL" && source !== sourceEl.value) return false;
  if (ruleEl && ruleEl.value !== "ALL" && ruleOf(f) !== ruleEl.value) return false;
  if (trustTierEl && trustTierEl.value !== "ALL" && trustTierOf(f) !== trustTierEl.value) return false;
  if (safeAiRiskEl && safeAiRiskEl.value !== "ALL") {
    var risk = safeAiRiskOf(f);
    if (safeAiRiskEl.value === "ANY" && risk === "none") return false;
    if (safeAiRiskEl.value === "none" && risk !== "none") return false;
    if (safeAiRiskEl.value !== "ANY" && safeAiRiskEl.value !== "none" && risk !== safeAiRiskEl.value) return false;
  }
  if (validationEl && validationEl.value === "ISSUE" && !isIssue) return false;
  if (validationEl && validationEl.value === "FP" && isIssue) return false;
  if (workflowStatusEl && workflowStatusEl.value !== "ALL" && workflowStatusOf(f) !== workflowStatusEl.value) return false;

  var qf = quickWinEl.value;
  if (qf === "YES" && !quickWinOf(f)) return false;
  if (qf === "NO" && quickWinOf(f)) return false;
  var ff = fallbackEl.value;
  if (ff === "YES" && !fallbackOf(f)) return false;
  if (ff === "NO" && fallbackOf(f)) return false;
  if (topLevelEl && topLevelEl.value !== "ALL" && topLevelOf(f) !== topLevelEl.value) return false;
  if (subCategoryEl && subCategoryEl.value !== "ALL" && subCategoryOf(f) !== subCategoryEl.value) return false;

  var q = String(searchEl.value || "").trim().toLowerCase();
  if (!q) return true;
  var hay = [
    f.rule_id, f.rule_title, f.file, f.match_text, f.language, f.file_type,
    f.top_level_category, f.sub_category, f.trust_tier, trustTierOf(f), workflowStatusOf(f),
    get(f,["llm_review","title"],""), get(f,["llm_review","why"],""), get(f,["llm_review","recommendation"],"")
  ].join(" ").toLowerCase();
  return hay.indexOf(q) !== -1;
}

function applyFilters() {
  state.shown = state.all.filter(includeByFilters);
  sortShown();
  state.currentPage = 1;
  renderTable();
  refreshSortIndicators();
  setStatus("Showing " + state.shown.length + " / " + state.all.length + " findings");
}

function detailBlock(title, value, asPre) {
  if (asPre == null) asPre = false;
  if (value == null || value === "") return "";
  var cls = asPre ? "pre" : "text-auto";
  return '<section class="block"><h3>' + esc(title) + '</h3><div class="' + cls + '">' + esc(value) + '</div></section>';
}

function highlightDiff(text) {
  var lines = String(text || "").split(/\r?\n/);
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var cls = "";
    if (/^(\+\+\+|---|@@)/.test(line)) cls = "diff-hdr";
    else if (/^\+/.test(line)) cls = "diff-add";
    else if (/^-/.test(line)) cls = "diff-del";
    out.push(cls ? '<span class="' + cls + '">' + esc(line) + "</span>" : esc(line));
  }
  return out.join("\n");
}

function highlightCode(text, language) {
  var html = esc(String(text || ""));
  html = html.replace(/(\/\/.*)$/gm, '<span class="cm">$1</span>');
  html = html.replace(/(\"([^\"\\\\]|\\\\.)*\")/g, '<span class="str">$1</span>');
  html = html.replace(/\b(\d+)\b/g, '<span class="num">$1</span>');

  if (String(language || "").toLowerCase() === "csharp" || String(language || "").toLowerCase() === "cs") {
    var kws = [
      "public","private","protected","internal","class","interface","struct","enum","namespace","using",
      "async","await","return","if","else","for","foreach","while","switch","case","break","continue",
      "try","catch","finally","throw","new","var","void","bool","int","long","float","double","decimal",
      "string","object","Task","IActionResult","CancellationToken","null","true","false","this","base"
    ];
    var re = new RegExp("\\\\b(" + kws.map(escapeRegExp).join("|") + ")\\\\b", "g");
    html = html.replace(re, '<span class="kw">$1</span>');
  }
  return html;
}

function renderSnippetWithMatch(text, language, matchText) {
  var lines = String(text || "").split(/\r?\n/);
  var needle = String(matchText || "").trim();
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var raw = lines[i];
    var code = highlightCode(raw, language);
    if (needle && raw.indexOf(needle) !== -1) out.push('<span class="line-hit">' + code + "</span>");
    else out.push(code);
  }
  return out.join("\n");
}

function detailCodeBlock(title, text, mode, language, matchText) {
  if (text == null || text === "") return "";
  var rendered = mode === "diff" ? highlightDiff(text) : renderSnippetWithMatch(text, language, matchText);
  var blockType = mode === "diff" ? "patch-block" : "snippet-block";
  return '<section class="block"><h3>' + esc(title) + '</h3><pre class="pre code-block ' + blockType + '"><code>' + rendered + "</code></pre></section>";
}

function showDetails(f) {
  state.selectedFindingKey = String(f.finding_key || "");
  var lr = f.llm_review || {};
  var loc = (f.file || "unknown") + ":" + (f.line || 1);
  var ws = workflowStatusOf(f);
  var wsRec = state.reviewState[String(f.finding_key || "")] || {};
  var wsMeta = wsRec.updated_utc ? ("Updated: " + String(wsRec.updated_utc)) : "Not updated yet.";
  var content = "";
  content += detailBlock("Title", lr.title || f.rule_title || "-");
  content += detailBlock("Severity", sevOf(f));
  content += detailBlock("Rule", (f.rule_id || "-") + " (" + (f.source || "unknown") + ")");
  content += detailBlock("Trust Tier", trustTierOf(f));
  content += detailBlock("Grouping", topLevelOf(f) + " / " + subCategoryOf(f));
  content += detailBlock("Language / File Type", (f.language || "unknown") + " / " + (f.file_type || "unknown"));
  content += detailBlock("Effort vs Benefit", effortOf(f) + " / " + benefitOf(f));
  content += detailBlock("Quick Win", quickWinOf(f) ? "Yes" : "No");
  content += detailBlock("Location", loc);
  content += detailBlock("Why", lr.why || "-", false);
  content += detailBlock("Recommendation", lr.recommendation || "-", false);
  content += '<section class="block"><h3>Workflow Status</h3>'
    + '<div class="text-auto">'
    + '<select id="reviewStatusSelect">'
    + '<option value="todo"' + (ws === "todo" ? " selected" : "") + '>To Do</option>'
    + '<option value="in_progress"' + (ws === "in_progress" ? " selected" : "") + '>In Progress</option>'
    + '<option value="verified"' + (ws === "verified" ? " selected" : "") + '>Verified</option>'
    + '<option value="resolved"' + (ws === "resolved" ? " selected" : "") + '>Resolved</option>'
    + '</select> '
    + '<button id="saveReviewStatusBtn" class="btn btn-lite" type="button">Save</button>'
    + '<div class="mini" id="reviewStatusMeta">' + esc(wsMeta) + '</div>'
    + '</div></section>';
  if (lr.changed_lines_reason) content += detailBlock("Patch Change Reason", String(lr.changed_lines_reason), false);
  content += detailBlock("Patch Status", patchStatusOf(f));
  if (state.viewMode === "safe_ai") {
    var risk = get(f, ["ai_policy", "risk"], "low");
    content += detailBlock("Safe AI Risk", String(risk));
    content += detailBlock("External Boundary", get(f, ["ai_policy", "external_boundary"], false) ? "Yes" : "No");
    content += detailBlock("Policy Mode", get(f, ["ai_policy", "mode"], "dry_run"));
  }
  content += detailBlock("Patch Safety", String(lr.patch_attention || "unavailable"));
  if (lr.patch_attention_reason) content += detailBlock("Patch Safety Reason", String(lr.patch_attention_reason));
  content += detailCodeBlock("Code Snippet", f.snippet || f.match_text || "", "code", f.language || "unknown", f.match_text || "");
  if (lr.patch && String(lr.patch).toLowerCase() !== "unknown") {
    content += detailCodeBlock("Suggested Patch", lr.patch, "diff", "diff", "");
  } else {
    content += detailBlock("Suggested Patch", "Patch unavailable for this finding.");
  }
  detailsBodyEl.innerHTML = content;
  var saveBtn = document.getElementById("saveReviewStatusBtn");
  if (saveBtn) {
    saveBtn.addEventListener("click", function () {
      var sel = document.getElementById("reviewStatusSelect");
      var nextStatus = sel ? sel.value : "todo";
      saveWorkflowStatus(f, nextStatus);
    });
  }
}

function showError(err) {
  rowsEl.innerHTML = "";
  emptyEl.classList.remove("hidden");
  emptyEl.textContent = err && err.message ? err.message : "Failed to load findings.";
  setStatus("Error: " + emptyEl.textContent);
}

function loadReviewState() {
  return fetch("/api/review-state", { cache: "no-store" })
    .then(function (r) { if (!r.ok) throw new Error("Failed to load review state"); return r.json(); })
    .then(function (payload) {
      var items = payload && payload.items && typeof payload.items === "object" ? payload.items : {};
      state.reviewState = items;
    });
}

function saveWorkflowStatus(finding, status, refreshDetails) {
  if (refreshDetails == null) refreshDetails = true;
  if (!finding || !finding.finding_key) return;
  var body = {
    finding_key: String(finding.finding_key),
    status: String(status || "todo"),
    file_name: String(state.currentFile || "")
  };
  setStatus("Saving workflow status...");
  fetch("/api/review-state", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
    .then(function (r) { if (!r.ok) throw new Error("Failed to save workflow status"); return r.json(); })
    .then(function (payload) {
      if (payload && payload.finding_key && payload.entry) {
        state.reviewState[payload.finding_key] = payload.entry;
      }
      applyFilters();
      if (refreshDetails) showDetails(finding);
      setStatus("Workflow status saved.");
    })
    .catch(showError);
}

function loadFileOptions() {
  setStatus("Loading findings file list...");
  return fetch("/api/findings-files", { cache: "no-store" })
    .then(function (r) { if (!r.ok) throw new Error("Failed to list findings files"); return r.json(); })
    .then(function (payload) {
      var files = payload.files || [];
      var html = "";
      for (var i = 0; i < files.length; i++) {
        html += '<option value="' + esc(files[i].name) + '">' + esc(files[i].name) + '</option>';
      }
      filePickerEl.innerHTML = html || '<option value="findings.json">findings.json</option>';
      if (files.length > 0) {
        var names = files.map(function (f) { return f.name; });
        if (!state.currentFile || names.indexOf(state.currentFile) === -1) {
          state.currentFile = files[0].name;
        } else if (state.currentFile.indexOf("uploaded__") === 0 && names.indexOf("findings.json") !== -1) {
          // Prefer latest canonical pointer over stale uploaded file selections.
          state.currentFile = "findings.json";
        }
        filePickerEl.value = state.currentFile;
      } else {
        state.currentFile = "findings.json";
        filePickerEl.value = "findings.json";
      }
      setStatus("Loaded " + files.length + " findings file option(s)");
    });
}

function loadData(fileName, allowFallback) {
  if (allowFallback == null) allowFallback = true;
  var requested = fileName || filePickerEl.value || state.currentFile || "findings.json";
  state.currentFile = requested;
  filePickerEl.value = requested;
  var token = ++state.loadToken;
  setStatus("Loading " + requested + " ...");
  return fetch("/api/findings-file?name=" + encodeURIComponent(requested), { cache: "no-store" })
    .then(function (res) {
      if (!res.ok) {
        if (res.status === 404 && allowFallback) {
          return loadFileOptions().then(function () {
            var fallback = filePickerEl.value || state.currentFile || "findings.json";
            if (fallback && fallback !== requested) return loadData(fallback, false);
            throw new Error("Failed to load " + requested + " (404)");
          });
        }
        throw new Error("Failed to load " + requested + " (" + res.status + ")");
      }
      return res.json();
    })
    .then(function (payload) {
      if (token !== state.loadToken) return;
      var json = payload.data || {};
      if (isSafeAiPayload(json)) {
        setViewMode("safe_ai");
        json = normalizeSafeAiPayload(json);
      } else if (state.viewMode !== "safe_ai") {
        setViewMode("findings");
      }
      var findings = json.findings || [];
      // Keep all reviewed findings visible in UI, including non-issue/demoted rows.
      // Summary cards still distinguish reviewed vs confirmed counts.
      state.all = findings.slice();
      state.currentFile = payload.name || requested;
      if (filePickerEl) filePickerEl.value = state.currentFile;
      emptyEl.textContent = DEFAULT_EMPTY_TEXT;
      refreshCategoryFilters();
      renderCards(json.summary || {});
      applyFilters();
      setStatus("Loaded " + state.all.length + " finding(s) from " + state.currentFile);
    });
}

function uploadFile(file) {
  if (!file) return Promise.resolve();
  setStatus("Uploading " + file.name + " ...");
  var form = new FormData();
  form.append("file", file, file.name);
  return fetch("/api/upload-findings", { method: "POST", body: form })
    .then(function (res) { if (!res.ok) throw new Error("Upload failed (" + res.status + ")"); return res.json(); })
    .then(function (payload) {
      setStatus("Upload saved as " + payload.saved_as);
      return loadFileOptions().then(function () {
        filePickerEl.value = payload.saved_as;
        return loadData(payload.saved_as);
      });
    });
}

document.getElementById("reloadBtn").addEventListener("click", function () {
  loadReviewState()
    .then(function () { return loadFileOptions(); })
    .then(function () {
      // Reload should prefer latest canonical pointers for operational runs.
      if (state.viewMode === "safe_ai") return loadData("safe_ai_risk.json");
      return loadData("findings.json");
    })
    .catch(showError);
});

if (tabFindingsEl) {
  tabFindingsEl.addEventListener("click", function () {
    setViewMode("findings");
    loadData(state.currentFile).catch(showError);
  });
}
if (tabSafeAiEl) {
  tabSafeAiEl.addEventListener("click", function () {
    setViewMode("safe_ai");
    var current = String(filePickerEl.value || state.currentFile || "");
    if (current.indexOf("safe_ai_risk") !== -1) {
      loadData(current).catch(showError);
      return;
    }
    loadFileOptions()
      .then(function () {
        var opts = filePickerEl.options || [];
        for (var i = 0; i < opts.length; i++) {
          var name = String(opts[i].value || "");
          if (name.indexOf("safe_ai_risk") !== -1) {
            filePickerEl.value = name;
            return loadData(name);
          }
        }
        throw new Error("No safe_ai_risk file found. Run scan with --safe-ai-dry-run first.");
      })
      .catch(showError);
  });
}

filePickerEl.addEventListener("change", function () { loadData(filePickerEl.value).catch(showError); });
uploadEl.addEventListener("change", function () { uploadFile(uploadEl.files[0]).catch(showError); });
severityEl.addEventListener("change", applyFilters);
sourceEl.addEventListener("change", applyFilters);
if (ruleEl) ruleEl.addEventListener("change", applyFilters);
if (trustTierEl) trustTierEl.addEventListener("change", applyFilters);
if (safeAiRiskEl) safeAiRiskEl.addEventListener("change", applyFilters);
if (validationEl) validationEl.addEventListener("change", applyFilters);
if (workflowStatusEl) workflowStatusEl.addEventListener("change", applyFilters);
quickWinEl.addEventListener("change", applyFilters);
fallbackEl.addEventListener("change", applyFilters);
topLevelEl.addEventListener("change", function () {
  refreshCategoryFilters();
  applyFilters();
});
subCategoryEl.addEventListener("change", applyFilters);
searchEl.addEventListener("input", applyFilters);

columnTogglesEl.addEventListener("change", function (e) {
  var col = e.target.getAttribute("data-col-toggle");
  if (!col) return;
  state.columns[col] = Boolean(e.target.checked);
  saveColumnPrefs();
  applyColumnVisibility();
});
columnTogglesEl.addEventListener("click", function (e) {
  var btn = e.target.closest("button[data-col-move]");
  if (!btn) return;
  var col = btn.getAttribute("data-col-move");
  var dir = Number(btn.getAttribute("data-dir") || "0");
  if (!col || !dir) return;
  moveColumn(col, dir);
});

rowsEl.addEventListener("click", function (e) {
  if (e.target && e.target.closest(".row-workflow-select")) return;
  var tr = e.target.closest("tr[data-i]");
  if (!tr) return;
  var i = Number(tr.getAttribute("data-i"));
  showDetails(state.pageRows[i]);
});

rowsEl.addEventListener("change", function (e) {
  var sel = e.target && e.target.closest(".row-workflow-select");
  if (!sel) return;
  var fk = String(sel.getAttribute("data-fk") || "");
  if (!fk) return;
  var finding = null;
  for (var i = 0; i < state.pageRows.length; i++) {
    if (String(state.pageRows[i].finding_key || "") === fk) {
      finding = state.pageRows[i];
      break;
    }
  }
  if (!finding) return;
  saveWorkflowStatus(finding, String(sel.value || "todo"), false);
});

document.querySelector("thead").addEventListener("click", function (e) {
  var th = e.target.closest("th[data-col]");
  if (!th) return;
  var col = th.getAttribute("data-col");
  if (!col) return;
  if (state.sortCol === col) state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
  else { state.sortCol = col; state.sortDir = "asc"; }
  sortShown();
  renderTable();
  refreshSortIndicators();
});

pageSizeEl.addEventListener("change", function () {
  var size = Number(pageSizeEl.value || "20");
  if (!size || size < 1) size = 20;
  state.pageSize = size;
  state.currentPage = 1;
  renderTable();
});

firstPageBtnEl.addEventListener("click", function () {
  state.currentPage = 1;
  renderTable();
});
prevPageBtnEl.addEventListener("click", function () {
  state.currentPage = Math.max(1, state.currentPage - 1);
  renderTable();
});
nextPageBtnEl.addEventListener("click", function () {
  state.currentPage = Math.min(totalPages(), state.currentPage + 1);
  renderTable();
});
lastPageBtnEl.addEventListener("click", function () {
  state.currentPage = totalPages();
  renderTable();
});

function applyDetailsWidth(pct) {
  var p = Number(pct);
  if (!p || isNaN(p)) return;
  if (p < 25) p = 25;
  if (p > 60) p = 60;
  document.documentElement.style.setProperty("--details-width", p + "%");
  try { localStorage.setItem("nfr_details_width", String(p)); } catch (e) {}
}

function applySnippetHeight(px) {
  var h = Number(px);
  if (!h || isNaN(h)) return;
  if (h < 180) h = 180;
  if (h > 900) h = 900;
  document.documentElement.style.setProperty("--snippet-max-height", h + "px");
  if (snippetHeightEl) snippetHeightEl.value = String(h);
  if (snippetHeightValueEl) snippetHeightValueEl.textContent = h + "px";
  try { localStorage.setItem("nfr_snippet_height", String(h)); } catch (e) {}
}

function applyPatchHeight(px) {
  var h = Number(px);
  if (!h || isNaN(h)) return;
  if (h < 180) h = 180;
  if (h > 900) h = 900;
  document.documentElement.style.setProperty("--patch-max-height", h + "px");
  if (patchHeightEl) patchHeightEl.value = String(h);
  if (patchHeightValueEl) patchHeightValueEl.textContent = h + "px";
  try { localStorage.setItem("nfr_patch_height", String(h)); } catch (e) {}
}

function initSplitter() {
  if (!splitterEl || !splitEl) return;
  try {
    var stored = localStorage.getItem("nfr_details_width");
    if (stored) applyDetailsWidth(stored);
  } catch (e) {}

  var dragging = false;
  function onMove(ev) {
    if (!dragging || window.innerWidth <= 980) return;
    var rect = splitEl.getBoundingClientRect();
    var detailsPct = ((rect.right - ev.clientX) / rect.width) * 100;
    applyDetailsWidth(detailsPct);
  }
  function onUp() { dragging = false; document.body.style.userSelect = ""; }

  splitterEl.addEventListener("mousedown", function () {
    if (window.innerWidth <= 980) return;
    dragging = true;
    document.body.style.userSelect = "none";
  });
  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
}

function initSnippetHeight() {
  var stored = null;
  try { stored = localStorage.getItem("nfr_snippet_height"); } catch (e) {}
  if (stored) applySnippetHeight(stored);
  else applySnippetHeight(snippetHeightEl ? snippetHeightEl.value : 280);

  if (snippetHeightEl) {
    snippetHeightEl.addEventListener("input", function () {
      applySnippetHeight(snippetHeightEl.value);
    });
  }
}

function initPatchHeight() {
  var stored = null;
  try { stored = localStorage.getItem("nfr_patch_height"); } catch (e) {}
  if (stored) applyPatchHeight(stored);
  else applyPatchHeight(patchHeightEl ? patchHeightEl.value : 280);

  if (patchHeightEl) {
    patchHeightEl.addEventListener("input", function () {
      applyPatchHeight(patchHeightEl.value);
    });
  }
}

function initFiltersPanel() {
  if (!toggleFiltersPanelBtnEl || !filtersPanelBodyEl) return;
  var isOpen = false;
  try { isOpen = localStorage.getItem("nfr_filters_panel_open") === "1"; } catch (e) {}
  function apply() {
    filtersPanelBodyEl.classList.toggle("hidden", !isOpen);
    toggleFiltersPanelBtnEl.setAttribute("aria-expanded", isOpen ? "true" : "false");
    toggleFiltersPanelBtnEl.textContent = isOpen ? "Hide Filters" : "Show Filters";
  }
  apply();
  toggleFiltersPanelBtnEl.addEventListener("click", function () {
    isOpen = !isOpen;
    apply();
    try { localStorage.setItem("nfr_filters_panel_open", isOpen ? "1" : "0"); } catch (e) {}
  });
}

loadColumnPrefs();
renderColumnToggles();
initFiltersPanel();
initSplitter();
initSnippetHeight();
initPatchHeight();
loadReviewState()
  .then(function () { return loadFileOptions(); })
  .then(function () { return loadData(state.currentFile); })
  .catch(showError);
