/**
 * TAJ-CTF-Engine v2.0 · app.js
 * Aggressive CTF automation frontend
 */

const AppState = {
  scanning: false,
  results:  null,
  flags:    [],
  vulns:    [],
};

const ALL_MODULES = [
  { id: "dirbrute",      label: "DIR BRUTE",   icon: "🗂" },
  { id: "sqli",          label: "SQL INJ",     icon: "💉" },
  { id: "ssti",          label: "SSTI",        icon: "🔧" },
  { id: "cmdi",          label: "CMD INJ",     icon: "💻" },
  { id: "lfi",           label: "LFI/PATH",    icon: "📂" },
  { id: "xss",           label: "XSS",         icon: "⚡" },
  { id: "headers",       label: "HEADERS",     icon: "🔑" },
  { id: "open_redirect", label: "REDIRECT",    icon: "↪" },
  { id: "ssrf",          label: "SSRF",        icon: "🌐" },
  { id: "jwt",           label: "JWT",         icon: "🎫" },
  { id: "nosql",         label: "NOSQL",       icon: "🍃" },
  { id: "idor",          label: "IDOR",        icon: "🔓" },
  { id: "xxe",           label: "XXE",         icon: "📄" },
  { id: "typejuggle",    label: "TYPE JUG",    icon: "🎭" },
];

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  buildModuleGrid();
  buildModuleStatusGrid();
  startClock();
  const urlInput = document.getElementById("target-url");
  urlInput.addEventListener("input", e => validateURL(e.target.value));
  urlInput.addEventListener("keydown", e => {
    if (e.key === "Enter" && !AppState.scanning) launchScan();
  });
  urlInput.focus();
});

function startClock() {
  const el = document.getElementById("clock");
  setInterval(() => {
    el.textContent = new Date().toISOString().replace("T"," ").slice(0,19) + " UTC";
  }, 1000);
}

function validateURL(val) {
  const hint = document.getElementById("url-hint");
  if (!val) { hint.textContent = ""; return; }
  try {
    new URL(val.startsWith("http") ? val : "https://"+val);
    hint.style.color = "var(--accent3)";
    hint.textContent = "✓ Valid URL — press ENTER or LAUNCH ATTACK";
  } catch {
    hint.style.color = "var(--accent2)";
    hint.textContent = "⚠ Invalid URL format";
  }
}

function buildModuleGrid() {
  const grid = document.getElementById("module-grid");
  grid.innerHTML = "";
  ALL_MODULES.forEach(m => {
    const btn = document.createElement("div");
    btn.className = "mod-chip active";
    btn.id = `mod-${m.id}`;
    btn.innerHTML = `<span class="mod-icon">${m.icon}</span><span>${m.label}</span>`;
    btn.onclick = () => btn.classList.toggle("active");
    grid.appendChild(btn);
  });
  updateSelectAllLabel();
}

function buildModuleStatusGrid() {
  const grid = document.getElementById("module-status-grid");
  grid.innerHTML = "";
  ALL_MODULES.forEach(m => {
    const row = document.createElement("div");
    row.className = "ms-row";
    row.id = `ms-${m.id}`;
    row.innerHTML = `<span class="ms-icon">${m.icon}</span>
      <span class="ms-label">${m.label}</span>
      <span class="ms-state ms-idle" id="ms-state-${m.id}">IDLE</span>`;
    grid.appendChild(row);
  });
}

function setModuleState(mod, state) {
  const el = document.getElementById(`ms-state-${mod}`);
  if (!el) return;
  el.className = `ms-state ms-${state}`;
  el.textContent = state.toUpperCase();
}

function toggleSelectAll() {
  const chips = document.querySelectorAll(".mod-chip");
  const allActive = [...chips].every(c => c.classList.contains("active"));
  chips.forEach(c => allActive ? c.classList.remove("active") : c.classList.add("active"));
  updateSelectAllLabel();
}

function updateSelectAllLabel() {
  const chips = document.querySelectorAll(".mod-chip");
  const active = [...chips].filter(c => c.classList.contains("active")).length;
  document.getElementById("btn-select-all").textContent =
    active === chips.length ? "DESELECT ALL" : "SELECT ALL";
}

function toggleOptions() {
  const grid  = document.getElementById("options-grid");
  const arrow = document.getElementById("opt-arrow");
  const shown = grid.style.display !== "none";
  grid.style.display = shown ? "none" : "grid";
  arrow.textContent  = shown ? "▶" : "▼";
}

// ── URL / Options ──────────────────────────────────────────────────────────────

function getTargetURL() {
  const v = document.getElementById("target-url").value.trim();
  if (!v) return null;
  return v.startsWith("http") ? v : "https://"+v;
}

function getOptions() {
  const opts = { timeout: parseInt(document.getElementById("opt-timeout").value)||10 };
  const cookies = document.getElementById("opt-cookies").value.trim();
  const auth    = document.getElementById("opt-auth").value.trim();
  const proxy   = document.getElementById("opt-proxy").value.trim();
  if (cookies) {
    const c = {};
    cookies.split(";").forEach(p => {
      const [k,v] = p.split("=").map(s=>s.trim());
      if (k) c[k]=v||"";
    });
    opts.cookies = c;
  }
  if (auth)  opts.headers = { Authorization: auth };
  if (proxy) opts.proxy = proxy;
  return opts;
}

function getSelectedModules() {
  return ALL_MODULES
    .filter(m => document.getElementById(`mod-${m.id}`)?.classList.contains("active"))
    .map(m => m.id);
}

// ── Quick Flag ─────────────────────────────────────────────────────────────────

async function quickFlagScan() {
  const url = getTargetURL();
  if (!url) { termError("⚠ Enter a target URL first."); return; }
  termLine(`\n⚡ QUICK FLAG HUNT → ${url}`, "term-warn");
  try {
    const data = await fetch("/api/quick_flag", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, options: getOptions() })
    }).then(r => r.json());

    if (data.flags && data.flags.length) {
      data.flags.forEach(f => {
        addFlagToUI(f);
        termLine(`  🚩 FLAG: ${f}`, "term-flag");
        triggerFlagModal(f);
      });
      termLine(`  ✓ ${data.flags.length} flag(s) found!`, "term-success");
    } else {
      termLine("  [-] No flags in quick scan.", "term-dim");
    }
    if (data.findings) {
      data.findings.forEach(f =>
        termLine(`     via: ${f.source}`, "term-dim")
      );
    }
  } catch(e) {
    termError(`  [!] Quick scan error: ${e.message}`);
  }
}

// ── Main Scan ──────────────────────────────────────────────────────────────────

async function launchScan() {
  if (AppState.scanning) return;
  const url     = getTargetURL();
  const modules = getSelectedModules();
  if (!url)            { termError("⚠ No target URL."); return; }
  if (!modules.length) { termError("⚠ No modules selected."); return; }

  AppState.scanning = true;
  AppState.flags = []; AppState.vulns = [];
  clearResults();

  const btn = document.getElementById("btn-launch");
  btn.classList.add("scanning");
  btn.querySelector(".btn-text").textContent = "◈ SCANNING...";
  document.getElementById("progress-wrap").style.display = "block";
  document.getElementById("stat-status").textContent = "SCANNING";
  setProgress(0, "Initializing...");

  termLine("\n" + "═".repeat(62), "term-dim");
  termLine(`[*] TARGET  : ${url}`, "term-info");
  termLine(`[*] MODULES : ${modules.join(", ")}`, "term-info");
  termLine(`[*] CRAWL   : ${document.getElementById("opt-crawl").checked ? "ON" : "OFF"}`, "term-info");
  termLine(`[*] START   : ${new Date().toISOString()}`, "term-info");
  termLine("─".repeat(62), "term-dim");

  const total = modules.length;
  for (let i = 0; i < modules.length; i++) {
    const mod = modules[i];
    setProgress(Math.round((i / total) * 90), `Running ${mod.toUpperCase()}...`);
    setModuleState(mod, "running");
    termLine(`\n[+] MODULE: ${mod.toUpperCase()}`, "term-warn");
    await runModule(url, mod, getOptions());
    setProgress(Math.round(((i+1) / total) * 90), `${mod.toUpperCase()} done`);
  }

  setProgress(100, "Scan complete.");
  termLine("\n" + "═".repeat(62), "term-dim");
  const flagMsg = AppState.flags.length > 0
    ? `🚩 ${AppState.flags.length} FLAG(S) CAPTURED!`
    : "No flags found.";
  termLine(`[✓] Scan complete. ${flagMsg} | ${AppState.vulns.length} vuln(s).`,
           AppState.flags.length ? "term-flag" : "term-success");
  termLine(`[*] END: ${new Date().toISOString()}`, "term-dim");

  document.getElementById("stat-status").textContent =
    AppState.flags.length ? `🚩 ${AppState.flags.length} FLAG(S)!` : "DONE";
  document.getElementById("btn-export").disabled = false;

  AppState.scanning = false;
  btn.classList.remove("scanning");
  btn.querySelector(".btn-text").textContent = "◈ LAUNCH ATTACK";
}

async function runModule(url, module, options) {
  const crawl = document.getElementById("opt-crawl").checked;
  try {
    const data = await fetch("/api/scan_module", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, module, options, crawl })
    }).then(r => r.json());

    // ── Flags ────────────────────────────────────────────────────────
    const allFlags = [...(data.flags||[]), ...(data.result?.flags||[])];
    [...new Set(allFlags)].forEach(f => {
      if (!AppState.flags.includes(f)) {
        AppState.flags.push(f);
        addFlagToUI(f);
        termLine(`\n  🚩 FLAG FOUND: ${f}`, "term-flag");
        triggerFlagModal(f);
      }
    });

    // ── Logs ─────────────────────────────────────────────────────────
    const result = data.result || {};
    (result.logs||[]).forEach(l => {
      const cls = l.includes("FLAG") || l.includes("🚩") ? "term-flag"
                : l.includes("[!]") ? "term-error"
                : l.includes("Confirmed") || l.includes("captured") ? "term-success"
                : l.includes("HIT") || l.includes("Found") ? "term-success"
                : l.includes("Output:") ? "term-info"
                : "term-dim";
      termLine(`  ${l}`, cls);
    });

    // ── Vulns ─────────────────────────────────────────────────────────
    const vulns = result.vulnerabilities || [];
    if (vulns.length > 0) {
      vulns.forEach(v => {
        AppState.vulns.push({ module, ...v });
        addVulnToUI(module, v);
        termLine(`  ⚡ VULN [${module.toUpperCase()}] type=${v.type}`, "term-vuln");
        if (v.payload) termLine(`     payload: ${String(v.payload).slice(0,100)}`, "term-dim");
        if (v.url)     termLine(`     url: ${v.url}`, "term-dim");
      });
      setModuleState(module, "vuln");
    } else {
      setModuleState(module, result.status === "unreachable" ? "error" : "safe");
      if (!allFlags.length) termLine(`  [-] Nothing found.`, "term-dim");
    }

    // ── Crawl stats (shown once on first module with crawl data) ───────
    if (data.crawl_summary && data.crawl_summary.endpoints_found) {
      const cs = data.crawl_summary;
      document.getElementById("crawl-stats").style.display = "block";
      document.getElementById("cs-ep").textContent    = cs.endpoints_found;
      document.getElementById("cs-forms").textContent = cs.forms_found;
      document.getElementById("cs-secrets").textContent = (cs.js_secrets||[]).length;
      if (cs.js_secrets && cs.js_secrets.length) {
        termLine(`  🔍 JS SECRET: ${cs.js_secrets[0].value?.slice(0,60)}`, "term-warn");
      }
    }

  } catch (err) {
    termError(`  [!] ${module} error: ${err.message}`);
    setModuleState(module, "error");
  }
}

// ── UI Helpers ────────────────────────────────────────────────────────────────

function clearResults() {
  document.getElementById("flags-box").innerHTML = '<div class="empty-state">Scanning...</div>';
  document.getElementById("vulns-box").innerHTML = '<div class="empty-state">Scanning...</div>';
  document.getElementById("flag-count").textContent = "0";
  document.getElementById("vuln-count").textContent = "0";
  document.getElementById("crawl-stats").style.display = "none";
  buildModuleStatusGrid();
}

function addFlagToUI(flag) {
  const box = document.getElementById("flags-box");
  if (box.querySelector(".empty-state")) box.innerHTML = "";
  const div = document.createElement("div");
  div.className = "flag-item";
  div.innerHTML = `<span class="flag-emoji">🚩</span><span class="flag-text">${escHtml(flag)}</span>
    <span class="flag-copy" title="Copy">📋</span>`;
  div.querySelector(".flag-copy").onclick = (e) => {
    navigator.clipboard.writeText(flag);
    e.target.textContent = "✓";
    setTimeout(() => e.target.textContent = "📋", 1500);
  };
  box.prepend(div);
  document.getElementById("flag-count").textContent =
    parseInt(document.getElementById("flag-count").textContent) + 1;
}

function addVulnToUI(module, vuln) {
  const box = document.getElementById("vulns-box");
  if (box.querySelector(".empty-state")) box.innerHTML = "";
  const div = document.createElement("div");
  div.className = "vuln-item";
  const detail = vuln.payload ? `payload: ${String(vuln.payload).slice(0,60)}`
               : vuln.url     ? `url: ${vuln.url.slice(0,60)}`
               : vuln.note || vuln.evidence || "";
  div.innerHTML = `<div class="vuln-type">[${module.toUpperCase()}] ${vuln.type}</div>
    <div class="vuln-detail">${escHtml(detail)}</div>`;
  box.appendChild(div);
  document.getElementById("vuln-count").textContent =
    parseInt(document.getElementById("vuln-count").textContent) + 1;
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── Terminal ──────────────────────────────────────────────────────────────────

function termLine(msg, cls="term-dim") {
  const term = document.getElementById("terminal");
  const cursor = term.querySelector(".cursor");
  if (cursor) cursor.parentElement.remove();
  const div = document.createElement("div");
  div.className = `term-line ${cls}`;
  div.textContent = msg;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
  // Restore cursor
  const cp = document.createElement("div");
  cp.className = "term-line term-prompt";
  cp.innerHTML = 'root@taj-ctf:~# <span class="cursor">█</span>';
  term.appendChild(cp);
}

function termInfo(msg)  { termLine(msg, "term-info"); }
function termError(msg) { termLine(msg, "term-error"); }

function clearTerminal() {
  document.getElementById("terminal").innerHTML =
    '<div class="term-line term-prompt">root@taj-ctf:~# <span class="cursor">█</span></div>';
}

// ── Flag Modal ─────────────────────────────────────────────────────────────────

let _lastFlag = "";
function triggerFlagModal(flag) {
  _lastFlag = flag;
  document.getElementById("flag-modal-text").textContent = flag;
  document.getElementById("flag-modal").style.display = "flex";
  // Auto-dismiss after 6 seconds
  setTimeout(closeModal, 6000);
}
function closeModal() {
  document.getElementById("flag-modal").style.display = "none";
}
function copyModalFlag() {
  navigator.clipboard.writeText(_lastFlag);
  const btn = document.getElementById("btn-copy-modal");
  btn.textContent = "✓ COPIED!";
  setTimeout(() => btn.textContent = "📋 COPY FLAG", 1500);
}
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeModal();
});

// ── Export ─────────────────────────────────────────────────────────────────────

function setProgress(pct, label) {
  document.getElementById("progress-fill").style.width = pct + "%";
  document.getElementById("progress-label").textContent = label;
}

function exportResults() {
  const report = {
    timestamp: new Date().toISOString(),
    target: getTargetURL(),
    flags: AppState.flags,
    vulns: AppState.vulns,
    tool: "TAJ-CTF-Engine v2.0 by Taj | CSYClub IIITK",
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = `taj_ctf_report_${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(url);
}

function exportLogs() {
  const logs = document.getElementById("terminal").innerText;
  const blob = new Blob([logs], { type: "text/plain" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = `taj_ctf_logs_${Date.now()}.txt`;
  a.click(); URL.revokeObjectURL(url);
}
