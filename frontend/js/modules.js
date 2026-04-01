/**
 * TAJ-CTF-Engine · modules.js
 * Module chip UI + status grid
 */

const MODULE_META = [
  { id: "sqli",  label: "SQLi",   icon: "💉", desc: "SQL Injection" },
  { id: "xss",   label: "XSS",    icon: "🕸", desc: "Cross-Site Scripting" },
  { id: "ssti",  label: "SSTI",   icon: "🐍", desc: "Template Injection" },
  { id: "lfi",   label: "LFI",    icon: "📂", desc: "Local File Inclusion" },
  { id: "cmdi",  label: "CMDi",   icon: "💻", desc: "Command Injection" },
  { id: "jwt",   label: "JWT",    icon: "🔑", desc: "JWT Attacks" },
  { id: "ssrf",  label: "SSRF",   icon: "🔄", desc: "Server-Side Req Forgery" },
  { id: "idor",  label: "IDOR",   icon: "🔓", desc: "Broken Object Auth" },
  { id: "xxe",   label: "XXE",    icon: "📋", desc: "XML External Entity" },
  { id: "nosql", label: "NoSQL",  icon: "🍃", desc: "NoSQL Injection" },
];

let selectedModules = new Set(MODULE_META.map(m => m.id));

function initModules() {
  const grid = document.getElementById("module-grid");
  grid.innerHTML = "";
  MODULE_META.forEach(m => {
    const chip = document.createElement("div");
    chip.className   = "module-chip active";
    chip.id          = `chip-${m.id}`;
    chip.title       = m.desc;
    chip.innerHTML   = `<span class="chip-dot"></span>
      <span class="chip-icon">${m.icon}</span>
      <span>${m.label}</span>`;
    chip.onclick     = () => toggleModule(m.id);
    grid.appendChild(chip);
  });

  document.getElementById("btn-select-all").onclick = () => {
    const allSelected = selectedModules.size === MODULE_META.length;
    if (allSelected) {
      selectedModules.clear();
      MODULE_META.forEach(m => document.getElementById(`chip-${m.id}`)
                               .classList.remove("active"));
    } else {
      MODULE_META.forEach(m => {
        selectedModules.add(m.id);
        document.getElementById(`chip-${m.id}`).classList.add("active");
      });
    }
  };
}

function toggleModule(id) {
  const chip = document.getElementById(`chip-${id}`);
  if (selectedModules.has(id)) {
    selectedModules.delete(id);
    chip.classList.remove("active");
  } else {
    selectedModules.add(id);
    chip.classList.add("active");
  }
}

function getSelectedModules() {
  return [...selectedModules];
}

function initModuleStatusGrid() {
  const grid = document.getElementById("module-status-grid");
  grid.innerHTML = "";
  MODULE_META.forEach(m => {
    const row = document.createElement("div");
    row.className = "mod-status";
    row.id        = `modstat-${m.id}`;
    row.innerHTML = `<div class="mod-dot"></div>
      <span class="mod-name">${m.icon} ${m.label}</span>
      <span class="mod-state-label" id="modlbl-${m.id}">IDLE</span>`;
    grid.appendChild(row);
  });
}

function setModuleState(id, state) {
  const row = document.getElementById(`modstat-${id}`);
  const lbl = document.getElementById(`modlbl-${id}`);
  if (!row || !lbl) return;
  row.className  = `mod-status ${state}`;
  const labels   = { running: "RUNNING", vuln: "VULNERABLE",
                     safe: "CLEAN", error: "ERROR", idle: "IDLE" };
  lbl.textContent = labels[state] || state.toUpperCase();
}
