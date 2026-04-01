/**
 * TAJ-CTF-Engine · terminal.js
 * Terminal output helpers
 */

function termLine(text, cls = "term-line") {
  const t   = document.getElementById("terminal");
  const div = document.createElement("div");
  div.className   = `term-line ${cls}`;
  div.textContent = text;
  t.appendChild(div);
  t.scrollTop = t.scrollHeight;
}

function termInfo(text)    { termLine(text, "term-info");    }
function termWarn(text)    { termLine(text, "term-warn");    }
function termError(text)   { termLine(text, "term-error");   }
function termSuccess(text) { termLine(text, "term-success"); }

function clearTerminal() {
  const t = document.getElementById("terminal");
  t.innerHTML = `
    <div class="term-line term-dim">
      ${"─".repeat(62)}<br/>Terminal cleared · ${new Date().toISOString()}
    </div>
    <div class="term-line term-prompt">root@taj-ctf:~# <span class="cursor">█</span></div>
  `;
}
