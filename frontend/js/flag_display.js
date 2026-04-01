/**
 * TAJ-CTF-Engine · flag_display.js
 * Flag celebration modal + copy helper
 */

let _flagModalQueue = [];
let _flagModalOpen  = false;

function triggerFlagModal(flag) {
  _flagModalQueue.push(flag);
  if (!_flagModalOpen) _showNextFlag();
}

function _showNextFlag() {
  if (_flagModalQueue.length === 0) { _flagModalOpen = false; return; }
  _flagModalOpen = true;
  const flag = _flagModalQueue.shift();
  document.getElementById("modal-flag-text").textContent = flag;
  document.getElementById("flag-modal").style.display    = "flex";

  // Auto-close after 4 seconds
  setTimeout(() => {
    closeFlagModal();
    setTimeout(_showNextFlag, 400);
  }, 4000);
}

function closeFlagModal() {
  document.getElementById("flag-modal").style.display = "none";
  _flagModalOpen = false;
}

// Close on overlay click
document.addEventListener("click", (e) => {
  if (e.target.id === "flag-modal") closeFlagModal();
});

// Copy flag text on modal click
document.addEventListener("DOMContentLoaded", () => {
  const flagText = document.getElementById("modal-flag-text");
  if (flagText) {
    flagText.style.cursor = "pointer";
    flagText.title        = "Click to copy";
    flagText.onclick      = () => {
      navigator.clipboard.writeText(flagText.textContent);
      const orig = flagText.textContent;
      flagText.textContent = "✓ Copied to clipboard!";
      setTimeout(() => (flagText.textContent = orig), 1500);
    };
  }
});
