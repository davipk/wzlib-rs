import init from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $ } from './state.js';
import { handleFile } from './file-handlers.js';
import { saveCurrentFile } from './save.js';

// Side-effect import: registers global Ctrl+F handler and search worker
import './search.js';

// ── WASM init ────────────────────────────────────────────────────────
try {
  await init();
  state.wasmReady = true;
  $.statusWasm.textContent = 'WASM: ready';
  $.loading.classList.add('hidden');
} catch (e) {
  $.loadingText.textContent = `Failed to load WASM: ${e.message}`;
  $.statusWasm.textContent = 'WASM: error';
  console.error(e);
}

// ── File input ───────────────────────────────────────────────────────
$.dropZone.addEventListener('click', () => $.fileInput.click());
$.fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) handleFile(e.target.files[0]);
});

$.dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  $.dropZone.classList.add('active');
});
$.dropZone.addEventListener('dragleave', () => {
  $.dropZone.classList.remove('active');
});
$.dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  $.dropZone.classList.remove('active');
  if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
});

// ── Save button ─────────────────────────────────────────────────────
$.saveBtn.addEventListener('click', () => saveCurrentFile());

// ── Tree filter search ───────────────────────────────────────────────
$.searchBox.addEventListener('input', () => {
  const q = $.searchBox.value.toLowerCase();
  $.tree.querySelectorAll('.tree-node').forEach((n) => {
    const name = n.dataset.name?.toLowerCase() || '';
    n.style.display = name.includes(q) ? '' : 'none';
  });
});
