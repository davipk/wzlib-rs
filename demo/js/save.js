import {
  saveWzFile,
  saveHotfixDataWz,
  saveMsFile,
  saveWzImage,
  saveMsImage,
} from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $ } from './state.js';
import { formatBytes } from './utils.js';

// ── Helpers ─────────────────────────────────────────────────────────

function downloadBlob(data, filename) {
  const blob = new Blob([data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function withProgress(label, fn) {
  $.loading.classList.remove('hidden');
  $.loadingText.textContent = label;

  // Yield to the UI so the loading overlay renders before the sync WASM call
  return new Promise((resolve) => setTimeout(resolve, 0)).then(() => {
    try {
      const t0 = performance.now();
      const result = fn();
      const elapsed = (performance.now() - t0).toFixed(1);
      $.statusParse.textContent = `Saved in ${elapsed}ms (${formatBytes(result.length)})`;
      return result;
    } finally {
      $.loading.classList.add('hidden');
    }
  });
}

// ── Save entire file ────────────────────────────────────────────────

export async function saveCurrentFile() {
  if (!state.wzData) return;

  try {
    switch (state.fileMode) {
      case 'standard': {
        const result = await withProgress('Saving WZ file (parsing all images)...', () =>
          saveWzFile(state.wzData, state.wzVersionName),
        );
        downloadBlob(result, state.fileName.replace(/\.wz$/i, '_saved.wz'));
        break;
      }
      case 'hotfix': {
        const result = await withProgress('Saving hotfix Data.wz...', () =>
          saveHotfixDataWz(state.wzData, state.wzVersionName),
        );
        downloadBlob(result, state.fileName.replace(/\.wz$/i, '_saved.wz'));
        break;
      }
      case 'ms': {
        const result = await withProgress('Saving MS file (decrypting all entries)...', () =>
          saveMsFile(state.wzData, state.msFileName),
        );
        downloadBlob(result, state.fileName.replace(/\.ms$/i, '_saved.ms'));
        break;
      }
      case 'list':
        alert('List.wz files are read-only path indexes and cannot be saved.');
        return;
    }
  } catch (e) {
    $.loading.classList.add('hidden');
    alert(`Save error: ${e.message}`);
    console.error('Save error:', e);
  }
}

// ── Save individual image ───────────────────────────────────────────

export async function saveCurrentImage(imgOffset, imgName) {
  if (!state.wzData) return;

  try {
    const result = await withProgress(`Saving image ${imgName}...`, () =>
      saveWzImage(state.wzData, state.wzVersionName, imgOffset, state.wzVersionHash),
    );
    downloadBlob(result, imgName);
  } catch (e) {
    $.loading.classList.add('hidden');
    alert(`Save image error: ${e.message}`);
    console.error('Save image error:', e);
  }
}

export async function saveCurrentMsImage(entryIndex, entryName) {
  if (!state.wzData) return;

  try {
    const result = await withProgress(`Saving MS entry ${entryName}...`, () =>
      saveMsImage(state.wzData, state.msFileName, entryIndex),
    );
    const shortName = entryName.includes('/') ? entryName.split('/').pop() : entryName;
    downloadBlob(result, shortName);
  } catch (e) {
    $.loading.classList.add('hidden');
    alert(`Save image error: ${e.message}`);
    console.error('Save image error:', e);
  }
}
