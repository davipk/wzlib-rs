import {
  parseWzImageForEdit,
  parseHotfixForEdit,
  parseMsImageForEdit,
  parseMsFile,
  decryptMsEntry,
  buildWzImage,
  buildWzFile,
  buildMsFile,
} from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $ } from './state.js';
import { formatBytes } from './utils.js';
import { unpackEditResult, packBlobs } from './packed.js';

// Collect images depth-first matching attach_image_data traversal order
function collectImages(dir) {
  const images = [];
  for (const img of dir.images) images.push(img);
  for (const sub of dir.subdirectories) images.push(...collectImages(sub));
  return images;
}

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

// ── Build a single image, using edit state if available ──────────────

function buildImageFromWz(imgOffset, imgSize) {
  const editData = state.editableImages.get(String(imgOffset));
  if (editData) {
    return buildWzImage(JSON.stringify(editData.properties), packBlobs(editData.blobs), state.wzVersionName);
  }
  const packed = parseWzImageForEdit(state.wzData, state.wzVersionName, imgOffset, imgSize, state.wzVersionHash);
  const { properties, blobs } = unpackEditResult(packed);
  return buildWzImage(JSON.stringify(properties), packBlobs(blobs), state.wzVersionName);
}

function buildImageFromHotfix() {
  const editData = state.editableImages.get('hotfix');
  if (editData) {
    return buildWzImage(JSON.stringify(editData.properties), packBlobs(editData.blobs), state.wzVersionName);
  }
  const packed = parseHotfixForEdit(state.wzData, state.wzVersionName);
  const { properties, blobs } = unpackEditResult(packed);
  return buildWzImage(JSON.stringify(properties), packBlobs(blobs), state.wzVersionName);
}

function buildImageFromMs(entryIndex, entryName) {
  const editData = state.editableImages.get(`ms:${entryIndex}`);
  if (editData) {
    return buildWzImage(JSON.stringify(editData.properties), packBlobs(editData.blobs), 'bms');
  }
  // Non-.img entries (e.g. .txt files) are raw data, not WZ images
  if (!entryName.toLowerCase().endsWith('.img')) {
    return decryptMsEntry(state.wzData, state.msFileName, entryIndex);
  }
  const packed = parseMsImageForEdit(state.wzData, state.msFileName, entryIndex);
  const { properties, blobs } = unpackEditResult(packed);
  return buildWzImage(JSON.stringify(properties), packBlobs(blobs), 'bms');
}

// ── Save entire file ────────────────────────────────────────────────

export async function saveCurrentFile() {
  if (!state.wzData) return;

  try {
    switch (state.fileMode) {
      case 'standard': {
        const result = await withProgress('Saving WZ file...', () => {
          const images = collectImages(state.parsedTree);
          const imageBlobs = images.map((img) => {
            // New or modified images: build from edit state
            const editData = state.editableImages.get(String(img.offset));
            if (editData) {
              return buildWzImage(JSON.stringify(editData.properties), packBlobs(editData.blobs), state.wzVersionName);
            }
            // Unchanged images with valid offsets: pass through original bytes
            if (img.offset >= 0 && !state.modifiedImages?.has(img.offset)) {
              return state.wzData.slice(img.offset, img.offset + img.size);
            }
            return buildImageFromWz(img.offset, img.size);
          });
          return buildWzFile(
            JSON.stringify(state.parsedTree),
            packBlobs(imageBlobs),
            state.wzPatchVersion,
            state.wzVersionName,
            state.wzIs64bit,
          );
        });
        downloadBlob(result, state.fileName.replace(/\.wz$/i, '_saved.wz'));
        break;
      }
      case 'hotfix': {
        const result = await withProgress('Saving hotfix Data.wz...', () => buildImageFromHotfix());
        downloadBlob(result, state.fileName.replace(/\.wz$/i, '_saved.wz'));
        break;
      }
      case 'ms': {
        // MS format derives encryption keys from the filename — saved file must
        // use the same filename it was built with, otherwise it can't be reopened.
        const result = await withProgress('Saving MS file as v1 (building all entries)...', () => {
          const parsed = JSON.parse(parseMsFile(state.wzData, state.msFileName));
          const entryDefs = parsed.entries.map((e) => ({
            name: e.name,
            entryKey: e.entryKey,
            originalSize: state.editableImages.has(`ms:${e.index}`) ? undefined : e.size,
          }));
          const imageBlobs = parsed.entries.map((e, i) => buildImageFromMs(i, e.name));
          return buildMsFile(state.msFileName, state.msSalt, JSON.stringify(entryDefs), packBlobs(imageBlobs));
        });
        downloadBlob(result, state.msFileName);
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
      buildImageFromWz(imgOffset, 0),
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
      buildImageFromMs(entryIndex, entryName),
    );
    const shortName = entryName.includes('/') ? entryName.split('/').pop() : entryName;
    downloadBlob(result, shortName);
  } catch (e) {
    $.loading.classList.add('hidden');
    alert(`Save image error: ${e.message}`);
    console.error('Save image error:', e);
  }
}
