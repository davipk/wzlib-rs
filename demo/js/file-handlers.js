import {
  parseWzFile,
  detectWzMapleVersion,
  detectWzFileType,
  parseWzListFile,
  parseHotfixDataWz,
  parseMsFile,
} from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $ } from './state.js';
import { formatBytes, countNodes, countProps } from './utils.js';
import { renderTree, renderListEntries, renderHotfixTree, renderMsEntries } from './tree-view.js';

// ── Shared parse logic ───────────────────────────────────────────────

function parseWithVersion(data, version, parseFn) {
  if (version === 'auto') {
    $.loadingText.textContent = 'Auto-detecting encryption variant...';
    const result = JSON.parse(detectWzMapleVersion(data));
    return { result, detectedVersion: result.versionName };
  }
  return { result: JSON.parse(parseFn(data, version)), detectedVersion: version };
}

function finalizeFileState(data, detectedVersion, versionHash, tree, mode = 'standard', extra = {}) {
  state.wzData = data;
  state.wzVersionName = detectedVersion;
  state.wzVersionHash = versionHash;
  state.parsedTree = tree;
  state.fileMode = mode;
  state.msFileName = '';
  state.msSalt = '';
  state.wzPatchVersion = extra.patchVersion ?? 0;
  state.wzIs64bit = extra.is64bit ?? false;
  state.currentMsEntryIndex = -1;
  if (detectedVersion !== $.version.value) $.version.value = detectedVersion;
}

// ── File type handlers ───────────────────────────────────────────────

function handleStandardFile(file, data, version) {
  $.loadingText.textContent = 'Parsing WZ file...';
  const t0 = performance.now();

  const { result, detectedVersion } = parseWithVersion(data, version, parseWzFile);
  const elapsed = (performance.now() - t0).toFixed(1);

  finalizeFileState(data, detectedVersion, result.versionHash, result.directory, 'standard', {
    patchVersion: result.version,
    is64bit: result.is64bit,
  });

  const versionLabel = version === 'auto' ? ` (detected: ${detectedVersion.toUpperCase()})` : '';
  const counts = countNodes(state.parsedTree);
  $.fileName.textContent = file.name;
  $.fileStats.textContent = `${counts.dirs} dirs, ${counts.images} imgs`;
  $.statusFile.textContent = `File: ${file.name} (${formatBytes(file.size)})`;
  $.statusParse.textContent = `Parsed in ${elapsed}ms | v${result.version} ${result.is64bit ? '(64-bit)' : ''}${versionLabel} hash=${result.versionHash}`;

  renderTree(state.parsedTree);
}

function handleListFile(file, data, version) {
  $.loadingText.textContent = 'Parsing List.wz...';
  const t0 = performance.now();

  const { result, detectedVersion } = parseWithVersion(data, version, parseWzListFile);
  const entries = result.entries || result;
  const elapsed = (performance.now() - t0).toFixed(1);

  finalizeFileState(data, detectedVersion, 0, null, 'list');

  const versionLabel = version === 'auto' ? ` (detected: ${detectedVersion.toUpperCase()})` : '';
  $.fileName.textContent = file.name;
  $.fileStats.textContent = `${entries.length} entries`;
  $.statusFile.textContent = `File: ${file.name} (${formatBytes(file.size)})`;
  $.statusParse.textContent = `Parsed in ${elapsed}ms | List.wz${versionLabel}`;

  renderListEntries(entries);
}

function handleHotfixFile(file, data, version) {
  $.loadingText.textContent = 'Parsing hotfix Data.wz...';
  const t0 = performance.now();

  const { result, detectedVersion } = parseWithVersion(data, version, parseHotfixDataWz);
  const properties = result.properties || result;
  const elapsed = (performance.now() - t0).toFixed(1);

  finalizeFileState(data, detectedVersion, 0, null, 'hotfix');

  const versionLabel = version === 'auto' ? ` (detected: ${detectedVersion.toUpperCase()})` : '';
  $.fileName.textContent = file.name;
  $.fileStats.textContent = `${countProps(properties)} properties`;
  $.statusFile.textContent = `File: ${file.name} (${formatBytes(file.size)})`;
  $.statusParse.textContent = `Parsed in ${elapsed}ms | Hotfix Data.wz${versionLabel}`;

  renderHotfixTree(file.name, properties);
}

function handleMsFile(file, data) {
  $.loadingText.textContent = 'Parsing MS file...';
  const t0 = performance.now();

  const json = parseMsFile(data, file.name);
  const parsed = JSON.parse(json);
  const elapsed = (performance.now() - t0).toFixed(1);

  state.wzData = data;
  state.wzVersionName = 'bms';
  state.wzVersionHash = 0;
  state.fileMode = 'ms';
  state.fileName = file.name;
  state.msFileName = file.name;
  state.msSalt = parsed.salt || '';
  state.parsedTree = null;

  $.fileName.textContent = file.name;
  $.fileStats.textContent = `${parsed.entryCount} entries`;
  $.statusFile.textContent = `File: ${file.name} (${formatBytes(file.size)})`;
  $.statusParse.textContent = `Parsed in ${elapsed}ms | MS archive, ${parsed.entryCount} entries`;

  renderMsEntries(parsed.entries);
}

// ── Main entry point ─────────────────────────────────────────────────

export async function handleFile(file) {
  if (!state.wasmReady) return alert('WASM module not ready');

  $.loading.classList.remove('hidden');
  $.loadingText.textContent = `Reading ${file.name} (${formatBytes(file.size)})...`;

  const buffer = await file.arrayBuffer();
  const data = new Uint8Array(buffer);
  const version = $.version.value;

  $.loadingText.textContent = 'Detecting file type...';

  try {
    state.fileName = file.name;
    const isMsFile = file.name.toLowerCase().endsWith('.ms');

    if (isMsFile) {
      handleMsFile(file, data);
    } else {
      const fileType = detectWzFileType(data);

      if (fileType === 'list') {
        handleListFile(file, data, version);
      } else if (fileType === 'hotfix') {
        handleHotfixFile(file, data, version);
      } else {
        handleStandardFile(file, data, version);
      }
    }

    $.dropZone.classList.add('hidden');
    $.main.classList.add('visible');
    $.saveBtn.classList.remove('hidden');
  } catch (e) {
    alert(`Parse error: ${e.message}\n\nTry a different encryption version.`);
    console.error(e);
  } finally {
    $.loading.classList.add('hidden');
  }
}
