import { parseWzImage, parseMsImage } from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $, propChildrenData, childContainerMap, propPathMap, resetPropertyState, imgCache, msImgCache } from './state.js';
import { escapeHtml, formatBytes, countProps, formatPropValue, searchEditorHtml } from './utils.js';
import { loadCanvasPreview, loadSoundPlayer, loadVideoDownload, getCanvasAnimFrames, createAnimPlayer } from './media.js';
import { feedWorkerData, setupSearchEditor } from './search.js';
import { saveCurrentImage, saveCurrentMsImage } from './save.js';

// ── Property tree rendering ──────────────────────────────────────────

export function initPropertyView(container, properties, imgOffset) {
  state.currentImgOffset = imgOffset;
  resetPropertyState();
  renderPropertyLevel(container, properties, 0, '');
  feedWorkerData(properties);
  setupSearchEditor();
}

export function renderPropertyLevel(container, props, depth, parentPath) {
  for (const prop of props) {
    const el = document.createElement('div');
    const propPath = parentPath ? `${parentPath}/${prop.name}` : prop.name;

    const hasChildren = prop.children && prop.children.length > 0;
    const isCanvas = prop.type === 'Canvas';
    const isSound = prop.type === 'Sound';
    const isVideo = prop.type === 'Video';

    const item = document.createElement('div');
    item.className = 'prop-item';
    item.style.setProperty('--pdepth', depth);
    item.dataset.path = propPath;

    if (propPathMap) propPathMap.set(propPath, item);

    const toggle = document.createElement('span');
    toggle.className = 'prop-toggle';
    toggle.textContent = (hasChildren || isCanvas || isSound || isVideo) ? '\u25B6' : ' ';
    item.appendChild(toggle);

    const nameSpan = document.createElement('span');
    nameSpan.className = 'pname';
    nameSpan.textContent = prop.name;
    item.appendChild(nameSpan);

    const typeSpan = document.createElement('span');
    typeSpan.className = 'ptype';
    typeSpan.textContent = prop.type;
    item.appendChild(typeSpan);

    const valSpan = document.createElement('span');
    valSpan.className = 'pval';
    const valText = formatPropValue(prop);
    if (valText) {
      if (prop.type === 'String') valSpan.classList.add('str');
      else if (prop.type === 'UOL') valSpan.classList.add('link');
      else if (['Short','Int','Long','Float','Double'].includes(prop.type)) valSpan.classList.add('num');
      valSpan.textContent = valText;
      item.appendChild(valSpan);
    }

    el.appendChild(item);

    const childContainer = document.createElement('div');
    childContainer.className = 'prop-children';
    childContainer.style.display = 'none';

    if (isCanvas) childContainer.appendChild(createMediaHolder('canvas-loading', 'Click to load preview...', depth));
    if (isSound) childContainer.appendChild(createMediaHolder('sound-loading', 'Click to load player...', depth));
    if (isVideo) childContainer.appendChild(createMediaHolder('video-loading', 'Click to extract video...', depth));

    if (hasChildren) {
      propChildrenData.set(propPath, { children: prop.children, type: prop.type });
    }

    el.appendChild(childContainer);
    childContainerMap.set(propPath, childContainer);

    if (hasChildren || isCanvas || isSound || isVideo) {
      item.style.cursor = 'pointer';
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = childContainer.style.display !== 'none';
        childContainer.style.display = open ? 'none' : '';
        toggle.textContent = open ? '\u25B6' : '\u25BC';

        if (!open && hasChildren) {
          ensureChildrenRendered(propPath);
        }

        if (isCanvas && !open)
          loadMediaIfNeeded(childContainer, '.canvas-loading', 'Decoding...', h =>
            loadCanvasPreview(h, state.currentImgOffset, propPath, prop.width, prop.height, depth));
        if (isSound && !open)
          loadMediaIfNeeded(childContainer, '.sound-loading', 'Extracting audio...', h =>
            loadSoundPlayer(h, state.currentImgOffset, propPath, prop.duration_ms, depth));
        if (isVideo && !open)
          loadMediaIfNeeded(childContainer, '.video-loading', 'Extracting video...', h =>
            loadVideoDownload(h, state.currentImgOffset, propPath, prop, depth));

        if (childContainer._animPlayer) {
          if (!open) childContainer._animPlayer._anim.init();
          else childContainer._animPlayer._anim.destroy();
        }
      });
    }

    container.appendChild(el);
  }
}

export function ensureChildrenRendered(propPath) {
  const container = childContainerMap.get(propPath);
  if (!container || container.dataset.rendered === 'true') return;
  container.dataset.rendered = 'true';

  const data = propChildrenData.get(propPath);
  if (!data) return;

  const childDepth = propPath.split('/').length;

  if ((data.type === 'SubProperty' || data.type === 'Convex')) {
    const animFrames = getCanvasAnimFrames({ children: data.children });
    if (animFrames) {
      const animPlayerEl = createAnimPlayer(animFrames, state.currentImgOffset, propPath, childDepth - 1);
      container.appendChild(animPlayerEl);
      container._animPlayer = animPlayerEl;
      animPlayerEl._anim.init();
    }
  }

  renderPropertyLevel(container, data.children, childDepth, propPath);
}

export function expandToPath(targetPath) {
  const segments = targetPath.split('/');
  let current = '';
  for (let i = 0; i < segments.length - 1; i++) {
    current = current ? `${current}/${segments[i]}` : segments[i];
    ensureChildrenRendered(current);
  }
}

function loadMediaIfNeeded(container, selector, loadingText, loaderFn) {
  const holder = container.querySelector(selector);
  if (holder && holder.dataset.loaded === 'false') {
    holder.dataset.loaded = 'true';
    holder.textContent = loadingText;
    loaderFn(holder);
  }
}

function createMediaHolder(className, text, depth) {
  const holder = document.createElement('div');
  holder.className = className;
  holder.style.setProperty('--pdepth', depth);
  holder.textContent = text;
  holder.dataset.loaded = 'false';
  return holder;
}

// ── IMG opening (shared) ─────────────────────────────────────────────

async function openAndCacheImage({ cache, cacheKey, name, loadingText, parseLabel, parseFn, tableRows, onSave, viewKey, beforeParse }) {
  if (!state.wzData) return;
  if (beforeParse) beforeParse();

  if (cache.has(cacheKey)) {
    showProperties(name, cache.get(cacheKey), tableRows, onSave, viewKey);
    return;
  }

  $.detail.innerHTML = `
    <h2>${escapeHtml(name)}</h2>
    <div class="img-parsing">${loadingText}</div>
  `;

  await new Promise(r => setTimeout(r, 0));

  try {
    const t0 = performance.now();
    const json = parseFn();
    const t1 = performance.now();
    const properties = JSON.parse(json);
    cache.set(cacheKey, properties);
    $.statusParse.textContent = `${parseLabel} parsed in ${(t1 - t0).toFixed(1)}ms (${properties.length} props)`;
    showProperties(name, properties, tableRows, onSave, viewKey);
  } catch (e) {
    $.detail.innerHTML = `
      <h2>${escapeHtml(name)}</h2>
      <table class="props">${tableRows}</table>
      <div style="color: var(--accent); margin-top: 12px;">Parse error: ${escapeHtml(e.message)}</div>
    `;
    console.error(`${parseLabel} parse error:`, e);
  }
}

export async function openImage(img) {
  return openAndCacheImage({
    cache: imgCache,
    cacheKey: img.offset,
    name: img.name,
    loadingText: 'Parsing image...',
    parseLabel: 'IMG',
    parseFn: () => parseWzImage(state.wzData, state.wzVersionName, img.offset, img.size, state.wzVersionHash),
    tableRows: `
      <tr><th>Type</th><td>Image</td></tr>
      <tr><th>Size</th><td>${formatBytes(img.size)}</td></tr>
      <tr><th>Offset</th><td>0x${img.offset.toString(16).toUpperCase()}</td></tr>
    `,
    onSave: () => saveCurrentImage(img.offset, img.name),
    viewKey: img.offset,
  });
}

export async function openMsImage(entry) {
  return openAndCacheImage({
    cache: msImgCache,
    cacheKey: entry.index,
    name: entry.name,
    loadingText: 'Decrypting &amp; parsing image...',
    parseLabel: 'MS IMG',
    parseFn: () => parseMsImage(state.wzData, state.msFileName, entry.index),
    tableRows: `
      <tr><th>Type</th><td>MS Entry</td></tr>
      <tr><th>Size</th><td>${formatBytes(entry.size)}</td></tr>
      <tr><th>Index</th><td>${entry.index}</td></tr>
    `,
    onSave: () => saveCurrentMsImage(entry.index, entry.name),
    viewKey: entry.index,
    beforeParse: () => { state.currentMsEntryIndex = entry.index; },
  });
}

function showProperties(name, properties, tableRows, onSave, viewKey) {
  state.activeAnimControllers.forEach(c => c.destroy());
  state.activeAnimControllers = [];

  $.detail.innerHTML = `
    <h2>${escapeHtml(name)}<button class="save-img-btn" id="save-img-btn" title="Save as standalone Data.wz">Save Image</button></h2>
    <table class="props">
      ${tableRows}
      <tr><th>Properties</th><td>${countProps(properties)}</td></tr>
    </table>
    ${searchEditorHtml()}
    <div class="prop-tree" id="prop-tree"></div>
  `;

  document.getElementById('save-img-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    onSave();
  });

  initPropertyView(document.getElementById('prop-tree'), properties, viewKey);
}
