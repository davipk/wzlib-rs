import { parseWzImage, parseMsImage, decryptMsEntry, decompressPngData, decodePixels } from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state, $, propChildrenData, childContainerMap, propPathMap, resetPropertyState, imgCache, msImgCache } from './state.js';
import { escapeHtml, formatBytes, countProps, formatPropValue, searchEditorHtml } from './utils.js';
import { loadCanvasPreview, loadSoundPlayer, loadVideoDownload, getCanvasAnimFrames, createAnimPlayer } from './media.js';
import { feedWorkerData, setupSearchEditor } from './search.js';
import { saveCurrentImage, saveCurrentMsImage } from './save.js';
import {
  isEditing, getEditData, enterEditMode,
  updateProperty, deleteProperty, addProperty, replaceCanvasImage,
  createCanvasBlob, createSoundBlob,
  createDefaultProperty, ADDABLE_TYPES,
} from './edit.js';

// ── Edit mode state (per-render) ────────────────────────────────────

let currentEditMode = false;
let currentViewKey = null;

// ── Property tree rendering ──────────────────────────────────────────

export function initPropertyView(container, properties, imgOffset, editMode = false) {
  state.currentImgOffset = imgOffset;
  currentEditMode = editMode;
  currentViewKey = imgOffset;
  resetPropertyState();
  renderPropertyLevel(container, properties, 0, '');

  if (editMode) {
    container.appendChild(createAddPropertyButton('', 0, container));
  } else {
    feedWorkerData(properties);
    setupSearchEditor();
  }
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

    // ── Edit controls ──────────────────────────────────────────────
    if (currentEditMode) {
      if (isEditableValue(prop)) {
        valSpan.classList.add('editable');
        valSpan.addEventListener('click', (e) => {
          e.stopPropagation();
          startInlineEdit(item, valSpan, prop, propPath);
        });
      }

      const delBtn = document.createElement('button');
      delBtn.className = 'prop-delete';
      delBtn.textContent = '\u00D7';
      delBtn.title = 'Delete property';
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (!confirm(`Delete "${prop.name}"?`)) return;
        if (deleteProperty(currentViewKey, propPath)) {
          el.remove();
          // Also clean up maps for this path and descendants
          propChildrenData.delete(propPath);
          childContainerMap.delete(propPath);
          if (propPathMap) propPathMap.delete(propPath);
        }
      });
      item.appendChild(delBtn);
    }

    el.appendChild(item);

    const childContainer = document.createElement('div');
    childContainer.className = 'prop-children';
    childContainer.style.display = 'none';

    if (isCanvas) childContainer.appendChild(createMediaHolder('canvas-loading', 'Click to load preview...', depth));
    if (isSound) childContainer.appendChild(createMediaHolder('sound-loading', 'Click to load player...', depth));
    if (isVideo) childContainer.appendChild(createMediaHolder('video-loading', 'Click to extract video...', depth));

    // Canvas replace button (edit mode)
    if (currentEditMode && isCanvas) {
      childContainer.insertBefore(
        createCanvasReplaceButton(prop, propPath, valSpan, childContainer, depth),
        childContainer.firstChild,
      );
    }

    if (hasChildren) {
      propChildrenData.set(propPath, { children: prop.children, type: prop.type });
    }

    // Add "+" button for containers in edit mode
    if (currentEditMode && (prop.type === 'SubProperty' || prop.type === 'Convex')) {
      childContainer.appendChild(createAddPropertyButton(propPath, depth + 1, childContainer));
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
          loadMediaIfNeeded(childContainer, '.canvas-loading', 'Decoding...', h => {
            if (prop.blobIndex != null && getEditData(currentViewKey)) {
              loadCanvasFromBlob(h, propPath, prop, depth);
            } else {
              loadCanvasPreview(h, state.currentImgOffset, propPath, prop.width, prop.height, depth);
            }
          });
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

  if (!currentEditMode && (data.type === 'SubProperty' || data.type === 'Convex')) {
    const animFrames = getCanvasAnimFrames({ children: data.children });
    if (animFrames) {
      const animPlayerEl = createAnimPlayer(animFrames, state.currentImgOffset, propPath, childDepth - 1);
      container.appendChild(animPlayerEl);
      container._animPlayer = animPlayerEl;
      animPlayerEl._anim.init();
    }
  }

  const addBtn = container.querySelector(':scope > .prop-add-btn');
  const fragment = document.createDocumentFragment();
  renderPropertyLevel(fragment, data.children, childDepth, propPath);
  if (addBtn) {
    container.insertBefore(fragment, addBtn);
  } else {
    container.appendChild(fragment);
  }
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

// ── Canvas replace button + preview update ──────────────────────────

function createCanvasReplaceButton(prop, propPath, valSpan, childContainer, depth) {
  const replaceBtn = document.createElement('button');
  replaceBtn.className = 'canvas-replace-btn';
  replaceBtn.textContent = 'Replace Image';
  replaceBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.addEventListener('change', async () => {
      if (input.files.length === 0) return;
      try {
        replaceBtn.textContent = 'Encoding...';
        replaceBtn.disabled = true;
        const result = await replaceCanvasImage(currentViewKey, propPath, input.files[0]);
        if (result) {
          prop.width = result.width;
          prop.height = result.height;
          prop.format = 2;
          valSpan.textContent = formatPropValue(prop);
          updateCanvasPreview(childContainer, result.width, result.height, result.rgba, depth);
          replaceBtn.textContent = 'Replace Image';
          replaceBtn.disabled = false;
        }
      } catch (err) {
        replaceBtn.textContent = 'Replace Image';
        replaceBtn.disabled = false;
        alert(`Failed to replace image: ${err.message}`);
      }
    });
    input.click();
  });
  return replaceBtn;
}

function updateCanvasPreview(childContainer, w, h, rgba, depth) {
  const cvs = document.createElement('canvas');
  cvs.width = w;
  cvs.height = h;
  const ctx = cvs.getContext('2d');
  const imgData = new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), w, h);
  ctx.putImageData(imgData, 0, 0);

  const wrapper = document.createElement('div');
  wrapper.className = 'canvas-preview';
  wrapper.style.setProperty('--pdepth', depth);
  wrapper.title = `${w}x${h} — replaced`;
  if (w <= 200 && h <= 200) wrapper.classList.add('pixelated');
  wrapper.appendChild(cvs);
  wrapper.addEventListener('click', (e) => {
    e.stopPropagation();
    wrapper.classList.toggle('expanded');
  });

  // Replace existing preview or loading placeholder
  const existing = childContainer.querySelector('.canvas-preview') || childContainer.querySelector('.canvas-loading');
  if (existing) {
    existing.replaceWith(wrapper);
  } else {
    // Insert after the replace button
    const replaceBtn = childContainer.querySelector('.canvas-replace-btn');
    if (replaceBtn) replaceBtn.after(wrapper);
    else childContainer.appendChild(wrapper);
  }
}

// ── Canvas decode from edit blob ─────────────────────────────────────

function loadCanvasFromBlob(holder, propPath, prop, depth) {
  setTimeout(() => {
    try {
      const data = getEditData(currentViewKey);
      if (!data || prop.blobIndex == null || prop.blobIndex >= data.blobs.length) {
        holder.textContent = 'No blob data available';
        return;
      }

      const compressed = data.blobs[prop.blobIndex];
      const raw = decompressPngData(compressed);
      const decoded = decodePixels(raw, prop.width, prop.height, prop.format);
      // decoded is RGBA bytes
      const w = prop.width;
      const h = prop.height;

      const cvs = document.createElement('canvas');
      cvs.width = w;
      cvs.height = h;
      const ctx = cvs.getContext('2d');
      const imgData = new ImageData(new Uint8ClampedArray(decoded.buffer, decoded.byteOffset, decoded.byteLength), w, h);
      ctx.putImageData(imgData, 0, 0);

      const wrapper = document.createElement('div');
      wrapper.className = 'canvas-preview';
      wrapper.style.setProperty('--pdepth', depth);
      wrapper.title = `${w}x${h} — from edit data`;
      if (w <= 200 && h <= 200) wrapper.classList.add('pixelated');
      wrapper.appendChild(cvs);
      wrapper.addEventListener('click', (e) => {
        e.stopPropagation();
        wrapper.classList.toggle('expanded');
      });

      holder.replaceWith(wrapper);
    } catch (e) {
      holder.textContent = `Decode error: ${e.message}`;
      holder.style.color = 'var(--accent)';
      console.error('Canvas blob decode error:', e);
    }
  }, 10);
}

// ── Inline value editing ────────────────────────────────────────────

function isEditableValue(prop) {
  return ['Short', 'Int', 'Long', 'Float', 'Double', 'String', 'UOL', 'Vector'].includes(prop.type);
}

function startInlineEdit(item, valSpan, prop, propPath) {
  if (item.querySelector('.edit-input')) return;
  const originalText = valSpan.textContent;
  valSpan.classList.remove('editable');

  if (prop.type === 'Vector') {
    startVectorEdit(item, valSpan, prop, propPath, originalText);
  } else {
    startScalarEdit(item, valSpan, prop, propPath, originalText);
  }
}

function startVectorEdit(item, valSpan, prop, propPath, originalText) {
  const xInput = document.createElement('input');
  xInput.type = 'number';
  xInput.className = 'edit-input vec';
  xInput.value = prop.x ?? 0;

  const yInput = document.createElement('input');
  yInput.type = 'number';
  yInput.className = 'edit-input vec';
  yInput.value = prop.y ?? 0;

  valSpan.textContent = '(';
  valSpan.appendChild(xInput);
  valSpan.appendChild(document.createTextNode(', '));
  valSpan.appendChild(yInput);
  valSpan.appendChild(document.createTextNode(')'));

  const doConfirm = () => {
    const x = parseInt(xInput.value) || 0;
    const y = parseInt(yInput.value) || 0;
    updateProperty(currentViewKey, propPath, { x, y });
    prop.x = x;
    prop.y = y;
    valSpan.textContent = formatPropValue(prop);
    valSpan.classList.add('editable');
  };

  const doCancel = () => {
    valSpan.textContent = originalText;
    valSpan.classList.add('editable');
  };

  for (const inp of [xInput, yInput]) {
    inp.addEventListener('keydown', (e) => {
      e.stopPropagation();
      if (e.key === 'Enter') doConfirm();
      if (e.key === 'Escape') doCancel();
    });
  }
  yInput.addEventListener('blur', (e) => {
    if (!item.contains(e.relatedTarget)) doConfirm();
  });

  xInput.focus();
  xInput.select();
}

function startScalarEdit(item, valSpan, prop, propPath, originalText) {
  const input = document.createElement('input');
  input.className = 'edit-input';

  if (['Short', 'Int', 'Long'].includes(prop.type)) {
    input.type = 'number';
    input.step = '1';
    input.value = prop.value ?? 0;
  } else if (['Float', 'Double'].includes(prop.type)) {
    input.type = 'number';
    input.step = 'any';
    input.value = prop.value ?? 0;
  } else {
    input.type = 'text';
    input.value = prop.value ?? '';
  }

  valSpan.textContent = '';
  valSpan.appendChild(input);

  const doConfirm = () => {
    let value;
    if (['Short', 'Int', 'Long'].includes(prop.type)) {
      value = parseInt(input.value) || 0;
    } else if (['Float', 'Double'].includes(prop.type)) {
      value = parseFloat(input.value) || 0;
    } else {
      value = input.value;
    }
    updateProperty(currentViewKey, propPath, { value });
    prop.value = value;
    valSpan.textContent = formatPropValue(prop);
    valSpan.classList.add('editable');
  };

  const doCancel = () => {
    valSpan.textContent = originalText;
    valSpan.classList.add('editable');
  };

  input.addEventListener('keydown', (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') doConfirm();
    if (e.key === 'Escape') doCancel();
  });
  input.addEventListener('blur', () => doConfirm());

  input.focus();
  input.select();
}

// ── Add property UI ─────────────────────────────────────────────────

function createAddPropertyButton(parentPath, depth, container) {
  const btn = document.createElement('button');
  btn.className = 'prop-add-btn';
  btn.style.setProperty('--pdepth', depth);
  btn.innerHTML = '+ Add property';

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    showAddPropertyForm(parentPath, depth, container, btn);
  });

  return btn;
}

function showAddPropertyForm(parentPath, depth, container, addBtn) {
  const form = document.createElement('div');
  form.className = 'prop-add-form';
  form.style.setProperty('--pdepth', depth);

  const nameInput = document.createElement('input');
  nameInput.type = 'text';
  nameInput.placeholder = 'name';
  nameInput.style.width = '100px';

  const typeSelect = document.createElement('select');
  for (const t of ADDABLE_TYPES) {
    const opt = document.createElement('option');
    opt.value = t;
    opt.textContent = t;
    typeSelect.appendChild(opt);
  }
  typeSelect.value = 'Int';

  const addConfirm = document.createElement('button');
  addConfirm.textContent = 'Add';

  const cancelBtn = document.createElement('button');
  cancelBtn.textContent = 'Cancel';
  cancelBtn.className = 'cancel';

  form.append(nameInput, typeSelect, addConfirm, cancelBtn);

  addBtn.replaceWith(form);
  nameInput.focus();

  // Change button text for file-based types
  typeSelect.addEventListener('change', () => {
    const t = typeSelect.value;
    if (t === 'Canvas') addConfirm.textContent = 'Choose Image\u2026';
    else if (t === 'Sound') addConfirm.textContent = 'Choose Audio\u2026';
    else addConfirm.textContent = 'Add';
  });

  const finish = () => {
    const newAddBtn = createAddPropertyButton(parentPath, depth, container);
    form.replaceWith(newAddBtn);
  };

  const renderNewProp = (newProp) => {
    const fragment = document.createDocumentFragment();
    renderPropertyLevel(fragment, [newProp], depth, parentPath);
    form.before(fragment);
    finish();
  };

  const doAdd = async () => {
    const name = nameInput.value.trim();
    if (!name) { nameInput.focus(); return; }

    const type = typeSelect.value;

    if (type === 'Canvas') {
      const file = await pickFile('image/*');
      if (!file) return;
      const newProp = createDefaultProperty(name, type);
      if (!addProperty(currentViewKey, parentPath, newProp)) {
        alert(`Property "${name}" already exists`);
        nameInput.focus();
        return;
      }
      addConfirm.textContent = 'Encoding\u2026';
      addConfirm.disabled = true;
      const result = await createCanvasBlob(currentViewKey, newProp, file);
      renderNewProp(newProp);
      // Immediately show preview so WASM decode is never attempted for new canvases
      if (result) {
        const propPath = parentPath ? `${parentPath}/${name}` : name;
        const cc = childContainerMap.get(propPath);
        if (cc) updateCanvasPreview(cc, result.width, result.height, result.rgba, depth);
      }
    } else if (type === 'Sound') {
      const file = await pickFile('audio/*,.mp3,.wav,.ogg');
      if (!file) return;
      const newProp = createDefaultProperty(name, type);
      if (!addProperty(currentViewKey, parentPath, newProp)) {
        alert(`Property "${name}" already exists`);
        nameInput.focus();
        return;
      }
      addConfirm.textContent = 'Importing\u2026';
      addConfirm.disabled = true;
      await createSoundBlob(currentViewKey, newProp, file);
      renderNewProp(newProp);
    } else {
      const newProp = createDefaultProperty(name, type);
      if (addProperty(currentViewKey, parentPath, newProp)) {
        renderNewProp(newProp);
      } else {
        alert(`Property "${name}" already exists`);
        nameInput.focus();
      }
    }
  };

  addConfirm.addEventListener('click', (e) => { e.stopPropagation(); doAdd(); });
  cancelBtn.addEventListener('click', (e) => { e.stopPropagation(); finish(); });
  nameInput.addEventListener('keydown', (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') doAdd();
    if (e.key === 'Escape') finish();
  });
}

function pickFile(accept) {
  return new Promise(resolve => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.addEventListener('change', () => {
      resolve(input.files.length > 0 ? input.files[0] : null);
    });
    input.click();
  });
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
  // Non-.img entries (e.g. .txt) — decrypt and show raw content
  if (!entry.name.toLowerCase().endsWith('.img')) {
    return openMsRawEntry(entry);
  }
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

function openMsRawEntry(entry) {
  state.currentMsEntryIndex = entry.index;
  const raw = decryptMsEntry(state.wzData, state.msFileName, entry.index);
  let content;
  try {
    content = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    // Not valid UTF-8 — show hex dump
    const hex = Array.from(raw.slice(0, 4096), b => b.toString(16).padStart(2, '0')).join(' ');
    content = hex + (raw.length > 4096 ? `\n\n... (${formatBytes(raw.length)} total)` : '');
  }

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>${escapeHtml(entry.name)}</h2>
    <table class="props">
      <tr><th>Type</th><td>Raw File</td></tr>
      <tr><th>Size</th><td>${formatBytes(entry.size)}</td></tr>
      <tr><th>Index</th><td>${entry.index}</td></tr>
    </table>
    <pre style="margin-top: 12px; padding: 12px; background: var(--bg-card); border-radius: 6px; overflow: auto; max-height: 600px; white-space: pre-wrap; word-break: break-all; font-size: 13px;">${escapeHtml(content)}</pre>
  `;
}

function showProperties(name, properties, tableRows, onSave, viewKey, forceEditMode = null) {
  state.activeAnimControllers.forEach(c => c.destroy());
  state.activeAnimControllers = [];

  const hasEditData = isEditing(viewKey);
  const editActive = forceEditMode !== null ? forceEditMode : hasEditData;
  const displayProps = hasEditData ? getEditData(viewKey).properties : properties;

  $.detail.innerHTML = `
    <h2>
      ${escapeHtml(name)}
      <button class="edit-img-btn${editActive ? ' active' : ''}" id="edit-img-btn">
        ${editActive ? 'Done Editing' : 'Edit Properties'}
      </button>
      <button class="save-img-btn" id="save-img-btn" title="Export as standalone Data.wz">Export Image</button>
    </h2>
    <table class="props">
      ${tableRows}
      <tr><th>Properties</th><td>${countProps(displayProps)}</td></tr>
    </table>
    ${editActive ? '' : searchEditorHtml()}
    <div class="prop-tree" id="prop-tree"></div>
  `;

  document.getElementById('save-img-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    onSave();
  });

  const editBtn = document.getElementById('edit-img-btn');
  editBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (editActive) {
      showProperties(name, properties, tableRows, onSave, viewKey, false);
    } else {
      try {
        enterEditMode(viewKey);
        showProperties(name, properties, tableRows, onSave, viewKey, true);
      } catch (err) {
        alert(`Failed to enter edit mode: ${err.message}`);
        console.error('Edit mode error:', err);
      }
    }
  });

  const propTree = document.getElementById('prop-tree');
  initPropertyView(propTree, displayProps, viewKey, editActive);
}
