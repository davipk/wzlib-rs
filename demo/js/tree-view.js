import { state, $, imgCache } from './state.js';
import { escapeHtml, countProps, searchEditorHtml, groupByPath } from './utils.js';
import { openImage, openMsImage, initPropertyView } from './property-view.js';
import { isEditing, getEditData, enterEditMode, getEditKey, createEmptyEditData, markModified } from './edit.js';

// ── Drag state ──────────────────────────────────────────────────────

const dragState = { source: null, img: null, dir: null };

function clearDropIndicators() {
  document.querySelectorAll('.drop-above, .drop-below').forEach(el => {
    el.classList.remove('drop-above', 'drop-below');
  });
}

// ── Standard WZ tree ─────────────────────────────────────────────────

export function renderTree(root) {
  $.tree.innerHTML = '';
  const fragment = document.createDocumentFragment();

  for (const dir of root.subdirectories || []) {
    renderDirNode(fragment, dir, 0);
  }
  for (const img of root.images || []) {
    renderImgNode(fragment, img, 0, root);
  }

  // "Add Image" button for root
  fragment.appendChild(createAddImgButton(root, 0));

  $.tree.appendChild(fragment);
}

function renderDirNode(parent, dir, depth) {
  const childCount = (dir.subdirectories?.length || 0) + (dir.images?.length || 0);
  const el = createNodeEl(dir.name, 'dir', depth, childCount);
  el.dataset.nodeType = 'dir';
  el.dataset.name = dir.name;
  parent.appendChild(el);

  const children = document.createElement('div');
  children.style.display = 'none';
  children.classList.add('tree-children');

  for (const sub of dir.subdirectories || []) {
    renderDirNode(children, sub, depth + 1);
  }
  for (const img of dir.images || []) {
    renderImgNode(children, img, depth + 1, dir);
  }

  // "Add Image" button inside this directory
  children.appendChild(createAddImgButton(dir, depth + 1));

  parent.appendChild(children);

  el.addEventListener('click', () => {
    toggleTreeNode(el, children);
    selectNode(el, { type: 'directory', ...dir });
  });
}

function renderImgNode(parent, img, depth, dir) {
  const el = createNodeEl(img.name, 'img', depth, 0);
  el.dataset.nodeType = 'img';
  el.dataset.name = img.name;

  // ── Drag-and-drop reordering ────────────────────────────────────
  el.draggable = true;

  el.addEventListener('dragstart', (e) => {
    e.stopPropagation();
    el.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    dragState.source = el;
    dragState.img = img;
    dragState.dir = dir;
  });

  el.addEventListener('dragend', () => {
    el.classList.remove('dragging');
    clearDropIndicators();
    dragState.source = null;
  });

  el.addEventListener('dragover', (e) => {
    if (!dragState.source || dragState.source === el || dragState.dir !== dir) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    clearDropIndicators();
    const rect = el.getBoundingClientRect();
    el.classList.add(e.clientY < rect.top + rect.height / 2 ? 'drop-above' : 'drop-below');
  });

  el.addEventListener('dragleave', () => {
    el.classList.remove('drop-above', 'drop-below');
  });

  el.addEventListener('drop', (e) => {
    e.preventDefault();
    clearDropIndicators();
    if (!dragState.source || dragState.source === el || dragState.dir !== dir) return;

    const above = e.clientY < el.getBoundingClientRect().top + el.offsetHeight / 2;

    // Update data model
    const fromIdx = dir.images.indexOf(dragState.img);
    if (fromIdx < 0) return;
    dir.images.splice(fromIdx, 1);
    let toIdx = dir.images.indexOf(img);
    if (!above) toIdx++;
    dir.images.splice(toIdx, 0, dragState.img);

    // Update DOM
    if (above) el.parentNode.insertBefore(dragState.source, el);
    else el.parentNode.insertBefore(dragState.source, el.nextSibling);
  });

  // ── Edit buttons ────────────────────────────────────────────────
  const btns = document.createElement('span');
  btns.className = 'tree-edit-btns';

  const renameBtn = document.createElement('button');
  renameBtn.className = 'rename-btn';
  renameBtn.textContent = '\u270E';
  renameBtn.title = 'Rename image';
  renameBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const newName = prompt('Rename image:', img.name);
    if (!newName || newName === img.name) return;
    img.name = newName;
    el.querySelector('.name').textContent = newName;
    el.dataset.name = newName;
  });

  const delBtn = document.createElement('button');
  delBtn.className = 'del-btn';
  delBtn.textContent = '\u00D7';
  delBtn.title = 'Delete image';
  delBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (!confirm(`Delete image "${img.name}"?`)) return;
    const idx = dir.images.indexOf(img);
    if (idx >= 0) {
      dir.images.splice(idx, 1);
      el.remove();
      const key = getEditKey(img.offset);
      state.editableImages.delete(key);
      state.modifiedImages.delete(img.offset);
      imgCache.delete(img.offset);
    }
  });

  btns.append(renameBtn, delBtn);
  el.appendChild(btns);
  parent.appendChild(el);

  el.addEventListener('click', () => {
    selectNode(el, { type: 'image', ...img });
    openImage(img);
  });
}

function createAddImgButton(dir, depth) {
  const btn = document.createElement('button');
  btn.className = 'tree-add-img';
  btn.style.setProperty('--depth', depth);
  btn.textContent = '+ Add Image';
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const name = prompt('Image name (e.g., "NewImage.img"):');
    if (!name) return;

    const syntheticOffset = state.nextSyntheticOffset--;
    const newImg = { name, size: 0, checksum: 0, offset: syntheticOffset };
    dir.images.push(newImg);

    // Create empty edit data so it can be edited and saved
    const key = getEditKey(syntheticOffset);
    createEmptyEditData(key);
    markModified(syntheticOffset);

    // Insert the new image node before this button
    const fragment = document.createDocumentFragment();
    renderImgNode(fragment, newImg, depth, dir);
    btn.before(fragment);
  });
  return btn;
}

function createNodeEl(name, type, depth, childCount) {
  const el = document.createElement('div');
  el.className = `tree-node ${type}`;
  el.style.setProperty('--depth', depth);

  const toggle = type === 'dir' ? '\u25B6' : '';
  const icon = type === 'dir' ? '\uD83D\uDCC1' : '\uD83D\uDCC4';

  el.innerHTML = `
    <span class="toggle">${toggle}</span>
    <span class="icon">${icon}</span>
    <span class="name">${escapeHtml(name)}</span>
    ${childCount > 0 ? `<span class="count">${childCount}</span>` : ''}
  `;
  return el;
}

// ── Shared helpers ──────────────────────────────────────────────────

function toggleTreeNode(el, children) {
  const isOpen = children.style.display !== 'none';
  children.style.display = isOpen ? 'none' : '';
  el.querySelector('.toggle').textContent = isOpen ? '\u25B6' : '\u25BC';
}

// ── Node selection / detail panel ────────────────────────────────────

export function selectNode(el, data) {
  document.querySelectorAll('.tree-node.selected').forEach(n => n.classList.remove('selected'));
  el.classList.add('selected');
  state.selectedNode = data;
  showDetail(data);
}

function showDetail(data) {
  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';

  if (data.type === 'directory') {
    const subdirs = data.subdirectories?.length || 0;
    const imgs = data.images?.length || 0;
    $.detail.innerHTML = `
      <h2>${escapeHtml(data.name)}</h2>
      <table class="props">
        <tr><th>Type</th><td>Directory</td></tr>
        <tr><th>Subdirectories</th><td>${subdirs}</td></tr>
        <tr><th>Images</th><td>${imgs}</td></tr>
        <tr><th>Size</th><td>${data.size ?? '\u2014'}</td></tr>
        <tr><th>Checksum</th><td>${data.checksum != null ? '0x' + (data.checksum >>> 0).toString(16).toUpperCase() : '\u2014'}</td></tr>
        <tr><th>Offset</th><td>${data.offset != null ? '0x' + data.offset.toString(16).toUpperCase() : '\u2014'}</td></tr>
      </table>
    `;
  } else if (data.type === 'list-entry') {
    $.detail.innerHTML = `
      <h2>${escapeHtml(data.path)}</h2>
      <table class="props">
        <tr><th>Type</th><td>List Entry</td></tr>
        <tr><th>Path</th><td>${escapeHtml(data.path)}</td></tr>
      </table>
    `;
  } else {
    $.detail.innerHTML = `
      <h2>${escapeHtml(data.name)}</h2>
      <div class="img-parsing">Loading...</div>
    `;
  }
}

// ── List.wz entries ──────────────────────────────────────────────────

export function renderListEntries(entries) {
  $.tree.innerHTML = '';
  const fragment = document.createDocumentFragment();

  const groups = new Map();
  for (const entry of entries) {
    const slash = entry.indexOf('/');
    const group = slash >= 0 ? entry.substring(0, slash) : '(root)';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(entry);
  }

  for (const [group, paths] of groups) {
    const dirEl = createNodeEl(group, 'dir', 0, paths.length);
    dirEl.dataset.nodeType = 'dir';
    dirEl.dataset.name = group;
    fragment.appendChild(dirEl);

    const children = document.createElement('div');
    children.style.display = 'none';
    children.classList.add('tree-children');

    for (const path of paths) {
      const name = path.substring(path.indexOf('/') + 1) || path;
      const el = createNodeEl(name, 'img', 1, 0);
      el.dataset.nodeType = 'list-entry';
      el.dataset.name = name;
      el.addEventListener('click', () => {
        selectNode(el, { type: 'list-entry', path });
      });
      children.appendChild(el);
    }

    fragment.appendChild(children);

    dirEl.addEventListener('click', () => toggleTreeNode(dirEl, children));
  }

  $.tree.appendChild(fragment);

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>List.wz</h2>
    <table class="props">
      <tr><th>Type</th><td>List File (pre-Big Bang)</td></tr>
      <tr><th>Entries</th><td>${entries.length}</td></tr>
      <tr><th>Categories</th><td>${groups.size}</td></tr>
    </table>
    <p style="color: var(--text-dim); margin-top: 12px;">
      List.wz is a path index used by pre-Big Bang MapleStory clients.
      Each entry is a relative path to an .img file within Data.wz.
    </p>
  `;
}

// ── Hotfix Data.wz ───────────────────────────────────────────────────

export function renderHotfixTree(fileName, properties) {
  $.tree.innerHTML = '';
  const fragment = document.createDocumentFragment();

  const rootEl = createNodeEl(fileName, 'img', 0, 0);
  rootEl.dataset.nodeType = 'img';
  rootEl.dataset.name = fileName;
  rootEl.classList.add('selected');
  fragment.appendChild(rootEl);
  $.tree.appendChild(fragment);

  renderHotfixDetail(fileName, properties);
}

function renderHotfixDetail(fileName, properties, forceEditMode = null) {
  state.activeAnimControllers.forEach(c => c.destroy());
  state.activeAnimControllers = [];

  const hasEditData = isEditing(0);
  const editActive = forceEditMode !== null ? forceEditMode : hasEditData;
  const displayProps = hasEditData ? getEditData(0).properties : properties;

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>
      ${escapeHtml(fileName)}
      <button class="edit-img-btn${editActive ? ' active' : ''}" id="edit-img-btn">
        ${editActive ? 'Done Editing' : 'Edit Properties'}
      </button>
    </h2>
    <table class="props">
      <tr><th>Type</th><td>Hotfix Data.wz</td></tr>
      <tr><th>Properties</th><td>${countProps(displayProps)}</td></tr>
    </table>
    ${editActive ? '' : searchEditorHtml()}
    <div class="prop-tree" id="prop-tree"></div>
  `;

  const editBtn = document.getElementById('edit-img-btn');
  editBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (editActive) {
      renderHotfixDetail(fileName, properties, false);
    } else {
      try {
        enterEditMode(0);
        renderHotfixDetail(fileName, properties, true);
      } catch (err) {
        alert(`Failed to enter edit mode: ${err.message}`);
        console.error('Edit mode error:', err);
      }
    }
  });

  const propTree = document.getElementById('prop-tree');
  initPropertyView(propTree, displayProps, 0, editActive);
}

// ── MS entries ───────────────────────────────────────────────────────

export function renderMsEntries(entries) {
  $.tree.innerHTML = '';
  const fragment = document.createDocumentFragment();

  const groups = groupByPath(entries, e => e.name);

  for (const [group, groupEntries] of groups) {
    const dirEl = createNodeEl(group, 'dir', 0, groupEntries.length);
    dirEl.dataset.nodeType = 'dir';
    dirEl.dataset.name = group;
    fragment.appendChild(dirEl);

    const children = document.createElement('div');
    children.style.display = 'none';
    children.classList.add('tree-children');

    for (const entry of groupEntries) {
      const name = entry.name.substring(entry.name.lastIndexOf('/') + 1) || entry.name;
      const el = createNodeEl(name, 'img', 1, 0);
      el.dataset.nodeType = 'ms-entry';
      el.dataset.name = name;
      el.addEventListener('click', () => {
        selectNode(el, { type: 'ms-entry' });
        openMsImage(entry);
      });
      children.appendChild(el);
    }

    fragment.appendChild(children);

    dirEl.addEventListener('click', () => toggleTreeNode(dirEl, children));
  }

  $.tree.appendChild(fragment);

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>${escapeHtml(state.msFileName)}</h2>
    <table class="props">
      <tr><th>Type</th><td>MS Archive (${state.msVersion === 2 ? 'ChaCha20' : 'Snow2'} encrypted)</td></tr>
      <tr><th>Entries</th><td>${entries.length}</td></tr>
      <tr><th>Categories</th><td>${groups.size}</td></tr>
    </table>
    <p style="color: var(--text-dim); margin-top: 12px;">
      .ms files are BMS MapleStory encrypted archives containing WZ images.
      Click an entry to decrypt and inspect its properties.
    </p>
  `;
}
