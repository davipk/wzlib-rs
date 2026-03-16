import { state, $ } from './state.js';
import { escapeHtml, countProps, searchEditorHtml, groupByPath } from './utils.js';
import { openImage, openMsImage, initPropertyView } from './property-view.js';

// ── Standard WZ tree ─────────────────────────────────────────────────

export function renderTree(root) {
  $.tree.innerHTML = '';
  const fragment = document.createDocumentFragment();

  for (const dir of root.subdirectories || []) {
    renderDirNode(fragment, dir, 0);
  }
  for (const img of root.images || []) {
    renderImgNode(fragment, img, 0);
  }

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
    renderImgNode(children, img, depth + 1);
  }

  parent.appendChild(children);

  el.addEventListener('click', () => {
    const isOpen = children.style.display !== 'none';
    children.style.display = isOpen ? 'none' : '';
    el.querySelector('.toggle').textContent = isOpen ? '\u25B6' : '\u25BC';
    selectNode(el, { type: 'directory', ...dir });
  });
}

function renderImgNode(parent, img, depth) {
  const el = createNodeEl(img.name, 'img', depth, 0);
  el.dataset.nodeType = 'img';
  el.dataset.name = img.name;
  parent.appendChild(el);

  el.addEventListener('click', () => {
    selectNode(el, { type: 'image', ...img });
    openImage(img);
  });
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

// ── Node selection / detail panel ────────────────────────────────────

function selectNode(el, data) {
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
        <tr><th>Size</th><td>${data.size ?? '—'}</td></tr>
        <tr><th>Checksum</th><td>${data.checksum != null ? '0x' + (data.checksum >>> 0).toString(16).toUpperCase() : '—'}</td></tr>
        <tr><th>Offset</th><td>${data.offset != null ? '0x' + data.offset.toString(16).toUpperCase() : '—'}</td></tr>
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

  // List.wz groups by first-level directory (indexOf), not deepest parent
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
        document.querySelectorAll('.tree-node.selected').forEach(n => n.classList.remove('selected'));
        el.classList.add('selected');
        showListEntryDetail(path);
      });
      children.appendChild(el);
    }

    fragment.appendChild(children);

    dirEl.addEventListener('click', () => {
      const isOpen = children.style.display !== 'none';
      children.style.display = isOpen ? 'none' : '';
      dirEl.querySelector('.toggle').textContent = isOpen ? '\u25B6' : '\u25BC';
    });
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

function showListEntryDetail(path) {
  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>${escapeHtml(path)}</h2>
    <table class="props">
      <tr><th>Type</th><td>List Entry</td></tr>
      <tr><th>Path</th><td>${escapeHtml(path)}</td></tr>
    </table>
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

  state.activeAnimControllers.forEach(c => c.destroy());
  state.activeAnimControllers = [];

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>${escapeHtml(fileName)}</h2>
    <table class="props">
      <tr><th>Type</th><td>Hotfix Data.wz</td></tr>
      <tr><th>Properties</th><td>${countProps(properties)}</td></tr>
    </table>
    ${searchEditorHtml()}
    <div class="prop-tree" id="prop-tree"></div>
  `;

  initPropertyView(document.getElementById('prop-tree'), properties, 0);
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
        document.querySelectorAll('.tree-node.selected').forEach(n => n.classList.remove('selected'));
        el.classList.add('selected');
        openMsImage(entry);
      });
      children.appendChild(el);
    }

    fragment.appendChild(children);

    dirEl.addEventListener('click', () => {
      const isOpen = children.style.display !== 'none';
      children.style.display = isOpen ? 'none' : '';
      dirEl.querySelector('.toggle').textContent = isOpen ? '\u25B6' : '\u25BC';
    });
  }

  $.tree.appendChild(fragment);

  $.detailEmpty.style.display = 'none';
  $.detail.style.display = '';
  $.detail.innerHTML = `
    <h2>${escapeHtml(state.msFileName)}</h2>
    <table class="props">
      <tr><th>Type</th><td>MS Archive (Snow2 encrypted)</td></tr>
      <tr><th>Entries</th><td>${entries.length}</td></tr>
      <tr><th>Categories</th><td>${groups.size}</td></tr>
    </table>
    <p style="color: var(--text-dim); margin-top: 12px;">
      .ms files are BMS MapleStory encrypted archives containing WZ images.
      Click an entry to decrypt and inspect its properties.
    </p>
  `;
}
