export function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

export function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function countNodes(tree) {
  let dirs = 0, images = 0;
  function walk(node) {
    for (const sub of node.subdirectories || []) { dirs++; walk(sub); }
    images += (node.images || []).length;
  }
  walk(tree);
  return { dirs, images };
}

export function countProps(props) {
  let count = 0;
  for (const p of props) {
    count++;
    if (p.children) count += countProps(p.children);
  }
  return count;
}

export function searchEditorHtml() {
  return `
    <div class="search-editor" id="search-editor">
      <div class="search-editor-toolbar">
        <div class="search-input-wrap">
          <input type="text" id="search-editor-input" placeholder="Search properties... (Ctrl+F)" />
          <div class="search-toggles">
            <button class="search-toggle" id="toggle-regex" title="Use Regular Expression (Alt+R)">.*</button>
            <button class="search-toggle" id="toggle-case" title="Match Case (Alt+C)">Aa</button>
            <button class="search-toggle" id="toggle-word" title="Match Whole Word (Alt+W)">ab</button>
          </div>
        </div>
        <span class="search-results-count" id="search-results-count"></span>
      </div>
      <div class="search-results" id="search-results"></div>
    </div>
  `;
}

export function groupByPath(items, getPath) {
  const groups = new Map();
  for (const item of items) {
    const path = getPath(item);
    const slash = path.lastIndexOf('/');
    const group = slash >= 0 ? path.substring(0, slash) : '(root)';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(item);
  }
  return groups;
}

export function decodeCanvasResult(result) {
  const w = result[0] | (result[1] << 8) | (result[2] << 16) | (result[3] << 24);
  const h = result[4] | (result[5] << 8) | (result[6] << 16) | (result[7] << 24);
  return { w, h, rgba: result.slice(8) };
}

export function formatPropValue(prop) {
  switch (prop.type) {
    case 'Short': case 'Int': case 'Long': return String(prop.value);
    case 'Float': case 'Double': return Number(prop.value).toFixed(4);
    case 'String': return `"${prop.value}"`;
    case 'UOL': return `-> ${prop.value}`;
    case 'Vector': return `(${prop.x}, ${prop.y})`;
    case 'Canvas': return `${prop.width}x${prop.height} fmt=${prop.format} [${formatBytes(prop.dataLength)}]`;
    case 'Sound': return `${prop.duration_ms}ms [${formatBytes(prop.dataLength)}]`;
    case 'Video': {
      let desc = `type=${prop.videoType} [${formatBytes(prop.dataLength)}]`;
      if (prop.mcv) desc += ` ${prop.mcv.width}x${prop.mcv.height} ${prop.mcv.frameCount}f`;
      return desc;
    }
    case 'Lua': case 'RawData': return `[${formatBytes(prop.dataLength)}]`;
    case 'Null': return 'null';
    default: return '';
  }
}
