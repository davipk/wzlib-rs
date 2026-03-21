// ── Shared mutable state ─────────────────────────────────────────────
export const state = {
  wasmReady: false,
  parsedTree: null,
  selectedNode: null,
  wzData: null,           // Uint8Array of the full .wz/.ms file
  wzVersionHash: 0,       // version hash from parsing
  wzVersionName: '',      // "gms", "ems", "bms"
  wzPatchVersion: 0,      // detected patch version (for save)
  wzIs64bit: false,       // 64-bit format flag (for save)
  fileMode: 'standard',   // 'standard' | 'hotfix' | 'list' | 'ms'
  fileName: '',           // original filename
  msFileName: '',         // original .ms filename for key derivation
  msSalt: '',             // salt from .ms parsing (for save)
  msVersion: 0,           // 1 = Snow2 (v1), 2 = ChaCha20 (v2)
  currentMsEntryIndex: -1,
  currentImgOffset: 0,
  activeAnimControllers: [],
  currentAudio: null,
  currentPlayBtn: null,
  currentStopBtn: null,
  modifiedImages: new Set(),  // image offsets that were edited (passthrough all others on save)
  editableImages: new Map(),  // editKey → { properties, blobs } for images parsed-for-edit
  nextSyntheticOffset: -1,    // counter for new (added) images
};

// ── Lazy property tree rendering state ───────────────────────────────
export let propChildrenData = new Map();  // path → { children, type }
export let childContainerMap = new Map(); // path → child container DOM element
export let propPathMap = null;            // path → prop-item DOM element

export function resetPropertyState() {
  propPathMap = new Map();
  propChildrenData = new Map();
  childContainerMap = new Map();
}

// ── Caches ───────────────────────────────────────────────────────────
export const imgCache = new Map();  // offset → parsed properties
export const msImgCache = new Map(); // entryIndex → parsed properties

// ── DOM refs ─────────────────────────────────────────────────────────
export const $ = {
  loading:     document.getElementById('loading'),
  loadingText: document.getElementById('loading-text'),
  dropZone:    document.getElementById('drop-zone'),
  main:        document.getElementById('main'),
  fileInput:   document.getElementById('file-input'),
  fileName:    document.getElementById('file-name'),
  fileStats:   document.getElementById('file-stats'),
  searchBox:   document.getElementById('search-box'),
  tree:        document.getElementById('tree-container'),
  detail:      document.getElementById('detail-content'),
  detailEmpty: document.getElementById('detail-empty'),
  statusWasm:  document.getElementById('status-wasm'),
  statusFile:  document.getElementById('status-file'),
  statusParse: document.getElementById('status-parse'),
  version:     document.getElementById('version-select'),
  saveBtn:     document.getElementById('save-btn'),
};
